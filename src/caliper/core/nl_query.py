"""NL-to-SQL code query interface for the CodeGraph SQLite database.

Maps natural-language questions to pre-defined SQL templates via keyword
overlap scoring (no ML, no external dependencies).

# tested-by: tests/unit/test_nl_query.py
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class QueryTemplate:
    """A natural-language query pattern and its corresponding SQL."""

    pattern: list[str]  # keywords that trigger this template
    sql: str  # SQL query; parameterised templates use {param} placeholder
    description: str  # human-readable description shown to the user
    param_extract_patterns: list[str] | None = field(
        default=None,
        repr=False,
    )
    # Regex patterns (tried in order) to extract a symbol name from the question.
    # Each must have exactly one capture group.  Only set when sql contains {param}.


@dataclass
class QueryResult:
    """Result from query_code()."""

    query: str  # SQL that was executed (empty string == no match)
    description: str  # human-readable description of what was answered
    rows: list[dict]  # result rows as plain dicts
    columns: list[str]  # column names in display order


# ---------------------------------------------------------------------------
# Query templates
# ---------------------------------------------------------------------------

TEMPLATES: list[QueryTemplate] = [
    # 1 — highest fan-out (god functions)
    QueryTemplate(
        pattern=["highest fan-out", "fan-out", "most calls", "god function", "outgoing calls"],
        description="Top functions by outgoing call count (fan-out)",
        sql="""\
SELECT s.name, s.file, s.line, COUNT(e.id) AS calls_out
FROM symbols s
JOIN edges e ON e.source_id = s.id AND e.kind = 'calls'
WHERE s.kind IN ('function', 'method')
GROUP BY s.id
ORDER BY calls_out DESC
LIMIT 20""",
    ),
    # 2 — most imported / most depended on
    QueryTemplate(
        pattern=[
            "most imported",
            "most depended",
            "top dependencies",
            "highest dependents",
            "fan-in",
        ],
        description="Top symbols by incoming dependency count (fan-in)",
        sql="""\
SELECT s.name, s.file, s.line, s.kind, COUNT(e.id) AS dependents
FROM symbols s
JOIN edges e ON e.target_id = s.id
WHERE s.kind IN ('function', 'method', 'class')
GROUP BY s.id
ORDER BY dependents DESC
LIMIT 20""",
    ),
    # 3 — dead code / unused functions
    QueryTemplate(
        pattern=["unused functions", "dead code", "unused", "orphan", "zero callers", "no callers"],
        description="Unused functions with zero incoming call edges (potential dead code)",
        sql="""\
SELECT s.name, s.file, s.line, s.kind
FROM symbols s
LEFT JOIN edges e ON e.target_id = s.id AND e.kind = 'calls'
WHERE s.kind IN ('function', 'method')
AND s.name NOT LIKE '\\_%' ESCAPE '\\'
AND s.name NOT IN ('main', '__init__', 'setup', 'teardown')
AND e.id IS NULL
ORDER BY s.file, s.line""",
    ),
    # 4 — deepest inheritance chains
    QueryTemplate(
        pattern=[
            "deepest inheritance",
            "inheritance chain",
            "deep inheritance",
            "class hierarchy depth",
        ],
        description="Classes with the deepest inheritance chains",
        sql="""\
WITH RECURSIVE chain(id, depth) AS (
  SELECT s.id, 0
  FROM symbols s
  WHERE s.kind = 'class'
  UNION ALL
  SELECT e.target_id, chain.depth + 1
  FROM chain
  JOIN edges e ON e.source_id = chain.id AND e.kind = 'inherits'
  WHERE chain.depth < 20
)
SELECT s.name, s.file, s.line, MAX(chain.depth) AS depth
FROM chain
JOIN symbols s ON chain.id = s.id
GROUP BY chain.id
HAVING depth > 0
ORDER BY depth DESC
LIMIT 20""",
    ),
    # 5 — layer violations (core/ → data/)
    QueryTemplate(
        pattern=[
            "layer violations",
            "tier violations",
            "core imports data",
            "architecture violations",
            "layer violation",
        ],
        description="Layer violations: core/ symbols importing from data/ (three-tier breach)",
        sql="""\
SELECT s.name, s.file, s.line, t.name AS imported, t.file AS imported_from
FROM edges e
JOIN symbols s ON e.source_id = s.id
JOIN symbols t ON e.target_id = t.id
WHERE e.kind = 'imports'
AND s.file LIKE '%/core/%'
AND t.file LIKE '%/data/%'
ORDER BY s.file, s.line""",
    ),
    # 6 — upstream walk: what depends on {param}
    QueryTemplate(
        pattern=["depends on", "what depends", "upstream", "callers of", "who calls"],
        description="What depends on a named symbol (upstream / callers walk)",
        sql="""\
SELECT s.name, s.file, s.line, e.kind AS edge_kind, e.confidence
FROM edges e
JOIN symbols s ON e.source_id = s.id
JOIN symbols t ON e.target_id = t.id
WHERE t.name = {param}
ORDER BY s.file, s.line""",
        param_extract_patterns=[
            r"depends on (\w+)",
            r"callers of (\w+)",
            r"upstream of (\w+)",
            r"who calls (\w+)",
        ],
    ),
    # 7 — downstream walk: what does {param} call
    QueryTemplate(
        pattern=["what does", "downstream", "calls from", "outgoing from", "does call"],
        description="What a named symbol calls (downstream / callees walk)",
        sql="""\
SELECT t.name, t.file, t.line, e.kind AS edge_kind, e.confidence
FROM edges e
JOIN symbols s ON e.source_id = s.id
JOIN symbols t ON e.target_id = t.id
WHERE s.name = {param}
ORDER BY t.file, t.line""",
        param_extract_patterns=[
            r"does (\w+) call",
            r"downstream of (\w+)",
            r"calls from (\w+)",
            r"what does (\w+)",
        ],
    ),
    # 8 — largest files
    QueryTemplate(
        pattern=["largest files", "biggest files", "most symbols", "file size", "symbol count"],
        description="Files ranked by symbol count (largest first)",
        sql="""\
SELECT file, COUNT(*) AS symbol_count
FROM symbols
GROUP BY file
ORDER BY symbol_count DESC
LIMIT 20""",
    ),
    # 9 — stub / noop functions
    QueryTemplate(
        pattern=[
            "stub functions",
            "stub",
            "noop",
            "empty functions",
            "pass only",
            "no-op",
            "placeholder",
        ],
        description="Stub / noop functions (body_kind: noop, pass_only, or stub)",
        sql="""\
SELECT s.name, s.file, s.line, s.body_kind, s.stmt_count
FROM symbols s
WHERE s.kind IN ('function', 'method')
AND s.body_kind IN ('noop', 'pass_only', 'stub')
ORDER BY s.file, s.line""",
    ),
    # 10 — circular imports
    QueryTemplate(
        pattern=[
            "circular imports",
            "circular",
            "import cycles",
            "cyclic imports",
            "mutual imports",
        ],
        description="Circular imports: file pairs that mutually import each other",
        sql="""\
SELECT DISTINCT s1.file AS file_a, s2.file AS file_b
FROM edges e1
JOIN symbols s1 ON e1.source_id = s1.id
JOIN symbols s2 ON e1.target_id = s2.id
JOIN edges e2 ON e2.source_id = s2.id AND e2.target_id = s1.id
WHERE e1.kind = 'imports' AND e2.kind = 'imports'
AND s1.file != s2.file
ORDER BY s1.file""",
    ),
    # 11 — high complexity / many statements
    QueryTemplate(
        pattern=[
            "complex functions",
            "high complexity",
            "many statements",
            "large functions",
            "long functions",
        ],
        description="Complex functions with more than 10 statements",
        sql="""\
SELECT s.name, s.file, s.line, s.stmt_count
FROM symbols s
WHERE s.kind IN ('function', 'method')
AND s.stmt_count > 10
ORDER BY s.stmt_count DESC
LIMIT 20""",
    ),
    # 12 — all classes
    QueryTemplate(
        pattern=["all classes", "list classes", "show classes", "class list", "every class"],
        description="All classes in the codebase",
        sql="""\
SELECT s.name, s.file, s.line
FROM symbols s
WHERE s.kind = 'class'
ORDER BY s.file, s.line""",
    ),
]


# ---------------------------------------------------------------------------
# Fuzzy matching helpers
# ---------------------------------------------------------------------------


def _score(question: str, template: QueryTemplate) -> int:
    """Count how many template patterns appear as substrings in the question.

    Multi-word patterns ("highest fan-out") score the same as single-word
    patterns ("fan-out") — each match adds 1.  Duplicate hits for overlapping
    patterns (e.g. "fan-out" inside "highest fan-out") are each counted once,
    which naturally rewards templates whose pattern set has more specific hits.
    """
    q = question.lower()
    return sum(1 for kw in template.pattern if kw.lower() in q)


def _extract_param(question: str, patterns: list[str]) -> str | None:
    """Try each regex pattern against *question* and return the first capture.

    Patterns are applied with re.IGNORECASE but the original casing of the
    captured group is preserved so symbol names stay intact.
    """
    for pattern in patterns:
        m = re.search(pattern, question, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _match_template(question: str) -> tuple[QueryTemplate | None, str | None]:
    """Return the best-matching template and extracted parameter (if any).

    Returns (None, None) when no template scores above zero.
    """
    scored = [(t, _score(question, t)) for t in TEMPLATES]
    best_template, best_score = max(scored, key=lambda x: x[1])

    if best_score == 0:
        return None, None

    param: str | None = None
    if best_template.param_extract_patterns:
        param = _extract_param(question, best_template.param_extract_patterns)

    return best_template, param


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def query_code(question: str, db_path: Path) -> QueryResult:
    """Translate a natural-language question into SQL and execute it.

    Parameters
    ----------
    question:
        Free-text question from the user.
    db_path:
        Filesystem path to the CodeGraph SQLite database.

    Returns
    -------
    QueryResult
        When a template matches: populated ``rows`` and ``columns``.
        When no template matches: ``query`` is an empty string and ``rows``
        lists all available templates so the caller can guide the user.
    """
    template, param = _match_template(question)

    if template is None:
        logger.debug("nl_query.no_match", question=question)
        return QueryResult(
            query="",
            description="No matching template found. Available queries:",
            rows=[
                {
                    "template": t.description,
                    "keywords": ", ".join(t.pattern[:3]),
                }
                for t in TEMPLATES
            ],
            columns=["template", "keywords"],
        )

    # Build the SQL: replace {param} with a positional bind parameter
    sql = template.sql
    bind_params: tuple = ()
    if "{param}" in sql:
        if param is None:
            logger.debug("nl_query.param_required_not_found", question=question)
            return QueryResult(
                query=template.sql,
                description=(
                    f"{template.description} — parameter required but not found in question. "
                    "Try: 'what depends on <symbol_name>'"
                ),
                rows=[],
                columns=[],
            )
        sql = sql.replace("{param}", "?")
        bind_params = (param,)

    logger.debug("nl_query.execute", template=template.description, param=param)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(sql, bind_params)
        raw_rows = cursor.fetchall()
    except sqlite3.OperationalError as exc:
        logger.warning("nl_query.sql_error", error=str(exc), template=template.description)
        return QueryResult(
            query=template.sql,
            description=template.description,
            rows=[],
            columns=[],
        )
    finally:
        conn.close()

    if not raw_rows:
        return QueryResult(
            query=template.sql,
            description=template.description,
            rows=[],
            columns=[],
        )

    columns = list(raw_rows[0].keys())
    return QueryResult(
        query=template.sql,
        description=template.description,
        rows=[dict(r) for r in raw_rows],
        columns=columns,
    )
