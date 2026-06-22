"""Tests for nl_query — NL-to-SQL code query interface.

Tests are structured to follow TDD red-green discipline:
each test was written BEFORE the implementation.
"""

# tested-by: tests/unit/test_nl_query.py

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from caliper.core.nl_query import (
    TEMPLATES,
    QueryTemplate,
    _extract_param,
    _match_template,
    _score,
    query_code,
)
from caliper.plugins._runners.graph_builder import CodeGraph

# ---------------------------------------------------------------------------
# Minimal SQLite schema for SQL validity tests (mirrors graph_builder.py)
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER,
    hash TEXT,
    body_kind TEXT,
    stmt_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    confidence REAL DEFAULT 1.0
);
CREATE TABLE IF NOT EXISTS file_metadata (
    path TEXT PRIMARY KEY,
    mtime REAL,
    content_hash TEXT
);
"""


# ---------------------------------------------------------------------------
# SQL validity: every template must parse without OperationalError
# ---------------------------------------------------------------------------
class TestTemplateSQLValidity:
    """Each template's SQL must be syntactically valid against the real schema."""

    @pytest.mark.parametrize("template", TEMPLATES, ids=lambda t: t.description[:55])
    def test_sql_is_valid(self, template: QueryTemplate) -> None:
        conn = sqlite3.connect(":memory:")
        conn.executescript(_SCHEMA)
        sql = template.sql
        if "{param}" in sql:
            sql = sql.replace("{param}", "?")
            try:
                conn.execute(sql, ("test_symbol",))
            except sqlite3.OperationalError as exc:
                pytest.fail(f"SQL error in '{template.description}': {exc}")
        else:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError as exc:
                pytest.fail(f"SQL error in '{template.description}': {exc}")
        conn.close()


# ---------------------------------------------------------------------------
# Fuzzy matching: questions route to correct templates
# ---------------------------------------------------------------------------
class TestFuzzyMatching:
    """Questions should route to the intended template by keyword overlap."""

    def test_fanout_question_matches_fanout_template(self) -> None:
        template, _ = _match_template("which functions have the highest fan-out?")
        assert template is not None
        all_patterns = " ".join(template.pattern).lower()
        assert "fan" in all_patterns or "fan-out" in all_patterns

    def test_upstream_question_matches_upstream_template(self) -> None:
        template, _ = _match_template("what depends on pipeline?")
        assert template is not None
        all_patterns = " ".join(template.pattern).lower()
        assert "depends on" in all_patterns or "upstream" in all_patterns

    def test_dead_code_matches_unused_template(self) -> None:
        template, _ = _match_template("show me dead code")
        assert template is not None
        all_patterns = " ".join(template.pattern).lower()
        assert "dead" in all_patterns or "unused" in all_patterns

    def test_downstream_question_matches_downstream_template(self) -> None:
        template, _ = _match_template("what does evaluate call?")
        assert template is not None
        all_patterns = " ".join(template.pattern).lower()
        assert "downstream" in template.description.lower() or "call" in all_patterns

    def test_stub_question_matches_stub_template(self) -> None:
        template, _ = _match_template("show me all stub functions")
        assert template is not None
        all_patterns = " ".join(template.pattern).lower()
        assert "stub" in all_patterns or "noop" in all_patterns

    def test_circular_imports_matches_circular_template(self) -> None:
        template, _ = _match_template("are there circular imports?")
        assert template is not None
        all_patterns = " ".join(template.pattern).lower()
        assert "circular" in all_patterns

    def test_unrecognized_question_returns_none(self) -> None:
        template, _ = _match_template("xyzzy frobnicate shibboleth")
        assert template is None

    def test_score_is_zero_for_unrelated_question(self) -> None:
        for t in TEMPLATES:
            assert _score("xyzzy frobnicate shibboleth", t) == 0


# ---------------------------------------------------------------------------
# No-match path: unrecognized question returns template listing
# ---------------------------------------------------------------------------
class TestNoMatchResult:
    """Unrecognized questions return a QueryResult listing all templates."""

    def test_no_match_returns_template_list(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test.db"
        CodeGraph(str(db_file))  # creates schema, no data needed
        result = query_code("xyzzy frobnicate shibboleth", db_file)
        assert result.query == ""
        assert len(result.rows) == len(TEMPLATES)
        assert len(result.columns) >= 1

    def test_no_match_result_columns_include_description(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test.db"
        CodeGraph(str(db_file))
        result = query_code("xyzzy frobnicate shibboleth", db_file)
        # At least one column should be named "template" or "description"
        assert any(c in result.columns for c in ("template", "description"))


# ---------------------------------------------------------------------------
# Parameter extraction from questions
# ---------------------------------------------------------------------------
class TestParamExtraction:
    """Parameterized templates extract symbol names from questions."""

    def test_upstream_extracts_param_depends_on(self) -> None:
        _, param = _match_template("what depends on pipeline")
        assert param == "pipeline"

    def test_upstream_extracts_param_callers_of(self) -> None:
        _, param = _match_template("callers of evaluate")
        assert param == "evaluate"

    def test_downstream_extracts_param_does_call(self) -> None:
        _, param = _match_template("what does evaluate call?")
        assert param == "evaluate"

    def test_extract_param_helper_returns_first_match(self) -> None:
        """_extract_param tries patterns in order and returns first capture."""
        param = _extract_param(
            "what depends on pipeline",
            [r"depends on (\w+)", r"on (\w+)"],
        )
        assert param == "pipeline"

    def test_extract_param_helper_returns_none_on_no_match(self) -> None:
        param = _extract_param("show me dead code", [r"depends on (\w+)"])
        assert param is None

    def test_extract_param_preserves_original_case(self) -> None:
        param = _extract_param(
            "callers of ReviewPipeline",
            [r"callers of (\w+)", r"of (\w+)"],
        )
        assert param == "ReviewPipeline"


# ---------------------------------------------------------------------------
# query_code against a real CodeGraph database
# ---------------------------------------------------------------------------
_SAMPLE_SOURCE = """\
def foo():
    bar()
    baz()


def bar():
    pass


def baz():
    pass


class MyClass(BaseClass):
    def method_one(self): ...
    def method_two(self): ...
"""


class TestQueryCodeWithRealDB:
    """query_code works correctly against a real CodeGraph SQLite file."""

    def _make_db(self, tmp_path: Path, source: str = _SAMPLE_SOURCE) -> Path:
        db_file = tmp_path / "code.db"
        graph = CodeGraph(str(db_file))
        graph.index_file("src/core/sample.py", source)
        graph.conn.commit()  # commit deferred edge inserts
        graph.conn.close()
        return db_file

    def test_fanout_query_returns_results(self, tmp_path: Path) -> None:
        db = self._make_db(tmp_path)
        result = query_code("which functions have the highest fan-out?", db)
        assert result.query != ""
        assert isinstance(result.rows, list)
        assert isinstance(result.columns, list)
        assert len(result.columns) > 0

    def test_fanout_query_result_has_name_column(self, tmp_path: Path) -> None:
        db = self._make_db(tmp_path)
        result = query_code("which functions have the highest fan-out?", db)
        assert "name" in result.columns

    def test_dead_code_query_returns_results(self, tmp_path: Path) -> None:
        db = self._make_db(tmp_path)
        result = query_code("show me unused functions", db)
        assert result.query != ""
        assert isinstance(result.rows, list)

    def test_upstream_query_with_param_finds_callers(self, tmp_path: Path) -> None:
        """foo calls bar, so 'what depends on bar' should return foo."""
        db = self._make_db(tmp_path)
        result = query_code("what depends on bar", db)
        assert result.query != ""
        names = [r.get("name") for r in result.rows]
        assert "foo" in names

    def test_result_shape_is_valid(self, tmp_path: Path) -> None:
        db = self._make_db(tmp_path)
        result = query_code("largest files by symbol count", db)
        assert isinstance(result.query, str)
        assert isinstance(result.description, str)
        assert isinstance(result.rows, list)
        assert isinstance(result.columns, list)

    def test_all_row_dicts_have_column_keys(self, tmp_path: Path) -> None:
        db = self._make_db(tmp_path)
        result = query_code("largest files by symbol count", db)
        for row in result.rows:
            for col in result.columns:
                assert col in row

    def test_empty_db_returns_empty_rows_not_error(self, tmp_path: Path) -> None:
        db_file = tmp_path / "empty.db"
        CodeGraph(str(db_file))  # schema only, no data
        result = query_code("largest files by symbol count", db_file)
        assert result.query != ""
        assert result.rows == []

    def test_downstream_query_with_param(self, tmp_path: Path) -> None:
        """foo calls bar and baz — 'what does foo call' should include bar."""
        db = self._make_db(tmp_path)
        result = query_code("what does foo call", db)
        assert result.query != ""
        names = [r.get("name") for r in result.rows]
        assert "bar" in names or "baz" in names


# ---------------------------------------------------------------------------
# Template coverage: ensure at least 10 templates are registered
# ---------------------------------------------------------------------------
class TestTemplateCoverage:
    def test_at_least_ten_templates(self) -> None:
        assert len(TEMPLATES) >= 10

    def test_all_templates_have_pattern(self) -> None:
        for t in TEMPLATES:
            assert len(t.pattern) >= 1, f"Template '{t.description}' has empty pattern list"

    def test_all_templates_have_description(self) -> None:
        for t in TEMPLATES:
            assert t.description.strip() != ""

    def test_all_templates_have_sql(self) -> None:
        for t in TEMPLATES:
            assert t.sql.strip().upper().startswith("SELECT") or "WITH" in t.sql.upper()
