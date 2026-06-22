"""Code knowledge graph — AST to SQLite.

Parses Python/JS/TS source into a call graph stored in SQLite.
No LLM. No network. Pure AST analysis + SQL queries.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import sqlite3
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_GRAPH_DB_FILENAME = "code_graph.sqlite"


def default_graph_db_dir(repo_path: Path | str) -> Path:
    """Return the per-repo cache directory for the graph database.

    Defaults to ``$XDG_CACHE_HOME/eedom/graphs/<repo-hash>`` (falling back to
    ``~/.cache`` when ``XDG_CACHE_HOME`` is unset).  The hash is derived from
    the resolved absolute repo path so each reviewed repo gets its own db.
    """
    cache_root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    digest = hashlib.sha256(str(Path(repo_path).resolve()).encode()).hexdigest()[:16]
    return cache_root / "eedom" / "graphs" / digest


def resolve_graph_db_path(repo_path: Path | str, configured: str | None = None) -> Path:
    """Resolve where the code graph SQLite db for *repo_path* lives.

    Resolution order:

    1. ``EEDOM_GRAPH_DB`` environment variable (explicit override).
    2. *configured* — an explicit path from repo config
       (``thresholds.blast-radius.graph_db`` in ``.eagle-eyed-dom.yaml``);
       relative values are resolved against *repo_path*.
    3. A pre-existing legacy ``<repo>/.eedom/code_graph.sqlite`` (the pre-0.3
       layout) keeps being used so existing graphs are not orphaned.
    4. Default: :func:`default_graph_db_dir`, i.e. the user cache dir —
       reviewing a repo never writes into the repo itself (issue #391).
    """
    env_override = os.environ.get("EEDOM_GRAPH_DB")
    if env_override:
        return Path(env_override)
    if configured:
        p = Path(configured)
        return p if p.is_absolute() else Path(repo_path) / p
    legacy = Path(repo_path) / ".eedom" / _GRAPH_DB_FILENAME
    if legacy.exists():
        return legacy
    return default_graph_db_dir(repo_path) / _GRAPH_DB_FILENAME


def _hash_file(file_path: str) -> str:
    """Return SHA-256 hex digest of file contents."""
    return hashlib.sha256(Path(file_path).read_bytes()).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,  -- function, class, method, module
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER,
    hash TEXT,
    body_kind TEXT,  -- noop, pass_only, return_none, return_input, log_only, stub, real
    stmt_count INTEGER DEFAULT 0,
    UNIQUE(name, file, line)
);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES symbols(id),
    target_id INTEGER NOT NULL REFERENCES symbols(id),
    kind TEXT NOT NULL,  -- calls, imports, inherits
    confidence REAL DEFAULT 1.0,
    UNIQUE(source_id, target_id, kind)
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    query TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    description TEXT
);

CREATE TABLE IF NOT EXISTS file_metadata (
    path TEXT PRIMARY KEY,
    mtime REAL,
    content_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
"""


def _finding_message(check_name: str, description: str | None, finding: dict) -> str:
    """Build a non-empty human-readable message for a check finding.

    Base text is the check's description, falling back to the check name
    (NOT NULL in the schema), so the result is never empty (issue #390).
    Row context — subject symbol/files and metric columns — is appended
    deterministically when present.
    """
    existing = str(finding.get("message") or "").strip()
    if existing:
        return existing
    base = str(description or "").strip() or check_name
    name = finding.get("name")
    file = finding.get("file")
    subject = ""
    if name and name != file:
        subject = str(name)
    elif finding.get("file_a") and finding.get("file_b"):
        subject = f"{finding['file_a']} <-> {finding['file_b']}"
    metrics = [
        f"{key}={finding[key]}"
        for key in ("dependents", "calls_out", "depth", "import_count", "method_count")
        if finding.get(key) is not None
    ]
    msg = base
    if subject:
        msg = f"{base}: {subject}"
    if metrics:
        msg = f"{msg} ({', '.join(metrics)})"
    return msg


_CHECKS_YAML = Path(__file__).parent / "checks.yaml"


def _load_builtin_checks() -> list[dict]:
    import yaml

    if _CHECKS_YAML.exists():
        data = yaml.safe_load(_CHECKS_YAML.read_text())
        return data.get("checks", [])
    return []


class CodeGraph:
    """SQLite-backed code knowledge graph.

    Path convention (issue #387): ``symbols.file`` and ``file_metadata.path``
    store paths RELATIVE to the repo root. Once a repo root is known — passed
    to the constructor or inferred by :meth:`index_directory` — every public
    method accepts either repo-relative or absolute paths and normalizes them
    at the boundary. Absolute paths outside the repo root raise ``ValueError``.

    Without a repo root (``CodeGraph()`` ad hoc usage) paths are stored and
    matched exactly as given — callers must then be consistent about which
    form they use.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        fan_out_limit: int = 8,
        repo_root: str | Path | None = None,
    ) -> None:
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self._fan_out_limit = fan_out_limit
        self.repo_root: Path | None = Path(repo_root).resolve() if repo_root else None
        self._register_builtin_checks()

    # ------------------------------------------------------------------
    # Path normalization at the API boundary (issue #387)
    # ------------------------------------------------------------------

    def _storage_key(self, file_path: str | Path) -> str:
        """Return the stored (repo-relative) form of *file_path*.

        Absolute paths are relativized against ``repo_root``; absolute paths
        outside the root are rejected with a clear error. Relative paths are
        assumed repo-relative and returned unchanged. Without a repo root the
        path passes through as given (legacy behavior).
        """
        p = Path(file_path)
        if not p.is_absolute():
            return str(file_path)
        if self.repo_root is None:
            return str(file_path)
        try:
            return str(p.resolve().relative_to(self.repo_root))
        except ValueError:
            raise ValueError(
                f"Path {file_path} is outside the repo root {self.repo_root}; "
                "pass a repo-relative path or an absolute path under the root."
            ) from None

    def _disk_path(self, file_path: str | Path) -> Path:
        """Return the on-disk path for *file_path* (for stat/read).

        Relative paths resolve against ``repo_root`` when known, otherwise
        against the current working directory (legacy behavior).
        """
        p = Path(file_path)
        if p.is_absolute() or self.repo_root is None:
            return p
        return self.repo_root / p

    def _register_builtin_checks(self) -> None:
        required = {"name", "query", "severity", "description"}
        for check in _load_builtin_checks():
            if not required.issubset(check):
                logger.warning("graph.malformed_check", missing=sorted(required - set(check)))
                continue
            self.conn.execute(
                "INSERT OR IGNORE INTO checks (name, query, severity, description)"
                " VALUES (?, ?, ?, ?)",
                (check["name"], check["query"], check["severity"], check["description"]),
            )
        self.conn.commit()

    def register_check(
        self,
        name: str,
        query: str,
        severity: str = "info",
        description: str = "",
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO checks (name, query, severity, description)"
            " VALUES (?, ?, ?, ?)",
            (name, query, severity, description),
        )
        self.conn.commit()

    def index_file(self, file_path: str, source: str) -> None:
        if file_path.endswith(".py"):
            self._index_python(file_path, source)
        elif file_path.endswith((".ts", ".js", ".tsx", ".jsx")):
            self._index_javascript(file_path, source)

    def index_directory(self, root: Path) -> int:
        """Index every code file under *root*.

        Symbols are stored with paths RELATIVE to *root*. Also records *root*
        as the graph's repo root (when not already set), enabling absolute or
        relative paths interchangeably on subsequent API calls (issue #387).
        """
        if self.repo_root is None:
            self.repo_root = Path(root).resolve()
        count = 0
        for ext in ("*.py", "*.ts", "*.js", "*.tsx", "*.jsx"):
            for path in root.rglob(ext):
                if any(
                    p in str(path)
                    for p in (
                        ".git",
                        "__pycache__",
                        "node_modules",
                        ".venv",
                        ".claude",
                        ".eedom",
                    )
                ):
                    continue
                try:
                    self.index_file(str(path.relative_to(root)), path.read_text())
                    count += 1
                except Exception:
                    logger.debug("graph.index_skip", file=str(path))
        self.conn.commit()
        return count

    def run_checks(self, changed_files: list[str]) -> list[dict]:
        """Run all registered checks scoped to *changed_files*.

        Accepts repo-relative or absolute paths; both are normalized to the
        stored repo-relative form when the repo root is known (issue #387).
        Each returned finding dict carries check/severity/description, a
        non-empty human-readable ``message`` (issue #390), and the row's
        columns (typically ``name``/``file``/``line`` plus check metrics).
        """
        if not changed_files:
            return []
        changed_files = [self._storage_key(f) for f in changed_files]
        placeholders = ",".join("?" for _ in changed_files)
        checks = self.conn.execute("SELECT * FROM checks").fetchall()
        findings: list[dict] = []
        for check in checks:
            query = check["query"].replace("{changed_files}", placeholders)
            query = query.replace("{fan_out_limit}", str(self._fan_out_limit))
            try:
                rows = self.conn.execute(query, changed_files).fetchall()
                for row in rows:
                    finding = {
                        "check": check["name"],
                        "severity": check["severity"],
                        "description": check["description"],
                        **dict(row),
                    }
                    # Issue #390: every finding carries a non-empty,
                    # human-readable message — consumers render it directly.
                    finding["message"] = _finding_message(
                        check["name"], check["description"], finding
                    )
                    findings.append(finding)
            except sqlite3.Error as exc:
                logger.debug("graph.check_failed", check=check["name"], error=str(exc))
        return findings

    def run_checks_for_file(self, file_path: str | Path) -> list[dict]:
        """Run all registered checks scoped to a single file (issue #387).

        Per-file convenience wrapper around :meth:`run_checks` — accepts a
        repo-relative or absolute path and normalizes it to the stored form,
        so library consumers never have to reverse-engineer the storage
        convention from SQL.
        """
        return self.run_checks([str(file_path)])

    def symbol_at(self, file_path: str | Path, line: int) -> dict | None:
        """Return the innermost symbol enclosing *file_path*:*line*, or None.

        Deterministic: among symbols whose ``[line, end_line]`` span contains
        *line*, the innermost (largest start line) wins. The enrichment layer
        (ADR-006) uses this to map a finding location to its function/class.
        """
        key = self._storage_key(file_path)
        row = self.conn.execute(
            "SELECT name, kind, file, line, end_line FROM symbols "
            "WHERE file = ? AND line <= ? AND COALESCE(end_line, line) >= ? "
            "ORDER BY line DESC LIMIT 1",
            (key, line, line),
        ).fetchone()
        return dict(row) if row else None

    def blast_radius(self, symbol_name: str, max_depth: int = 3) -> list[dict]:
        results: list[dict] = []
        visited: set[int] = set()
        sym = self.conn.execute(
            "SELECT id FROM symbols WHERE name = ? LIMIT 1",
            (symbol_name,),
        ).fetchone()
        if not sym:
            return []
        self._walk_upstream(sym["id"], 1, max_depth, visited, results)
        return results

    def _walk_upstream(
        self,
        sym_id: int,
        depth: int,
        max_depth: int,
        visited: set[int],
        results: list[dict],
    ) -> None:
        if depth > max_depth or sym_id in visited:
            return
        visited.add(sym_id)
        rows = self.conn.execute(
            "SELECT s.name, s.file, s.line, s.kind, e.kind as edge_kind,"
            " e.confidence"
            " FROM edges e JOIN symbols s ON e.source_id = s.id"
            " WHERE e.target_id = ?",
            (sym_id,),
        ).fetchall()
        risk = {1: "WILL_BREAK", 2: "LIKELY_AFFECTED", 3: "MAY_NEED_TESTING"}
        for row in rows:
            results.append(
                {
                    "name": row["name"],
                    "file": row["file"],
                    "line": row["line"],
                    "depth": depth,
                    "risk": risk.get(depth, "TRANSITIVE"),
                    "edge": row["edge_kind"],
                    "confidence": row["confidence"],
                }
            )
            upstream = self.conn.execute(
                "SELECT id FROM symbols WHERE name = ? AND file = ?",
                (row["name"], row["file"]),
            ).fetchone()
            # Dangling edge: the referenced symbol may be absent from `symbols`
            # (stale graph / cross-file edge). Skip recursion rather than crash.
            if upstream is not None:
                self._walk_upstream(
                    upstream["id"],
                    depth + 1,
                    max_depth,
                    visited,
                    results,
                )

    def stats(self) -> dict:
        symbols = self.conn.execute("SELECT COUNT(*) as c FROM symbols").fetchone()["c"]
        edges = self.conn.execute("SELECT COUNT(*) as c FROM edges").fetchone()["c"]
        checks = self.conn.execute("SELECT COUNT(*) as c FROM checks").fetchone()["c"]
        files = self.conn.execute("SELECT COUNT(DISTINCT file) as c FROM symbols").fetchone()["c"]
        return {
            "symbols": symbols,
            "edges": edges,
            "checks": checks,
            "files": files,
        }

    def _index_python(self, file_path: str, source: str) -> None:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return

        deferred_edges: list[tuple[str, str, str, str]] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                body_kind = self._classify_body(node)
                self._upsert_symbol(
                    node.name,
                    "function",
                    file_path,
                    node.lineno,
                    node.end_lineno,
                    body_kind=body_kind,
                    stmt_count=len(node.body),
                )
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        target = self._call_name(child)
                        if target:
                            deferred_edges.append((node.name, file_path, target, "calls"))

            elif isinstance(node, ast.ClassDef):
                self._upsert_symbol(
                    node.name,
                    "class",
                    file_path,
                    node.lineno,
                    node.end_lineno,
                )
                for base in node.bases:
                    base_name = self._attr_name(base)
                    if base_name:
                        deferred_edges.append((node.name, file_path, base_name, "inherits"))

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self._add_import_edge(file_path, alias.name)

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        self._add_import_edge(
                            file_path,
                            f"{node.module}.{alias.name}",
                        )

        self.conn.commit()
        for src, src_file, tgt, kind in deferred_edges:
            self._add_edge(src, src_file, tgt, kind)

    def _index_javascript(self, file_path: str, source: str) -> None:
        func_re = re.compile(
            r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>)"
        )
        call_re = re.compile(r"\b(\w+)\s*\(")
        import_re = re.compile(
            r"(?:import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]"
            r"|require\s*\(\s*['\"]([^'\"]+)['\"]\s*\))"
        )
        class_re = re.compile(r"class\s+(\w+)(?:\s+extends\s+(\w+))?")

        for i, line in enumerate(source.split("\n"), 1):
            for m in func_re.finditer(line):
                name = m.group(1) or m.group(2)
                if name:
                    self._upsert_symbol(name, "function", file_path, i, None)

            for m in call_re.finditer(line):
                self._add_edge(file_path, file_path, m.group(1), "calls", 0.7)

            for m in class_re.finditer(line):
                self._upsert_symbol(m.group(1), "class", file_path, i, None)
                if m.group(2):
                    self._add_edge(m.group(1), file_path, m.group(2), "inherits")

            for m in import_re.finditer(line):
                mod = m.group(1) or m.group(2)
                if mod:
                    self._add_import_edge(file_path, mod)

    def _upsert_symbol(
        self,
        name: str,
        kind: str,
        file: str,
        line: int,
        end_line: int | None,
        body_kind: str | None = None,
        stmt_count: int = 0,
    ) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO symbols"
            " (name, kind, file, line, end_line, body_kind, stmt_count)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, kind, file, line, end_line, body_kind, stmt_count),
        )

    def _add_edge(
        self,
        source_name: str,
        source_file: str,
        target_name: str,
        kind: str,
        confidence: float = 1.0,
    ) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO edges (source_id, target_id, kind, confidence)"
            " SELECT s.id, t.id, ?, ?"
            " FROM symbols s, symbols t"
            " WHERE s.name = ? AND s.file = ? AND t.name = ?"
            " LIMIT 1",
            (kind, confidence, source_name, source_file, target_name),
        )

    def _add_import_edge(self, file_path: str, module_name: str) -> None:
        if module_name.startswith("/") or ".." in module_name or "\\" in module_name:
            return
        mod_symbol = module_name.split(".")[-1]
        self._upsert_symbol(file_path, "module", file_path, 0, None)
        self._upsert_symbol(mod_symbol, "module", module_name, 0, None)
        self.conn.execute(
            "INSERT OR IGNORE INTO edges (source_id, target_id, kind, confidence)"
            " SELECT s.id, t.id, 'imports', 1.0"
            " FROM symbols s, symbols t"
            " WHERE s.name = ? AND s.file = ? AND t.name = ?",
            (file_path, file_path, mod_symbol),
        )

    @staticmethod
    def _call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    @staticmethod
    def _attr_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    @staticmethod
    def _classify_body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        body = node.body
        real_stmts = [
            s
            for s in body
            if not (
                isinstance(s, ast.Expr)
                and isinstance(s.value, ast.Constant | ast.JoinedStr)
                and isinstance(getattr(s.value, "value", None), str)
            )
        ]
        if not real_stmts:
            return "noop"
        if len(real_stmts) == 1:
            s = real_stmts[0]
            if isinstance(s, ast.Pass):
                return "pass_only"
            if (
                isinstance(s, ast.Expr)
                and isinstance(s.value, ast.Constant)
                and s.value.value is Ellipsis
            ):
                return "stub"
            if isinstance(s, ast.Return) and (
                s.value is None or (isinstance(s.value, ast.Constant) and s.value.value is None)
            ):
                return "return_none"
            if (
                isinstance(s, ast.Raise)
                and s.exc is not None
                and (
                    (
                        isinstance(s.exc, ast.Call)
                        and isinstance(s.exc.func, ast.Name)
                        and s.exc.func.id == "NotImplementedError"
                    )
                    or (isinstance(s.exc, ast.Name) and s.exc.id == "NotImplementedError")
                )
            ):
                return "stub"
        if len(real_stmts) <= 2:
            all_log = all(
                isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and _is_log_call(s.value)
                for s in real_stmts
            )
            if all_log:
                return "log_only"
            last = real_stmts[-1]
            if (
                isinstance(last, ast.Return)
                and last.value is None
                and len(real_stmts) == 2
                and isinstance(real_stmts[0], ast.Expr)
                and isinstance(real_stmts[0].value, ast.Call)
                and _is_log_call(real_stmts[0].value)
            ):
                return "log_only"
        return "real"

    def needs_rebuild(self, file_path: str) -> bool:
        """Return True if file_path is new or has changed since last rebuild.

        Accepts a repo-relative or absolute path (issue #387): metadata is
        looked up by the stored repo-relative key, while mtime/hash are
        checked against the resolved on-disk path.
        """
        key = self._storage_key(file_path)
        disk = self._disk_path(file_path)
        row = self.conn.execute(
            "SELECT mtime, content_hash FROM file_metadata WHERE path = ?",
            (key,),
        ).fetchone()
        if row is None:
            return True
        try:
            stat = disk.stat()
            if abs(stat.st_mtime - row["mtime"]) > 0.001:
                # mtime changed — confirm via content hash
                return _hash_file(str(disk)) != row["content_hash"]
            return False
        except FileNotFoundError:
            return True

    def rebuild_file(self, file_path: str) -> None:
        """Delete old symbols/edges for file_path, re-parse from disk, update metadata.

        Accepts a repo-relative or absolute path (issue #387). Symbols and
        metadata are stored under the repo-relative key; file contents are
        read from the resolved on-disk path.
        """
        key = self._storage_key(file_path)
        disk = self._disk_path(file_path)
        # Remove edges that involve symbols from this file
        self.conn.execute(
            "DELETE FROM edges"
            " WHERE source_id IN (SELECT id FROM symbols WHERE file = ?)"
            " OR target_id IN (SELECT id FROM symbols WHERE file = ?)",
            (key, key),
        )
        self.conn.execute("DELETE FROM symbols WHERE file = ?", (key,))
        self.conn.commit()

        content = disk.read_text()
        self.index_file(key, content)
        self.conn.commit()

        stat = disk.stat()
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        self.conn.execute(
            "INSERT OR REPLACE INTO file_metadata (path, mtime, content_hash) VALUES (?, ?, ?)",
            (key, stat.st_mtime, content_hash),
        )
        self.conn.commit()

    def purge_deleted_files(self, existing_files: list[str]) -> int:
        """Remove symbols/edges/metadata for files no longer on disk.

        Keys on actual disk existence, NOT membership in existing_files.
        A tracked file absent from the argument list but still present on
        disk must survive — per-file incremental callers
        (rebuild_incremental([one_file])) pass only the changed file, and
        list-membership purging destroyed every other tracked file's
        symbols (gitrdunhq/eedom#385). existing_files is retained for
        API compatibility but no longer consulted.

        Stored keys are resolved via :meth:`_disk_path` (issue #387), so the
        existence check is correct regardless of the caller's cwd.
        """
        tracked = self.conn.execute("SELECT path FROM file_metadata").fetchall()
        purged = 0
        for row in tracked:
            if not self._disk_path(row["path"]).exists():
                self.conn.execute(
                    "DELETE FROM edges"
                    " WHERE source_id IN (SELECT id FROM symbols WHERE file = ?)"
                    " OR target_id IN (SELECT id FROM symbols WHERE file = ?)",
                    (row["path"], row["path"]),
                )
                self.conn.execute("DELETE FROM symbols WHERE file = ?", (row["path"],))
                self.conn.execute("DELETE FROM file_metadata WHERE path = ?", (row["path"],))
                purged += 1
        if purged:
            self.conn.commit()
        return purged

    def rebuild_incremental(self, files: list[str]) -> int:
        """Rebuild only changed files. Returns count of files actually rebuilt.

        *files* may be repo-relative or absolute paths (issue #387); each is
        normalized at the boundary by :meth:`needs_rebuild` /
        :meth:`rebuild_file` / :meth:`purge_deleted_files`.
        """
        code_suffixes = {".py", ".ts", ".js", ".tsx", ".jsx"}
        code_files = [f for f in files if Path(f).suffix in code_suffixes]
        self.purge_deleted_files(code_files)
        rebuilt = 0
        for file_path in code_files:
            if self.needs_rebuild(file_path):
                try:
                    self.rebuild_file(file_path)
                    rebuilt += 1
                except Exception:
                    logger.debug("graph.rebuild_skip", file=file_path)
        return rebuilt


def _is_log_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in (
            "info",
            "debug",
            "warning",
            "error",
            "exception",
            "log",
            "print",
            "warn",
        )
    if isinstance(node.func, ast.Name):
        return node.func.id == "print"
    return False


from eedom.core.registries import CODEGRAPH_CHECKS  # noqa: E402  (registration wiring)


@CODEGRAPH_CHECKS.register("blast-radius")
def build_code_graph(
    *,
    db_path: str = ":memory:",
    fan_out_limit: int = 8,
    repo_root: str | None = None,
) -> CodeGraph:
    """Construct the SQLite code-graph check-runner (no I/O; graph built later)."""
    return CodeGraph(db_path=db_path, fan_out_limit=fan_out_limit, repo_root=repo_root)
