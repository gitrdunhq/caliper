"""Tests for CodeGraph persistence and incremental rebuild.
# tested-by: tests/unit/test_graph_builder.py
"""

from __future__ import annotations

import hashlib
import os
import textwrap
import time

import pytest

from eedom.plugins._runners.graph_builder import CodeGraph

SAMPLE_A = textwrap.dedent("""\
    def alpha():
        return 1

    def beta():
        alpha()
""")

SAMPLE_B = textwrap.dedent("""\
    def gamma():
        return 2

    def delta():
        gamma()
""")

SAMPLE_A_MODIFIED = textwrap.dedent("""\
    def alpha():
        return 99

    def beta():
        alpha()

    def epsilon():
        beta()
""")


class TestCodeGraphPersistence:
    def test_persistence_roundtrip(self, tmp_path):
        """Build graph with file db_path, close connection, reopen, verify nodes exist."""
        db_file = str(tmp_path / "graph.sqlite")

        # First run — build graph
        g1 = CodeGraph(db_path=db_file)
        g1.index_file("scanner.py", SAMPLE_A)
        g1.conn.commit()
        stats1 = g1.stats()
        assert stats1["symbols"] > 0
        g1.conn.close()

        # Second run — reopen same db, data must survive
        g2 = CodeGraph(db_path=db_file)
        stats2 = g2.stats()
        assert (
            stats2["symbols"] == stats1["symbols"]
        ), "symbols must survive connection close/reopen"
        funcs = g2.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        names = {r["name"] for r in funcs}
        assert "alpha" in names
        assert "beta" in names

    def test_in_memory_still_works(self):
        """db_path=':memory:' backward compatibility preserved."""
        g = CodeGraph(db_path=":memory:")
        g.index_file("t.py", SAMPLE_A)
        g.conn.commit()
        stats = g.stats()
        assert stats["symbols"] > 0


class TestFileMetadata:
    def test_file_metadata_table_exists(self):
        """file_metadata table must be created on init."""
        g = CodeGraph()
        tables = g.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='file_metadata'"
        ).fetchone()
        assert tables is not None, "file_metadata table must exist"

    def test_needs_rebuild_returns_true_for_new_file(self, tmp_path):
        """needs_rebuild() returns True for a file never seen before."""
        db_file = str(tmp_path / "graph.sqlite")
        py_file = tmp_path / "module.py"
        py_file.write_text(SAMPLE_A)

        g = CodeGraph(db_path=db_file)
        assert g.needs_rebuild(str(py_file)) is True

    def test_needs_rebuild_returns_false_after_tracking(self, tmp_path):
        """needs_rebuild() returns False for a file that hasn't changed since last index."""
        db_file = str(tmp_path / "graph.sqlite")
        py_file = tmp_path / "module.py"
        py_file.write_text(SAMPLE_A)

        g = CodeGraph(db_path=db_file)
        # index and record metadata
        g.rebuild_file(str(py_file))

        # same file, same mtime and hash — no rebuild needed
        assert g.needs_rebuild(str(py_file)) is False

    def test_needs_rebuild_returns_true_after_content_change(self, tmp_path):
        """needs_rebuild() returns True when file content changes."""
        db_file = str(tmp_path / "graph.sqlite")
        py_file = tmp_path / "module.py"
        py_file.write_text(SAMPLE_A)

        g = CodeGraph(db_path=db_file)
        g.rebuild_file(str(py_file))
        assert g.needs_rebuild(str(py_file)) is False

        # Overwrite file with new content
        py_file.write_text(SAMPLE_A_MODIFIED)
        # Force mtime change by touching the file
        os.utime(py_file, (time.time() + 1, time.time() + 1))

        assert g.needs_rebuild(str(py_file)) is True

    def test_metadata_tracks_mtime_and_hash(self, tmp_path):
        """After rebuild_file, file_metadata records mtime and content_hash."""
        db_file = str(tmp_path / "graph.sqlite")
        py_file = tmp_path / "module.py"
        py_file.write_text(SAMPLE_A)

        g = CodeGraph(db_path=db_file)
        g.rebuild_file(str(py_file))

        row = g.conn.execute(
            "SELECT mtime, content_hash FROM file_metadata WHERE path = ?",
            (str(py_file),),
        ).fetchone()
        assert row is not None
        assert row["mtime"] == pytest.approx(py_file.stat().st_mtime, abs=0.01)
        expected_hash = hashlib.sha256(SAMPLE_A.encode()).hexdigest()
        assert row["content_hash"] == expected_hash


class TestIncrementalRebuild:
    def test_rebuild_incremental_only_rebuilds_changed_files(self, tmp_path):
        """rebuild_incremental re-parses only files whose mtime/hash changed."""
        db_file = str(tmp_path / "graph.sqlite")
        file_a = tmp_path / "a.py"
        file_b = tmp_path / "b.py"
        file_a.write_text(SAMPLE_A)
        file_b.write_text(SAMPLE_B)

        # First full build
        g = CodeGraph(db_path=db_file)
        g.rebuild_incremental([str(file_a), str(file_b)])

        # Capture symbol count after first build
        symbols_after_first = g.conn.execute("SELECT COUNT(*) as c FROM symbols").fetchone()["c"]
        assert symbols_after_first > 0

        # Modify file_a, leave file_b unchanged
        file_a.write_text(SAMPLE_A_MODIFIED)
        os.utime(file_a, (time.time() + 2, time.time() + 2))

        # Incremental rebuild
        g.rebuild_incremental([str(file_a), str(file_b)])

        # New symbols from SAMPLE_A_MODIFIED (epsilon) should be present
        funcs = g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        names = {r["name"] for r in funcs}
        assert "epsilon" in names, "epsilon added in SAMPLE_A_MODIFIED must be indexed"
        # gamma and delta from file_b must still be present (file_b untouched)
        assert "gamma" in names
        assert "delta" in names

    def test_rebuild_incremental_skips_unchanged_files(self, tmp_path):
        """rebuild_incremental does not re-index files that haven't changed."""
        db_file = str(tmp_path / "graph.sqlite")
        file_a = tmp_path / "a.py"
        file_a.write_text(SAMPLE_A)

        g = CodeGraph(db_path=db_file)
        g.rebuild_incremental([str(file_a)])

        # Record metadata row mtime
        row_before = g.conn.execute(
            "SELECT mtime FROM file_metadata WHERE path = ?", (str(file_a),)
        ).fetchone()
        assert row_before is not None

        # Second call with same file — should be no-op
        g.rebuild_incremental([str(file_a)])

        row_after = g.conn.execute(
            "SELECT mtime FROM file_metadata WHERE path = ?", (str(file_a),)
        ).fetchone()
        # mtime in metadata must not have changed (file wasn't re-indexed)
        assert row_after["mtime"] == row_before["mtime"]

    def test_first_run_builds_from_scratch(self, tmp_path):
        """If db file doesn't exist, rebuild_incremental builds everything."""
        db_file = str(tmp_path / "graph.sqlite")
        file_a = tmp_path / "a.py"
        file_b = tmp_path / "b.py"
        file_a.write_text(SAMPLE_A)
        file_b.write_text(SAMPLE_B)

        g = CodeGraph(db_path=db_file)
        g.rebuild_incremental([str(file_a), str(file_b)])

        funcs = g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        names = {r["name"] for r in funcs}
        assert "alpha" in names
        assert "beta" in names
        assert "gamma" in names
        assert "delta" in names

    def test_rebuild_file_removes_old_symbols(self, tmp_path):
        """rebuild_file deletes old symbols for a file before re-parsing."""
        db_file = str(tmp_path / "graph.sqlite")
        py_file = tmp_path / "module.py"
        py_file.write_text(SAMPLE_A)

        g = CodeGraph(db_path=db_file)
        g.rebuild_file(str(py_file))

        # Verify alpha is indexed
        row = g.conn.execute("SELECT name FROM symbols WHERE name = 'alpha'").fetchone()
        assert row is not None

        # Completely replace file content — alpha disappears, gamma appears
        py_file.write_text(SAMPLE_B)
        os.utime(py_file, (time.time() + 2, time.time() + 2))
        g.rebuild_file(str(py_file))

        names = {
            r["name"]
            for r in g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        }
        assert "alpha" not in names, "alpha must be removed after rebuild_file replaces content"
        assert "gamma" in names


class TestPurgeDeletedFiles:
    def test_purge_removes_symbols_for_deleted_file(self, tmp_path):
        """After deleting a file from disk, purge removes its symbols."""
        db_file = str(tmp_path / "graph.sqlite")
        file_a = tmp_path / "a.py"
        file_b = tmp_path / "b.py"
        file_a.write_text(SAMPLE_A)
        file_b.write_text(SAMPLE_B)

        g = CodeGraph(db_path=db_file)
        g.rebuild_incremental([str(file_a), str(file_b)])

        names_before = {
            r["name"]
            for r in g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        }
        assert "alpha" in names_before
        assert "gamma" in names_before

        file_a.unlink()
        g.rebuild_incremental([str(file_b)])

        names_after = {
            r["name"]
            for r in g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        }
        assert "alpha" not in names_after
        assert "gamma" in names_after

    def test_purge_returns_count(self, tmp_path):
        """purge_deleted_files returns correct count of purged files."""
        db_file = str(tmp_path / "graph.sqlite")
        file_a = tmp_path / "a.py"
        file_b = tmp_path / "b.py"
        file_a.write_text(SAMPLE_A)
        file_b.write_text(SAMPLE_B)

        g = CodeGraph(db_path=db_file)
        g.rebuild_incremental([str(file_a), str(file_b)])

        file_b.unlink()
        count = g.purge_deleted_files([str(file_a)])
        assert count == 1

    def test_single_file_rebuild_preserves_other_tracked_files(self, tmp_path):
        """rebuild_incremental([one_file]) must NOT purge other tracked files
        that still exist on disk.

        Regression for the per-write incremental pattern (datum agent-loop):
        write A -> rebuild_incremental([A]); write B -> rebuild_incremental([B]).
        The second call passed only B, and purge_deleted_files treated 'not in
        the argument list' as 'deleted from disk', destroying A's symbols.
        Purge must key on actual disk existence, not list membership.
        """
        db_file = str(tmp_path / "graph.sqlite")
        file_a = tmp_path / "a.py"
        file_b = tmp_path / "b.py"
        file_a.write_text(SAMPLE_A)
        file_b.write_text(SAMPLE_B)

        g = CodeGraph(db_path=db_file)
        # Per-write pattern: each file rebuilt in its own call
        g.rebuild_incremental([str(file_a)])
        g.rebuild_incremental([str(file_b)])

        names = {
            r["name"]
            for r in g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        }
        assert "alpha" in names, "file_a still exists on disk — its symbols must survive"
        assert "gamma" in names

        # And the metadata row for file_a must survive too
        row = g.conn.execute(
            "SELECT path FROM file_metadata WHERE path = ?", (str(file_a),)
        ).fetchone()
        assert row is not None, "file_a metadata must not be purged while it exists on disk"

    def test_purge_with_all_files_present_returns_zero(self, tmp_path):
        """purge_deleted_files with all files still present returns 0."""
        db_file = str(tmp_path / "graph.sqlite")
        file_a = tmp_path / "a.py"
        file_a.write_text(SAMPLE_A)

        g = CodeGraph(db_path=db_file)
        g.rebuild_incremental([str(file_a)])

        count = g.purge_deleted_files([str(file_a)])
        assert count == 0
        names = {
            r["name"]
            for r in g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        }
        assert "alpha" in names


class TestPathNormalization:
    """Issue #387 — CodeGraph normalizes paths at the API boundary.

    Convention: symbols/file_metadata store paths RELATIVE to the repo root.
    Every public method accepts either repo-relative or absolute paths once a
    repo root is known (constructor arg or index_directory), and absolute
    paths outside the root are rejected loudly.
    """

    def _build(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_text(SAMPLE_A)
        (repo / "b.py").write_text(SAMPLE_B)
        g = CodeGraph(db_path=str(tmp_path / "graph.sqlite"))
        g.index_directory(repo)
        return repo, g

    def test_run_checks_accepts_absolute_paths(self, tmp_path):
        repo, g = self._build(tmp_path)
        rel = g.run_checks(["a.py"])
        absolute = g.run_checks([str(repo / "a.py")])
        assert rel, "relative path must produce findings (orphan alpha/beta)"
        assert absolute == rel, "absolute path must match the same stored rows"

    def test_run_checks_for_file_accepts_both_forms(self, tmp_path):
        repo, g = self._build(tmp_path)
        rel = g.run_checks_for_file("a.py")
        absolute = g.run_checks_for_file(str(repo / "a.py"))
        assert rel
        assert absolute == rel

    def test_rebuild_stores_relative_paths_no_duplicate_spellings(self, tmp_path):
        repo, g = self._build(tmp_path)
        (repo / "a.py").write_text(SAMPLE_A_MODIFIED)
        os.utime(repo / "a.py", (time.time() + 2, time.time() + 2))

        g.rebuild_incremental([str(repo / "a.py"), str(repo / "b.py")])

        files = {
            r["file"]
            for r in g.conn.execute("SELECT DISTINCT file FROM symbols").fetchall()
            if r["file"].endswith(".py")
        }
        assert files == {"a.py", "b.py"}, f"expected only relative spellings, got: {files}"
        # And the rebuilt content must be queryable via the relative form.
        findings = g.run_checks(["a.py"])
        names = {f.get("name") for f in findings}
        assert "epsilon" in names

    def test_needs_rebuild_accepts_relative_path(self, tmp_path):
        repo, g = self._build(tmp_path)
        g.rebuild_incremental(["a.py"])
        assert g.needs_rebuild("a.py") is False
        assert g.needs_rebuild(str(repo / "a.py")) is False

    def test_absolute_path_outside_root_rejected_loudly(self, tmp_path):
        repo, g = self._build(tmp_path)
        outside = tmp_path / "elsewhere" / "x.py"
        with pytest.raises(ValueError, match="repo root"):
            g.run_checks([str(outside)])

    def test_constructor_repo_root(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_text(SAMPLE_A)
        g = CodeGraph(db_path=str(tmp_path / "g.sqlite"), repo_root=repo)
        g.rebuild_incremental([str(repo / "a.py")])
        row = g.conn.execute("SELECT path FROM file_metadata").fetchone()
        assert row["path"] == "a.py", "metadata must use the repo-relative key"
        assert g.run_checks_for_file(str(repo / "a.py"))

    def test_no_repo_root_keeps_legacy_behavior(self, tmp_path):
        """Without a known root, paths are stored exactly as given."""
        py_file = tmp_path / "module.py"
        py_file.write_text(SAMPLE_A)
        g = CodeGraph()
        g.rebuild_file(str(py_file))
        row = g.conn.execute("SELECT path FROM file_metadata").fetchone()
        assert row["path"] == str(py_file)


class TestImportEdgePathTraversal:
    """_add_import_edge must reject paths that could escape the indexed directory."""

    def test_rejects_absolute_path(self):
        """Absolute path as module_name must not be stored in the database."""
        graph = CodeGraph(":memory:")
        graph._add_import_edge("legitimate.py", "/etc/passwd")
        result = graph.conn.execute(
            "SELECT * FROM symbols WHERE file = ?", ("/etc/passwd",)
        ).fetchall()
        assert len(result) == 0, "Absolute path must not be stored in symbols table"

    def test_rejects_parent_traversal(self):
        """Parent-traversal module names must not be stored in the database."""
        graph = CodeGraph(":memory:")
        graph._add_import_edge("src/mycode.py", "../../sensitive/module")
        result = graph.conn.execute(
            "SELECT * FROM symbols WHERE file = ?", ("../../sensitive/module",)
        ).fetchall()
        assert len(result) == 0, "Parent-traversal path must not be stored in symbols table"

    def test_rejects_backslash_traversal(self):
        """Windows-style path traversal must be rejected."""
        graph = CodeGraph(":memory:")
        graph._add_import_edge("src/mycode.py", "..\\..\\sensitive")
        result = graph.conn.execute(
            "SELECT * FROM symbols WHERE file = ?", ("..\\..\\sensitive",)
        ).fetchall()
        assert len(result) == 0, "Backslash traversal must not be stored"

    def test_accepts_valid_dotted_module(self):
        """Standard dotted module names like 'utils.helpers' must be indexed."""
        graph = CodeGraph(":memory:")
        graph._add_import_edge("src/mycode.py", "utils.helpers")
        result = graph.conn.execute("SELECT * FROM symbols WHERE name = 'helpers'").fetchall()
        assert len(result) > 0, "Valid dotted module name must be indexed"

    def test_accepts_stdlib_module(self):
        """Standard library names like 'os.path' must be indexed."""
        graph = CodeGraph(":memory:")
        graph._add_import_edge("app.py", "os.path")
        result = graph.conn.execute("SELECT * FROM symbols WHERE name = 'path'").fetchall()
        assert len(result) > 0, "stdlib module name must be indexed"


class TestMalformedChecksYaml:
    """_register_builtin_checks must skip malformed entries without crashing."""

    def test_malformed_check_missing_query_is_skipped(self, tmp_path):
        """A check entry missing 'query' is skipped; valid checks are still registered."""
        from unittest.mock import patch

        yaml_content = textwrap.dedent("""\
            checks:
              - name: valid_check
                query: "SELECT COUNT(*) as c FROM symbols"
                severity: info
                description: "A valid check"
              - name: missing_query_check
                severity: warning
                description: "This entry is missing the query field"
            """)
        yaml_path = tmp_path / "checks.yaml"
        yaml_path.write_text(yaml_content)

        with patch("eedom.plugins._runners.graph_builder._CHECKS_YAML", yaml_path):
            graph = CodeGraph()  # must not raise

        count = graph.conn.execute("SELECT COUNT(*) as c FROM checks").fetchone()["c"]
        assert count == 1, f"Expected 1 valid check registered, got {count}"

    def test_malformed_check_missing_name_is_skipped(self, tmp_path):
        """A check entry missing 'name' is skipped without crashing."""
        from unittest.mock import patch

        yaml_content = textwrap.dedent("""\
            checks:
              - name: good_check
                query: "SELECT COUNT(*) as c FROM symbols"
                severity: info
                description: "Valid"
              - query: "SELECT COUNT(*) as c FROM symbols"
                severity: info
                description: "Missing name field"
            """)
        yaml_path = tmp_path / "checks.yaml"
        yaml_path.write_text(yaml_content)

        with patch("eedom.plugins._runners.graph_builder._CHECKS_YAML", yaml_path):
            graph = CodeGraph()

        count = graph.conn.execute("SELECT COUNT(*) as c FROM checks").fetchone()["c"]
        assert count == 1, f"Expected 1 valid check, got {count}"


class TestBlastRadiusPersistence:
    def test_blast_radius_plugin_uses_persistent_db(self, tmp_path, monkeypatch):
        """BlastRadiusPlugin reads db_path from config and passes it to CodeGraph."""
        from eedom.plugins.blast_radius import BlastRadiusPlugin

        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        plugin = BlastRadiusPlugin()
        # The plugin's run() should not crash when called with a tmp repo_path
        # Create a minimal Python file so indexing succeeds
        src = tmp_path / "main.py"
        src.write_text(SAMPLE_A)
        result = plugin.run([str(src)], repo_path=tmp_path)
        assert result.error == ""
        assert result.summary.get("symbols_indexed", 0) > 0


class TestSqlInjectionPrevention:
    """Wave 1 Task 1.1: file paths must not be interpolated into SQL."""

    def test_injection_does_not_match_unrelated_files(self, tmp_path):
        """SQL injection via file path must not return rows from other files.

        Uses a real SQLite db + a custom check with {changed_files}.
        With vulnerable code (f-string interpolation), `' OR 1=1 --` expands to
        IN ('' OR 1=1 --') which matches ALL rows. With parameterized queries,
        the literal string "' OR 1=1 --" is bound and matches nothing.
        """
        graph = CodeGraph(str(tmp_path / "test.db"))
        graph.index_file("legit.py", SAMPLE_A)

        graph.register_check(
            name="injection-test",
            query="SELECT name, file FROM symbols WHERE file IN ({changed_files})",
            severity="high",
            description="test check",
        )

        findings = graph.run_checks(["') OR file IS NOT NULL --"])

        # With parameterized binding: zero findings (literal string matches nothing)
        # With interpolation: IN ('') OR file IS NOT NULL --') matches ALL rows
        legit_hits = [f for f in findings if f.get("file") == "legit.py"]
        assert len(legit_hits) == 0, (
            f"SQL injection: matched {len(legit_hits)} rows from legit.py "
            f"via injected file path"
        )

    def test_file_path_with_quotes_safe(self, tmp_path):
        """Paths with single/double quotes must be handled safely."""
        graph = CodeGraph(str(tmp_path / "test.db"))
        graph.index_file("safe.py", SAMPLE_A)

        graph.register_check(
            name="quotes-test",
            query="SELECT name, file FROM symbols WHERE file IN ({changed_files})",
            severity="info",
            description="test check",
        )

        tricky_paths = [
            "file'with'quotes.py",
            'file"with"doublequotes.py',
            "file\\with\\backslashes.py",
        ]
        findings = graph.run_checks(tricky_paths)
        count = graph.conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        assert count > 0


# ---------------------------------------------------------------------------
# Regression P15-2 — _walk_upstream fetchone None guard
# ---------------------------------------------------------------------------


class TestWalkUpstreamNoneGuardRegression:
    """Regression for P15-2: _walk_upstream called upstream["id"] without first
    checking that the fetchone() result was not None (dangling edge — cross-file
    call where the callee is absent from the symbols table).  blast_radius() must
    not raise TypeError when such a dangling edge exists."""

    def test_blast_radius_dangling_edge_does_not_raise(self):
        """blast_radius() must not raise when an edge target is absent from symbols.

        Simulates a dangling edge: symbol A calls B, but B's definition is not
        in the graph (the callee file was never indexed or was deleted).  The
        _walk_upstream traversal must skip rather than crash on None fetchone()."""
        graph = CodeGraph()

        # Manually insert a symbol and a dangling edge that points to a
        # non-existent target symbol id (99999)
        graph.conn.execute(
            "INSERT INTO symbols (name, kind, file, line) VALUES ('A', 'function', 'a.py', 1)"
        )
        sym_id = graph.conn.execute("SELECT id FROM symbols WHERE name = 'A'").fetchone()["id"]

        # Insert a ghost target to satisfy FK (we'll query by name+file, not id)
        graph.conn.execute(
            "INSERT INTO symbols (name, kind, file, line) VALUES ('B', 'function', 'b.py', 1)"
        )
        target_id = graph.conn.execute("SELECT id FROM symbols WHERE name = 'B'").fetchone()["id"]

        # Add edge A -> B
        graph.conn.execute(
            "INSERT INTO edges (source_id, target_id, kind) VALUES (?, ?, 'calls')",
            (sym_id, target_id),
        )
        # Now DELETE symbol B to create the dangling condition
        graph.conn.execute("DELETE FROM symbols WHERE name = 'B'")
        graph.conn.commit()

        try:
            results = graph.blast_radius("A")
        except (TypeError, KeyError) as exc:
            import pytest as _pytest

            _pytest.fail(
                f"blast_radius() raised {type(exc).__name__} on a dangling edge: {exc}. "
                "_walk_upstream must guard for fetchone() returning None."
            )

        # May return 0 or 1 result depending on what survives the deleted symbol lookup
        assert isinstance(results, list)
