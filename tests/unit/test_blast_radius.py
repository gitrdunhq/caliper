"""Tests for blast radius plugin and code graph.
# tested-by: tests/unit/test_blast_radius.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from caliper.plugins._runners.graph_builder import CodeGraph
from caliper.plugins.blast_radius import BlastRadiusPlugin

SAMPLE_PYTHON = textwrap.dedent("""\
    import os
    from pathlib import Path

    class BaseScanner:
        def scan(self):
            pass

    class OsvScanner(BaseScanner):
        def scan(self):
            result = self._fetch()
            return self._parse(result)

        def _fetch(self):
            return {}

        def _parse(self, data):
            return []

    def run_pipeline(repo_path):
        scanner = OsvScanner()
        result = scanner.scan()
        normalize(result)
        return result

    def normalize(findings):
        return sorted(findings)

    def main():
        run_pipeline("/workspace")
""")


class TestCodeGraph:
    def test_index_python_finds_functions(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        stats = g.stats()
        assert stats["symbols"] > 0
        funcs = g.conn.execute("SELECT name FROM symbols WHERE kind = 'function'").fetchall()
        names = {r["name"] for r in funcs}
        assert "run_pipeline" in names
        assert "normalize" in names
        assert "main" in names

    def test_index_python_finds_classes(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        classes = g.conn.execute("SELECT name FROM symbols WHERE kind = 'class'").fetchall()
        names = {r["name"] for r in classes}
        assert "BaseScanner" in names
        assert "OsvScanner" in names

    def test_index_python_finds_calls(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        edges = g.conn.execute(
            "SELECT s.name as src, t.name as tgt"
            " FROM edges e"
            " JOIN symbols s ON e.source_id = s.id"
            " JOIN symbols t ON e.target_id = t.id"
            " WHERE e.kind = 'calls'"
        ).fetchall()
        pairs = {(r["src"], r["tgt"]) for r in edges}
        assert ("run_pipeline", "normalize") in pairs

    def test_index_python_finds_inheritance(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        edges = g.conn.execute(
            "SELECT s.name as src, t.name as tgt"
            " FROM edges e"
            " JOIN symbols s ON e.source_id = s.id"
            " JOIN symbols t ON e.target_id = t.id"
            " WHERE e.kind = 'inherits'"
        ).fetchall()
        pairs = {(r["src"], r["tgt"]) for r in edges}
        assert ("OsvScanner", "BaseScanner") in pairs

    def test_blast_radius_finds_callers(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        radius = g.blast_radius("normalize", max_depth=2)
        names = {r["name"] for r in radius}
        assert "run_pipeline" in names

    def test_blast_radius_depth_labels(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        radius = g.blast_radius("normalize", max_depth=3)
        by_name = {r["name"]: r for r in radius}
        if "run_pipeline" in by_name:
            assert by_name["run_pipeline"]["risk"] == "WILL_BREAK"

    def test_run_checks_on_changed_files(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        findings = g.run_checks(["scanner.py"])
        assert isinstance(findings, list)

    def test_register_custom_check(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        g.register_check(
            name="too_many_functions",
            query="""
                SELECT file, COUNT(*) as func_count
                FROM symbols
                WHERE kind = 'function' AND file IN ({changed_files})
                GROUP BY file
                HAVING func_count > 3
            """,
            severity="medium",
            description="File has too many functions",
        )
        findings = g.run_checks(["scanner.py"])
        check_names = {f["check"] for f in findings}
        assert "too_many_functions" in check_names

    def test_builtin_checks_registered(self):
        g = CodeGraph()
        checks = g.conn.execute("SELECT name FROM checks").fetchall()
        names = {r["name"] for r in checks}
        assert "blast_radius_high" in names
        assert "circular_dependency" in names
        assert "orphan_symbol" in names
        assert "high_fan_out" in names

    def test_stats(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        g.conn.commit()
        s = g.stats()
        assert s["symbols"] > 5
        assert s["files"] >= 1
        assert s["checks"] >= 5

    def test_index_javascript(self):
        js_code = textwrap.dedent("""\
            import { Router } from 'express';
            const handler = async (req, res) => {
                const data = fetchData(req.params.id);
                res.json(data);
            };
            class UserController extends BaseController {
                getUser() { return {}; }
            }
        """)
        g = CodeGraph()
        g.index_file("handler.ts", js_code)
        g.conn.commit()
        stats = g.stats()
        assert stats["symbols"] > 0
        classes = g.conn.execute("SELECT name FROM symbols WHERE kind = 'class'").fetchall()
        assert any(r["name"] == "UserController" for r in classes)

    def test_empty_changed_files_returns_empty(self):
        g = CodeGraph()
        assert g.run_checks([]) == []

    def test_blast_radius_unknown_symbol_returns_empty(self):
        g = CodeGraph()
        assert g.blast_radius("nonexistent") == []

    def test_classifies_pass_only(self):
        g = CodeGraph()
        g.index_file("t.py", "def noop():\n    pass\n")
        g.conn.commit()
        row = g.conn.execute("SELECT body_kind FROM symbols WHERE name = 'noop'").fetchone()
        assert row["body_kind"] == "pass_only"

    def test_classifies_return_none(self):
        g = CodeGraph()
        g.index_file("t.py", "def nothing():\n    return None\n")
        g.conn.commit()
        row = g.conn.execute("SELECT body_kind FROM symbols WHERE name = 'nothing'").fetchone()
        assert row["body_kind"] == "return_none"

    def test_classifies_stub_ellipsis(self):
        g = CodeGraph()
        g.index_file("t.py", "def stub():\n    ...\n")
        g.conn.commit()
        row = g.conn.execute("SELECT body_kind FROM symbols WHERE name = 'stub'").fetchone()
        assert row["body_kind"] == "stub"

    def test_classifies_stub_not_implemented(self):
        g = CodeGraph()
        g.index_file("t.py", "def stub():\n    raise NotImplementedError\n")
        g.conn.commit()
        row = g.conn.execute("SELECT body_kind FROM symbols WHERE name = 'stub'").fetchone()
        assert row["body_kind"] == "stub"

    def test_classifies_log_only(self):
        g = CodeGraph()
        g.index_file("t.py", "def logit():\n    print('hi')\n")
        g.conn.commit()
        row = g.conn.execute("SELECT body_kind FROM symbols WHERE name = 'logit'").fetchone()
        assert row["body_kind"] == "log_only"

    def test_classifies_real_function(self):
        g = CodeGraph()
        g.index_file("t.py", "def real(x):\n    return x * 2\n")
        g.conn.commit()
        row = g.conn.execute("SELECT body_kind FROM symbols WHERE name = 'real'").fetchone()
        assert row["body_kind"] == "real"

    def test_noop_check_finds_stubs(self):
        g = CodeGraph()
        g.index_file(
            "app.py",
            textwrap.dedent("""\
            def real_work(x):
                return x * 2 + 1

            def placeholder():
                pass

            def todo():
                raise NotImplementedError

            def log_only():
                print("called")
        """),
        )
        g.conn.commit()
        findings = g.run_checks(["app.py"])
        noop_findings = [f for f in findings if f["check"] == "noop_function"]
        names = {f["name"] for f in noop_findings}
        assert "placeholder" in names
        assert "todo" in names
        assert "log_only" in names
        assert "real_work" not in names

    def test_mock_stub_check_skips_test_files(self):
        g = CodeGraph()
        g.index_file("test_app.py", "def test_stub():\n    pass\n")
        g.index_file("src.py", "def prod_stub():\n    pass\n")
        g.conn.commit()
        findings = g.run_checks(["test_app.py", "src.py"])
        mock_findings = [f for f in findings if f["check"] == "mock_stub_in_source"]
        names = {f["name"] for f in mock_findings}
        assert "prod_stub" in names
        assert "test_stub" not in names

    def test_checks_loaded_from_yaml(self):
        g = CodeGraph()
        checks = g.conn.execute("SELECT name FROM checks").fetchall()
        names = {r["name"] for r in checks}
        assert "noop_function" in names
        assert "mock_stub_in_source" in names
        assert len(names) >= 8


class TestFindingMessages:
    """Issue #390 — every blast-radius finding carries a non-empty message."""

    def _graph_with_findings(self):
        g = CodeGraph()
        g.index_file("scanner.py", SAMPLE_PYTHON)
        # A second module importing scanner-ish things to trigger more checks.
        g.index_file(
            "test_calculator.py",
            textwrap.dedent("""\
                def add(a, b):
                    return a + b

                def test_addition():
                    assert add(1, 2) == 3

                def test_subtraction():
                    assert add(5, -2) == 3
            """),
        )
        g.conn.commit()
        return g

    def test_run_checks_findings_all_have_nonempty_message(self):
        g = self._graph_with_findings()
        findings = g.run_checks(["scanner.py", "test_calculator.py"])
        assert findings, "fixture must trigger at least one finding"
        for f in findings:
            assert f.get("message", "").strip(), f"empty message in finding: {f}"

    def test_custom_check_with_empty_description_still_has_message(self):
        g = self._graph_with_findings()
        g.register_check(
            name="every_function",
            query="SELECT s.name, s.file, s.line FROM symbols s"
            " WHERE s.file IN ({changed_files}) AND s.kind = 'function'",
        )  # description defaults to "" — message must not be empty
        findings = g.run_checks(["scanner.py"])
        custom = [f for f in findings if f["check"] == "every_function"]
        assert custom, "custom check must produce findings"
        for f in custom:
            assert f.get("message", "").strip(), f"empty message in finding: {f}"

    def test_plugin_findings_normalize_to_nonempty_messages(self, tmp_path, monkeypatch):
        """End-to-end: PluginFinding.message is never empty for blast-radius."""
        from caliper.core.registry import _normalize_findings

        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "test_calculator.py").write_text(
            "def add(a, b):\n"
            "    return a + b\n\n"
            "def test_addition():\n"
            "    assert add(1, 2) == 3\n"
        )
        result = BlastRadiusPlugin().run(["test_calculator.py"], repo)
        assert result.error == ""
        findings = _normalize_findings(result.findings)
        assert findings, "fixture must trigger at least one finding (orphan test funcs)"
        for f in findings:
            assert f.message.strip(), f"empty message in finding: {f.to_dict()}"


class TestGraphDbLocation:
    """Issue #391 — the graph db must not pollute the reviewed repo by default."""

    def _make_repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "mod.py").write_text("def hello():\n    return 1\n")
        return repo

    def test_default_db_not_written_into_target_repo(self, tmp_path, monkeypatch):
        """Default graph db lives in the XDG cache dir, not in the reviewed repo."""
        cache = tmp_path / "cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
        monkeypatch.delenv("CALIPER_GRAPH_DB", raising=False)
        repo = self._make_repo(tmp_path)

        result = BlastRadiusPlugin().run(["mod.py"], repo)

        assert result.error == ""
        assert not (repo / ".caliper").exists(), "review must not dirty the target repo"
        dbs = list((cache / "caliper").rglob("code_graph.sqlite"))
        assert len(dbs) == 1, f"expected graph db under XDG cache, found: {dbs}"

    def test_env_var_overrides_db_location(self, tmp_path, monkeypatch):
        """CALIPER_GRAPH_DB points the graph db at an explicit path."""
        custom = tmp_path / "custom" / "graph.sqlite"
        monkeypatch.setenv("CALIPER_GRAPH_DB", str(custom))
        repo = self._make_repo(tmp_path)

        result = BlastRadiusPlugin().run(["mod.py"], repo)

        assert result.error == ""
        assert custom.exists()
        assert not (repo / ".caliper").exists()

    def test_config_graph_db_honored(self, tmp_path, monkeypatch):
        """A repo config that explicitly asks for an in-repo path keeps working."""
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.delenv("CALIPER_GRAPH_DB", raising=False)
        repo = self._make_repo(tmp_path)
        (repo / ".caliper.yaml").write_text(
            "thresholds:\n  blast-radius:\n    graph_db: .caliper/code_graph.sqlite\n"
        )

        result = BlastRadiusPlugin().run(["mod.py"], repo)

        assert result.error == ""
        assert (repo / ".caliper" / "code_graph.sqlite").exists()

    def test_legacy_in_repo_db_is_reused(self, tmp_path, monkeypatch):
        """An existing .caliper/code_graph.sqlite (pre-#391 layout) keeps being used."""
        cache = tmp_path / "cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
        monkeypatch.delenv("CALIPER_GRAPH_DB", raising=False)
        repo = self._make_repo(tmp_path)
        legacy = repo / ".caliper" / "code_graph.sqlite"
        legacy.parent.mkdir()
        g = CodeGraph(db_path=str(legacy))
        g.conn.close()

        result = BlastRadiusPlugin().run(["mod.py"], repo)

        assert result.error == ""
        # Legacy db got the symbols; no second db materialized in the cache.
        g2 = CodeGraph(db_path=str(legacy))
        assert g2.stats()["symbols"] > 0
        g2.conn.close()
        assert list((cache / "caliper").rglob("*.sqlite")) == []


class TestBlastRadiusPluginReadOnly:
    def test_run_falls_back_to_temp_dir_on_read_only_fs(self, tmp_path):
        """blast-radius should not crash when repo_path is read-only."""
        # Write a tiny Python file so can_run returns True.
        src = tmp_path / "mod.py"
        src.write_text("def hello():\n    pass\n")

        plugin = BlastRadiusPlugin()

        # Simulate a read-only workspace: mkdir raises OSError(30, …)
        with patch.object(Path, "mkdir", side_effect=OSError(30, "Read-only file system")):
            result = plugin.run(["mod.py"], tmp_path)

        # Must not surface the OSError as a plugin error
        assert result.error == "", f"Unexpected error: {result.error}"
