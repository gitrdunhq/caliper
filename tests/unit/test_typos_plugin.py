"""Tests for TyposPlugin — newline-delimited JSON parsing and fail-open guards.
# tested-by: tests/unit/test_typos_plugin.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from caliper.core.plugin import PluginCategory
from caliper.plugins.typos import TyposPlugin


def _typo_line(path: str, line_num: int, typo: str, *corrections: str) -> str:
    import json

    return json.dumps(
        {
            "type": "typo",
            "path": path,
            "line_num": line_num,
            "byte_offset": 0,
            "typo": typo,
            "corrections": list(corrections),
        }
    )


class TestTyposPluginBasics:
    def test_name_and_category(self):
        p = TyposPlugin()
        assert p.name == "typos"
        assert p.category == PluginCategory.quality

    def test_can_run_with_files(self):
        assert TyposPlugin().can_run(["app.py"], Path(".")) is True

    def test_can_run_empty_files(self):
        assert TyposPlugin().can_run([], Path(".")) is False

    @patch(
        "caliper.plugins.typos.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found_returns_error(self, _mock):
        result = TyposPlugin().run(["app.py"], Path("."))
        assert "not installed" in result.error

    @patch("caliper.plugins.typos.subprocess.run")
    def test_clean_output_no_findings(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        result = TyposPlugin().run(["app.py"], Path("."))
        assert result.error == ""
        assert result.findings == []

    @patch("caliper.plugins.typos.subprocess.run")
    def test_typo_produces_finding(self, mock_run):
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = _typo_line("./src/app.py", 10, "coontainer", "container")
        mock_run.return_value.stderr = ""
        result = TyposPlugin().run(["src/app.py"], Path("."))
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f["word"] == "coontainer"
        assert f["line"] == 10
        assert f["file"] == "src/app.py"  # leading ./ stripped
        assert f["suggestions"] == "container"
        assert f["severity"] == "info"

    @patch("caliper.plugins.typos.subprocess.run")
    def test_multiple_typos_and_multiple_corrections(self, mock_run):
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = "\n".join(
            [
                _typo_line("a.py", 1, "fo", "of", "for", "do"),
                _typo_line("b.py", 5, "teh", "the"),
            ]
        )
        mock_run.return_value.stderr = ""
        result = TyposPlugin().run(["a.py", "b.py"], Path("."))
        assert len(result.findings) == 2
        assert result.findings[0]["suggestions"] == "of, for, do"
        assert result.summary["total"] == 2

    @patch("caliper.plugins.typos.subprocess.run")
    def test_non_typo_json_lines_ignored(self, mock_run):
        # typos emits other object types (errors, binary-file notices) — skip them.
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = "\n".join(
            [
                '{"type":"binary_file","path":"./logo.png"}',
                _typo_line("real.py", 3, "wrod", "word"),
                '{"type":"error","message":"oops"}',
            ]
        )
        mock_run.return_value.stderr = ""
        result = TyposPlugin().run(["real.py"], Path("."))
        assert len(result.findings) == 1
        assert result.findings[0]["word"] == "wrod"

    @patch("caliper.plugins.typos.subprocess.run")
    def test_malformed_json_lines_are_suppressed(self, mock_run):
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = "not json at all\n" + _typo_line("x.py", 1, "wrod", "word")
        mock_run.return_value.stderr = ""
        result = TyposPlugin().run(["x.py"], Path("."))
        # fail-open: bad line skipped, good line still parsed
        assert len(result.findings) == 1


class TestTyposRender:
    def test_render_clean_returns_empty(self):
        from caliper.core.plugin import PluginResult

        out = TyposPlugin().render(PluginResult(plugin_name="typos", findings=[]))
        assert out == ""

    def test_render_error(self):
        from caliper.core.plugin import PluginResult

        out = TyposPlugin().render(PluginResult(plugin_name="typos", error="typos not installed"))
        assert "typos" in out and "not installed" in out

    def test_render_findings_table(self):
        from caliper.core.plugin import PluginResult

        result = PluginResult(
            plugin_name="typos",
            findings=[
                {
                    "file": "a.py",
                    "line": 2,
                    "severity": "info",
                    "word": "wrod",
                    "suggestions": "word",
                }
            ],
        )
        out = TyposPlugin().render(result)
        assert "Typos (1)" in out
        assert "`wrod`" in out
        assert "word" in out
