"""Tests for CspellPlugin — JSON reporter and stderr suppression.
# tested-by: tests/unit/test_cspell_plugin.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from caliper.core.plugin import PluginCategory, PluginResult
from caliper.plugins.cspell import CspellPlugin


class TestCspellPluginBasics:
    def test_name_and_category(self):
        p = CspellPlugin()
        assert p.name == "cspell"
        assert p.category == PluginCategory.quality

    def test_can_run_with_files(self):
        p = CspellPlugin()
        assert p.can_run(["app.py"], Path(".")) is True

    def test_can_run_empty_files(self):
        p = CspellPlugin()
        assert p.can_run([], Path(".")) is False

    @patch(
        "caliper.plugins.cspell.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found_returns_error(self, _mock):
        p = CspellPlugin()
        result = p.run(["app.py"], Path("."))
        assert "not installed" in result.error

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_clean_output_no_findings(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        result = p.run(["app.py"], Path("."))
        assert result.error == ""
        assert result.findings == []

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_misspelling_produces_finding(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = (
            "src/app.py:10:5 - Unknown word (coontainer) Suggestions: [container]"
        )
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        result = p.run(["src/app.py"], Path("."))
        assert len(result.findings) == 1
        assert result.findings[0]["word"] == "coontainer"

    def test_render_clean(self):
        p = CspellPlugin()
        result = PluginResult(plugin_name="cspell", findings=[])
        assert p.render(result) == ""

    def test_render_error(self):
        p = CspellPlugin()
        result = PluginResult(plugin_name="cspell", error="not installed")
        md = p.render(result)
        assert "not installed" in md


class TestCspellStderrSuppression:
    """--no-progress and --no-summary keep stderr quiet so stdout JSON stays parseable."""

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_command_includes_no_progress(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        assert "--no-progress" in cmd

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_command_includes_no_summary(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        assert "--no-summary" in cmd

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_command_uses_json_reporter(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        assert "--reporter" in cmd
        idx = cmd.index("--reporter")
        assert cmd[idx + 1] == "@cspell/cspell-json-reporter"

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_runs_from_repo_path_cwd(self, mock_run):
        """cspell must run from repo_path so relative file paths resolve."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["/workspace/app.py"], Path("/workspace"))
        kwargs = mock_run.call_args[1]
        assert kwargs.get("cwd") == Path("/workspace")

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_file_paths_made_relative_to_repo(self, mock_run):
        """Absolute file paths must be converted to relative for cspell."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["/workspace/src/app.py", "/workspace/lib/util.py"], Path("/workspace"))
        cmd = mock_run.call_args[0][0]
        assert "src/app.py" in cmd
        assert "lib/util.py" in cmd
        assert "/workspace/src/app.py" not in cmd

    @patch("caliper.plugins.cspell.subprocess.run")
    def test_command_includes_gitignore_flag(self, mock_run):
        """--gitignore must be passed so cspell skips node_modules and other ignored paths."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = CspellPlugin()
        p.run(["app.py"], Path("."))
        cmd = mock_run.call_args[0][0]
        assert "--gitignore" in cmd
