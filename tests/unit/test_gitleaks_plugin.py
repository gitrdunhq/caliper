"""Tests for gitleaks plugin.
# tested-by: tests/unit/test_gitleaks_plugin.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.plugin import PluginCategory
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolResult
from caliper.plugins.gitleaks import GitleaksPlugin

LEAK_OUTPUT = json.dumps(
    [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "StartLine": 5,
            "EndLine": 5,
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIA****EXAMPLE",
            "File": "config.py",
            "Entropy": 3.5,
            "Fingerprint": "abc123:config.py:aws-access-token:5",
        },
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "StartLine": 12,
            "EndLine": 12,
            "Match": "api_key = 'sk-prod-abc123'",
            "Secret": "sk-prod-****",
            "File": "src/app.py",
            "Entropy": 4.2,
            "Fingerprint": "def456:src/app.py:generic-api-key:12",
        },
    ]
)

CLEAN_OUTPUT = "[]"


class TestGitleaksPlugin:
    def test_name_and_category(self):
        p = GitleaksPlugin()
        assert p.name == "gitleaks"
        assert p.category == PluginCategory.supply_chain

    def test_can_run_always(self):
        p = GitleaksPlugin()
        assert p.can_run(["app.py"], Path(".")) is True

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_clean_scan(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = CLEAN_OUTPUT
        p = GitleaksPlugin()
        result = p.run(["app.py"], Path("/workspace"))
        assert result.error == ""
        assert len(result.findings) == 0

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_detects_leaks(self, mock_run, tmp_path):
        report = tmp_path / "gl.json"
        report.write_text(LEAK_OUTPUT)
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        with patch("tempfile.mktemp", return_value=str(report)):
            p = GitleaksPlugin()
            result = p.run(["config.py"], Path("/workspace"))
        assert len(result.findings) == 2
        assert result.findings[0]["rule"] == "aws-access-token"
        assert result.findings[0]["file"] == "config.py"
        assert result.findings[0]["severity"] == "critical"
        assert result.summary["leaks"] == 2

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_secrets_not_in_findings(self, mock_run, tmp_path):
        report = tmp_path / "gl.json"
        report.write_text(LEAK_OUTPUT)
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        with patch("tempfile.mktemp", return_value=str(report)):
            p = GitleaksPlugin()
            result = p.run(["config.py"], Path("/workspace"))
        for f in result.findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in str(f)
            assert "sk-prod-abc123" not in str(f)

    @patch(
        "caliper.core.subprocess_runner.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found(self, _mock):
        p = GitleaksPlugin()
        result = p.run(["app.py"], Path("."))
        assert "NOT_INSTALLED" in result.error

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_render_leaks(self, mock_run, tmp_path):
        report = tmp_path / "gl.json"
        report.write_text(LEAK_OUTPUT)
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        with patch("tempfile.mktemp", return_value=str(report)):
            p = GitleaksPlugin()
            result = p.run(["config.py"], Path("/workspace"))
        md = p.render(result)
        assert "Secrets" in md
        assert "aws-access-token" in md
        assert "config.py" in md
        assert "AKIAIOSFODNN7EXAMPLE" not in md

    def test_render_clean(self):
        from caliper.core.plugin import PluginResult

        p = GitleaksPlugin()
        result = PluginResult(plugin_name="gitleaks")
        assert p.render(result) == ""

    def test_render_error(self):
        from caliper.core.plugin import PluginResult

        p = GitleaksPlugin()
        result = PluginResult(plugin_name="gitleaks", error="not installed")
        assert "not installed" in p.render(result)

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_custom_config_passed_when_present(self, mock_run, tmp_path):
        config_dir = tmp_path / ".caliper"
        config_dir.mkdir()
        config_file = config_dir / "gitleaks.toml"
        config_file.write_text('title = "custom"\n')

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = CLEAN_OUTPUT

        p = GitleaksPlugin()
        p.run(["app.py"], tmp_path)

        cmd = mock_run.call_args[0][0]
        assert "--config" in cmd
        assert str(config_file) in cmd

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_no_config_flag_when_absent(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = CLEAN_OUTPUT

        p = GitleaksPlugin()
        p.run(["app.py"], Path("/nonexistent"))

        cmd = mock_run.call_args[0][0]
        assert "--config" not in cmd


class TestGitleaksFileHandleLeak:
    """File handle must be cleaned up even when exceptions occur mid-run."""

    def test_unlink_called_when_read_text_raises_oserror(self, tmp_path):
        """unlink(missing_ok=True) is called even when read_text raises OSError."""
        mock_runner = MagicMock(spec=SubprocessToolRunner)
        mock_runner.run.return_value = MagicMock(not_installed=False, timed_out=False)
        plugin = GitleaksPlugin(tool_runner=mock_runner)

        with patch("tempfile.mktemp", return_value="/fake/gitleaks-leak-test.json"):
            with patch.object(Path, "exists", return_value=True):
                with patch.object(Path, "read_text", side_effect=OSError("disk error")):
                    with patch.object(Path, "unlink") as mock_unlink:
                        try:
                            plugin.run([], tmp_path)
                        except OSError:
                            pass  # exception may propagate — that's fine

        assert mock_unlink.called, "unlink must be called even when read_text raises OSError"
        assert any(
            c[1].get("missing_ok") is True for c in mock_unlink.call_args_list
        ), "unlink must be called with missing_ok=True"

    def test_unlink_always_called_on_successful_run(self, tmp_path):
        """Temp file is cleaned up on a normal successful run."""
        mock_runner = MagicMock(spec=SubprocessToolRunner)
        mock_runner.run.return_value = MagicMock(not_installed=False, timed_out=False)
        plugin = GitleaksPlugin(tool_runner=mock_runner)

        report_json = json.dumps([])

        with patch("tempfile.mktemp", return_value="/fake/gitleaks-ok-test.json"):
            with patch.object(Path, "exists", return_value=True):
                with patch.object(Path, "read_text", return_value=report_json):
                    with patch.object(Path, "unlink") as mock_unlink:
                        plugin.run([], tmp_path)

        assert mock_unlink.called, "unlink must be called on a clean (no-leak) run"
        assert any(
            c[1].get("missing_ok") is True for c in mock_unlink.call_args_list
        ), "unlink must be called with missing_ok=True"


class TestGitleaksPluginExitCode:
    """GitleaksPlugin must distinguish expected exit codes from actual crashes."""

    def test_unexpected_exit_code_no_report_returns_error(self, tmp_path) -> None:
        """exit_code=2 with no report written → BINARY_CRASHED (total failure)."""
        runner = MagicMock()
        runner.run.return_value = ToolResult(exit_code=2, stdout="", stderr="fatal crash")
        plugin = GitleaksPlugin(tool_runner=runner)

        nonexistent = str(tmp_path / "no-report.json")
        with patch("tempfile.mktemp", return_value=nonexistent):
            result = plugin.run([], tmp_path)

        assert "BINARY_CRASHED" in result.error

    def test_exit_code_one_with_report_proceeds_normally(self, tmp_path) -> None:
        """exit_code=1 is normal gitleaks behaviour (leaks found) — must not return error."""
        report = tmp_path / "gl.json"
        report.write_text(LEAK_OUTPUT)
        runner = MagicMock()
        runner.run.return_value = ToolResult(exit_code=1, stdout="", stderr="")
        plugin = GitleaksPlugin(tool_runner=runner)

        with patch("tempfile.mktemp", return_value=str(report)):
            result = plugin.run([], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 2

    def test_unexpected_exit_code_with_report_proceeds_with_warning(self, tmp_path) -> None:
        """exit_code=2 but gitleaks still wrote a report — warn and surface findings."""
        report = tmp_path / "gl.json"
        report.write_text(LEAK_OUTPUT)
        runner = MagicMock()
        runner.run.return_value = ToolResult(exit_code=2, stdout="", stderr="")
        plugin = GitleaksPlugin(tool_runner=runner)

        with patch("tempfile.mktemp", return_value=str(report)):
            result = plugin.run([], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 2
