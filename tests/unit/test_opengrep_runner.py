"""Tests for opengrep runner — binary name and local-only rules.
# tested-by: tests/unit/test_opengrep_runner.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from eedom.plugins._runners.semgrep_runner import run_semgrep


class TestOpengrepBinaryName:
    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_uses_opengrep_binary(self, mock_run):
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "opengrep"
        assert "semgrep" not in cmd[0]


class TestRegistryAndLocalRules:
    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_includes_default_registry_rulesets(self, mock_run):
        """p/default and p/ci should always be present for max coverage."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert "p/default" in config_values
        assert "p/ci" in config_values

    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_python_file_adds_python_ruleset(self, mock_run):
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert "p/python" in config_values

    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_uses_local_policies_dir(self, mock_run):
        """Should use policies/semgrep/ when it exists."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        repo = str(Path(__file__).resolve().parent.parent.parent)
        run_semgrep(["app.py"], repo)
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert any("policies/semgrep" in v for v in config_values)


class TestExtraConfigDirs:
    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_extra_config_dirs_added(self, mock_run, tmp_path):
        """Extra config dirs from .eagle-eyed-dom.yaml appear as --config args."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        extra = tmp_path / "community-rules"
        extra.mkdir()
        (extra / "rule.yaml").touch()
        run_semgrep(["app.py"], "/workspace", extra_config_dirs=[str(extra)])
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert str(extra) in config_values

    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_extra_config_dir_missing_is_skipped(self, mock_run):
        """Non-existent extra config dirs are silently skipped."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace", extra_config_dirs=["/no/such/dir"])
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert "/no/such/dir" not in config_values


class TestExcludeRules:
    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_exclude_rules_passed_to_cli(self, mock_run):
        """Excluded rule IDs are passed as --exclude-rule flags."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(
            ["app.py"],
            "/workspace",
            exclude_rules=["path-traversal", "unvalidated-path-construction"],
        )
        cmd = mock_run.call_args[0][0]
        exclude_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--exclude-rule"]
        assert "path-traversal" in exclude_values
        assert "unvalidated-path-construction" in exclude_values

    @patch("eedom.plugins._runners.semgrep_runner.subprocess.run")
    def test_no_exclude_rules_by_default(self, mock_run):
        """No --exclude-rule flags when list is empty/None."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        assert "--exclude-rule" not in cmd
