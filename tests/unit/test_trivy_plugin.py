"""Tests for TrivyPlugin (src/caliper/plugins/trivy.py).
# tested-by: tests/unit/test_trivy_plugin.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.tool_runner import ToolResult
from caliper.plugins.trivy import TrivyPlugin

_TRIVY_OUTPUT = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "MEDIUM",
                        "Title": "Proxy-Auth header leak",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-32681",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-00001",
                        "PkgName": "urllib3",
                        "InstalledVersion": "1.26.0",
                        "FixedVersion": "",
                        "Severity": "HIGH",
                        "Title": "No fix available",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-00001",
                    },
                ],
            }
        ],
    }
)

_TRIVY_OUTPUT_MISSING_FIXED = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-00001",
                        "PkgName": "flask",
                        "InstalledVersion": "2.0.0",
                        # FixedVersion key absent entirely
                        "Severity": "CRITICAL",
                        "Title": "RCE in flask",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2025-00001",
                    },
                ],
            }
        ],
    }
)


class TestTrivyPluginFixedVersion:
    """TrivyPlugin findings must include fixed_version from FixedVersion field."""

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_finding_includes_fixed_version_field(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout=_TRIVY_OUTPUT, stderr="", returncode=0)
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        assert all("fixed_version" in f for f in result.findings)

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_fixed_version_populated_when_present(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout=_TRIVY_OUTPUT, stderr="", returncode=0)
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        finding = next(f for f in result.findings if f["id"] == "CVE-2023-32681")
        assert finding["fixed_version"] == "2.31.0"

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_fixed_version_empty_string_when_no_fix_available(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout=_TRIVY_OUTPUT, stderr="", returncode=0)
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        finding = next(f for f in result.findings if f["id"] == "CVE-2024-00001")
        assert finding["fixed_version"] == ""

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_fixed_version_empty_string_when_key_absent_in_trivy_output(
        self, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout=_TRIVY_OUTPUT_MISSING_FIXED, stderr="", returncode=0
        )
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        finding = result.findings[0]
        assert "fixed_version" in finding
        assert finding["fixed_version"] == ""


class TestTrivySkipDirs:
    """Trivy must pass --skip-dirs for .caliperignore patterns."""

    def test_caliperignore_dirs_become_skip_dirs(self):
        import caliper.plugins.trivy as trivy_mod

        mock_ignore = MagicMock(return_value=[".git/", "tests/e2e/fixtures/", "node_modules/"])
        with patch.object(trivy_mod, "load_ignore_patterns", mock_ignore):
            runner = MagicMock()
            runner.run.return_value = ToolResult(exit_code=0, stdout="{}", stderr="")
            plugin = TrivyPlugin(tool_runner=runner)
            plugin.run([], Path("/workspace"))
        cmd = runner.run.call_args[0][0].cmd
        assert "--skip-dirs" in cmd
        skip_idx = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        skip_vals = [cmd[i + 1] for i in skip_idx]
        assert "tests/e2e/fixtures" in skip_vals
        assert ".git" in skip_vals

    def test_glob_patterns_excluded_from_skip_dirs(self):
        import caliper.plugins.trivy as trivy_mod

        mock_ignore = MagicMock(return_value=["*.egg-info/", "tests/e2e/fixtures/"])
        with patch.object(trivy_mod, "load_ignore_patterns", mock_ignore):
            runner = MagicMock()
            runner.run.return_value = ToolResult(exit_code=0, stdout="{}", stderr="")
            plugin = TrivyPlugin(tool_runner=runner)
            plugin.run([], Path("/workspace"))
        cmd = runner.run.call_args[0][0].cmd
        skip_idx = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        skip_vals = [cmd[i + 1] for i in skip_idx]
        assert "*.egg-info" not in skip_vals
        assert "tests/e2e/fixtures" in skip_vals


class TestTrivyPluginExitCode:
    """TrivyPlugin must surface tool failures via exit_code, not just not_installed/timed_out."""

    def test_nonzero_exit_no_stdout_returns_binary_crashed_error(self) -> None:
        """exit_code=2, no stdout → BINARY_CRASHED error (total failure, no partial output)."""
        runner = MagicMock()
        runner.run.return_value = ToolResult(
            exit_code=2, stdout="", stderr="fatal error from trivy"
        )
        plugin = TrivyPlugin(tool_runner=runner)

        result = plugin.run([], Path("/project"))

        assert "BINARY_CRASHED" in result.error

    def test_nonzero_exit_with_stdout_proceeds_with_findings(self) -> None:
        """exit_code=1, stdout present → warn and surface findings (scanner uses non-zero for hits)."""
        runner = MagicMock()
        runner.run.return_value = ToolResult(exit_code=1, stdout=_TRIVY_OUTPUT, stderr="")
        plugin = TrivyPlugin(tool_runner=runner)

        result = plugin.run([], Path("/project"))

        assert result.error == ""
        assert len(result.findings) == 2
