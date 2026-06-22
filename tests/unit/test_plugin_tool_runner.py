"""RED tests — GitleaksPlugin + TrivyPlugin routed through ToolRunnerPort.

These tests verify the ToolRunnerPort migration contract for #164.
They FAIL until the production plugins accept a `tool_runner` kwarg in
their constructors and delegate external calls through it.

# tested-by: tests/unit/test_plugin_tool_runner.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from caliper.core.tool_runner import ToolInvocation, ToolResult
from caliper.plugins.gitleaks import GitleaksPlugin
from caliper.plugins.trivy import TrivyPlugin

# ---------------------------------------------------------------------------
# Fake ToolRunner — satisfies ToolRunnerPort structurally, never spawns real
# processes.
# ---------------------------------------------------------------------------

_GITLEAKS_CLEAN_OUTPUT = "[]"

_GITLEAKS_LEAK_OUTPUT = json.dumps(
    [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "config/settings.py",
            "StartLine": 42,
            "Entropy": 4.8,
            "Fingerprint": "abc123def456",
        }
    ]
)

_TRIVY_CLEAN_OUTPUT = json.dumps({"SchemaVersion": 2, "Results": []})

_TRIVY_VULN_OUTPUT = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-99999",
                        "PkgName": "cryptography",
                        "InstalledVersion": "3.4.6",
                        "FixedVersion": "41.0.0",
                        "Severity": "HIGH",
                        "Title": "Key extraction flaw",
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
                    }
                ],
            }
        ],
    }
)


class FakeToolRunner:
    """Deterministic test double that satisfies ToolRunnerPort structurally."""

    def __init__(self, result: ToolResult) -> None:
        self._result = result
        self.calls: list[ToolInvocation] = []

    def run(self, invocation: ToolInvocation) -> ToolResult:
        self.calls.append(invocation)
        return self._result


# ---------------------------------------------------------------------------
# Helper factories for common ToolResult shapes
# ---------------------------------------------------------------------------


def _ok(stdout: str, exit_code: int = 0) -> ToolResult:
    return ToolResult(exit_code=exit_code, stdout=stdout, stderr="")


def _not_installed() -> ToolResult:
    return ToolResult(exit_code=-1, stdout="", stderr="", not_installed=True)


def _timed_out() -> ToolResult:
    return ToolResult(exit_code=-1, stdout="", stderr="", timed_out=True)


# ---------------------------------------------------------------------------
# GitleaksPlugin — ToolRunnerPort contract
# ---------------------------------------------------------------------------


class TestGitleaksPluginToolRunner:
    """GitleaksPlugin must route through ToolRunnerPort when one is supplied."""

    def test_gitleaks_accepts_tool_runner_kwarg(self) -> None:
        """GitleaksPlugin.__init__ must accept an optional tool_runner parameter.

        FAILS until GitleaksPlugin gains a tool_runner kwarg.
        """
        fake = FakeToolRunner(_ok(_GITLEAKS_CLEAN_OUTPUT))
        plugin = GitleaksPlugin(tool_runner=fake)  # TypeError today
        assert plugin is not None

    def test_gitleaks_delegates_to_tool_runner_not_subprocess(self, tmp_path: Path) -> None:
        """When tool_runner is provided, the plugin calls runner.run() — not subprocess.

        FAILS because the plugin still calls subprocess.run directly.
        """
        fake = FakeToolRunner(_ok(_GITLEAKS_CLEAN_OUTPUT))
        plugin = GitleaksPlugin(tool_runner=fake)

        plugin.run([], tmp_path)

        assert len(fake.calls) == 1, "Expected exactly one ToolInvocation via the fake runner"

    def test_gitleaks_clean_scan_via_tool_runner(self, tmp_path: Path) -> None:
        """Clean scan (no leaks) via ToolRunner produces a PluginResult with zero findings.

        FAILS because the plugin doesn't accept tool_runner yet.
        """
        fake = FakeToolRunner(_ok(_GITLEAKS_CLEAN_OUTPUT))
        plugin = GitleaksPlugin(tool_runner=fake)

        result = plugin.run([], tmp_path)

        assert result.error == ""
        assert result.findings == []
        assert result.summary.get("leaks") == 0

    def test_gitleaks_findings_via_tool_runner(self, tmp_path: Path) -> None:
        """A leak in the report file is surfaced as a finding via ToolRunner."""
        report = tmp_path / "gl-report.json"
        report.write_text(_GITLEAKS_LEAK_OUTPUT)
        fake = FakeToolRunner(_ok("", exit_code=1))
        plugin = GitleaksPlugin(tool_runner=fake)

        with patch("tempfile.mktemp", return_value=str(report)):
            result = plugin.run([], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 1
        assert result.findings[0]["rule"] == "generic-api-key"
        assert result.findings[0]["file"] == "config/settings.py"

    def test_gitleaks_handles_not_installed_via_tool_runner(self, tmp_path: Path) -> None:
        """ToolResult.not_installed=True must produce a PluginResult with NOT_INSTALLED error.

        FAILS because the plugin doesn't route through ToolRunnerPort.
        """
        fake = FakeToolRunner(_not_installed())
        plugin = GitleaksPlugin(tool_runner=fake)

        result = plugin.run([], tmp_path)

        assert result.error != ""
        assert "NOT_INSTALLED" in result.error

    def test_gitleaks_handles_timed_out_via_tool_runner(self, tmp_path: Path) -> None:
        """ToolResult.timed_out=True must produce a PluginResult with TIMEOUT error.

        FAILS because the plugin doesn't route through ToolRunnerPort.
        """
        fake = FakeToolRunner(_timed_out())
        plugin = GitleaksPlugin(tool_runner=fake)

        result = plugin.run([], tmp_path)

        assert result.error != ""
        assert "TIMEOUT" in result.error


# ---------------------------------------------------------------------------
# TrivyPlugin — ToolRunnerPort contract
# ---------------------------------------------------------------------------


class TestTrivyPluginToolRunner:
    """TrivyPlugin must route through ToolRunnerPort when one is supplied."""

    def test_trivy_accepts_tool_runner_kwarg(self) -> None:
        """TrivyPlugin.__init__ must accept an optional tool_runner parameter.

        FAILS until TrivyPlugin gains a tool_runner kwarg.
        """
        fake = FakeToolRunner(_ok(_TRIVY_CLEAN_OUTPUT))
        plugin = TrivyPlugin(tool_runner=fake)  # TypeError today
        assert plugin is not None

    def test_trivy_delegates_to_tool_runner_not_subprocess(self, tmp_path: Path) -> None:
        """When tool_runner is provided, the plugin calls runner.run() — not subprocess.

        FAILS because the plugin still calls subprocess.run directly.
        """
        fake = FakeToolRunner(_ok(_TRIVY_CLEAN_OUTPUT))
        plugin = TrivyPlugin(tool_runner=fake)

        plugin.run([], tmp_path)

        assert len(fake.calls) == 1, "Expected exactly one ToolInvocation via the fake runner"

    def test_trivy_clean_scan_via_tool_runner(self, tmp_path: Path) -> None:
        """Clean scan (no vulns) via ToolRunner produces a PluginResult with zero findings.

        FAILS because the plugin doesn't accept tool_runner yet.
        """
        fake = FakeToolRunner(_ok(_TRIVY_CLEAN_OUTPUT))
        plugin = TrivyPlugin(tool_runner=fake)

        result = plugin.run([], tmp_path)

        assert result.error == ""
        assert result.findings == []

    def test_trivy_findings_via_tool_runner(self, tmp_path: Path) -> None:
        """Vulnerabilities in stdout are surfaced as findings when routed through ToolRunner.

        FAILS because the plugin doesn't accept tool_runner yet.
        """
        fake = FakeToolRunner(_ok(_TRIVY_VULN_OUTPUT, exit_code=0))
        plugin = TrivyPlugin(tool_runner=fake)

        result = plugin.run([], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding["id"] == "CVE-2024-99999"
        assert finding["severity"] == "high"

    def test_trivy_handles_not_installed_via_tool_runner(self, tmp_path: Path) -> None:
        """ToolResult.not_installed=True must produce a PluginResult with NOT_INSTALLED error.

        FAILS because the plugin doesn't route through ToolRunnerPort.
        """
        fake = FakeToolRunner(_not_installed())
        plugin = TrivyPlugin(tool_runner=fake)

        result = plugin.run([], tmp_path)

        assert result.error != ""
        assert "NOT_INSTALLED" in result.error

    def test_trivy_handles_timed_out_via_tool_runner(self, tmp_path: Path) -> None:
        """ToolResult.timed_out=True must produce a PluginResult with TIMEOUT error.

        FAILS because the plugin doesn't route through ToolRunnerPort.
        """
        fake = FakeToolRunner(_timed_out())
        plugin = TrivyPlugin(tool_runner=fake)

        result = plugin.run([], tmp_path)

        assert result.error != ""
        assert "TIMEOUT" in result.error
