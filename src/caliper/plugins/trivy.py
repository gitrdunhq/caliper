"""Trivy plugin — vulnerability scanning.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

import json
from pathlib import Path

from caliper.core.errors import ErrorCode, error_msg
from caliper.core.ignore import load_ignore_patterns
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

_TIMEOUT = 60


class TrivyPlugin(ScannerPlugin):
    def __init__(self, tool_runner: ToolRunnerPort | None = None) -> None:
        self._runner: ToolRunnerPort = (
            tool_runner if tool_runner is not None else SubprocessToolRunner()
        )

    @property
    def name(self) -> str:
        return "trivy"

    @property
    def description(self) -> str:
        return "Vulnerability scanning (Trivy database)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        cmd = ["trivy", "fs", "--format", "json", "--scanners", "vuln"]
        for pattern in load_ignore_patterns(repo_path):
            stripped = pattern.rstrip("/")
            if stripped and not any(c in stripped for c in "*?["):
                cmd.extend(["--skip-dirs", stripped])
        cmd.append(str(repo_path))
        tool_result = self._runner.run(
            ToolInvocation(cmd=cmd, cwd=str(repo_path), timeout=_TIMEOUT)
        )

        if tool_result.not_installed:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.NOT_INSTALLED, "trivy")
            )
        if tool_result.timed_out:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "trivy", timeout=_TIMEOUT),
            )
        if tool_result.exit_code != 0 and not tool_result.stdout:
            return PluginResult(
                plugin_name=self.name,
                error=(
                    f"[BINARY_CRASHED] trivy exited {tool_result.exit_code}"
                    f": {tool_result.stderr[:200]}"
                ),
            )

        try:
            data = json.loads(tool_result.stdout) if tool_result.stdout else {}
        except json.JSONDecodeError:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.PARSE_ERROR, "trivy")
            )

        findings = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "id": vuln.get("VulnerabilityID", "?"),
                        "url": vuln.get("PrimaryURL", ""),
                        "summary": vuln.get("Title") or vuln.get("Description", "")[:100],
                        "severity": _SEV_MAP.get(vuln.get("Severity", ""), "info"),
                        "package": vuln.get("PkgName", "?"),
                        "version": vuln.get("InstalledVersion", "?"),
                        "fixed_version": vuln.get("FixedVersion", ""),
                    }
                )

        crit = sum(1 for f in findings if f["severity"] in ("critical", "high"))
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings), "critical_high": crit},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**trivy**: {result.error}"
        if not result.findings:
            return ""
        return f"Trivy: {len(result.findings)} vulnerabilities found"


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("trivy")
def build_trivy_plugin() -> TrivyPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return TrivyPlugin()
