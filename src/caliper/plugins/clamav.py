"""ClamAV plugin — malware/virus scanning on changed files.
# tested-by: tests/unit/test_clamav_plugin.py

Wraps clamscan CLI. Exit 0 = clean, 1 = infected, 2 = error.
Parses text output — clamscan has no JSON mode.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import structlog

from caliper.core.errors import ErrorCode, error_msg
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin

logger = structlog.get_logger(__name__)

_FOUND_RE = re.compile(r"^(.+?):\s+(.+?)\s+FOUND\s*$")
_SUMMARY_RE = re.compile(r"Infected files:\s+(\d+)")


class ClamAvPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "clamav"

    @property
    def description(self) -> str:
        return "Malware/virus scanning (ClamAV)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.supply_chain

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(
        self,
        files: list[str],
        repo_path: Path,
        timeout: int = 120,
    ) -> PluginResult:
        try:
            r = subprocess.run(
                [
                    "clamscan",
                    "--recursive",
                    "--no-summary",
                    "--infected",
                    str(repo_path),
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "clamscan"),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "clamav", timeout=0),
            )

        output = r.stdout or ""
        stderr = r.stderr or ""

        if r.returncode == 2:
            stderr_detail = stderr.strip()
            base_error = error_msg(ErrorCode.BINARY_CRASHED, "clamscan", exit_code=2)
            full_error = f"{base_error}: {stderr_detail}" if stderr_detail else base_error
            return PluginResult(
                plugin_name=self.name,
                error=full_error,
            )

        findings = self._parse_output(output + stderr)

        full_output = r.stdout or ""
        summary_match = _SUMMARY_RE.search(full_output + stderr)
        infected_count = int(summary_match.group(1)) if summary_match else len(findings)

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={
                "infected": infected_count,
                "scanned": len(files),
            },
        )

    @staticmethod
    def _parse_output(output: str) -> list[dict]:
        findings = []
        for line in output.strip().split("\n"):
            m = _FOUND_RE.match(line.strip())
            if m:
                findings.append(
                    {
                        "file": m.group(1),
                        "signature": m.group(2),
                        "severity": "critical",
                        "category": "malware",
                    }
                )
        return findings

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        if result.error:
            return f"**clamav**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>🦠 <b>Malware Detection ({len(result.findings)})</b></summary>\n")
        lines.append("| File | Signature | Severity |")
        lines.append("|------|-----------|----------|")
        for f in result.findings:
            lines.append(f"| `{f['file']}` | `{f['signature']}` | 🔴 {f['severity']} |")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("clamav")
def build_clamav_plugin() -> ClamAvPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return ClamAvPlugin()
