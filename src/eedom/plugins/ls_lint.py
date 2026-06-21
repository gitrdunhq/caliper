"""ls-lint plugin — file naming convention linter.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin


class LsLintPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "ls-lint"

    @property
    def description(self) -> str:
        return "File naming convention linter"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return (repo_path / ".ls-lint.yml").exists()

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            r = subprocess.run(
                ["ls-lint"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(repo_path),
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "ls-lint"),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.TIMEOUT, "ls-lint", timeout=0)
            )

        output = r.stderr or r.stdout or ""
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("ls-lint"):
                continue
            findings.append(
                {
                    "file": line,
                    "message": "naming convention violation",
                }
            )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        if result.error:
            return f"**ls-lint**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(
            f"<summary>📁 <b>Naming Conventions" f" ({len(result.findings)})</b></summary>\n"
        )
        for n in result.findings[:20]:
            lines.append(f"- `{n['file']}` — {n['message']}")
        if len(result.findings) > 20:
            lines.append(f"- *...{len(result.findings) - 20} more*")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("ls-lint")
def build_ls_lint_plugin() -> LsLintPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return LsLintPlugin()
