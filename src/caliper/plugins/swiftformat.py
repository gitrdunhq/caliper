"""SwiftFormat plugin — Swift code formatting lint.
# tested-by: tests/unit/test_swiftformat.py

Runs `swiftformat --lint` on changed Swift files. Exit 1 means files would
be reformatted. All findings are INFO severity — they are 100% auto-fixable
by running `swiftformat .` in the repo root. The plugin never mutates files.
"""

from __future__ import annotations

import re
from pathlib import Path

import structlog

from caliper.core.errors import ErrorCode, error_msg
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

logger = structlog.get_logger(__name__)

_SWIFT_EXT = ".swift"
# swiftformat --lint writes "path -- would reformat" lines to stderr
_REFORMAT_RE = re.compile(r"^(.+?)\s+--\s+would reformat\s*$")


def _make_relative(file_path: str, repo_path: Path) -> str:
    try:
        return str(Path(file_path).relative_to(repo_path))
    except ValueError:
        return file_path


class SwiftFormatPlugin(ScannerPlugin):
    def __init__(self, tool_runner: ToolRunnerPort | None = None) -> None:
        self._runner: ToolRunnerPort = (
            tool_runner if tool_runner is not None else SubprocessToolRunner()
        )

    @property
    def name(self) -> str:
        return "swiftformat"

    @property
    def description(self) -> str:
        return "Swift code formatting lint — all findings auto-fixable with `swiftformat .`"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix == _SWIFT_EXT for f in files)

    def run(
        self,
        files: list[str],
        repo_path: Path,
        timeout: int = 120,
    ) -> PluginResult:
        swift_files = [f for f in files if Path(f).suffix == _SWIFT_EXT]
        if not swift_files:
            return PluginResult(plugin_name=self.name, skip_reason="no Swift files")

        cmd = ["swiftformat", "--lint", *swift_files]

        result = self._runner.run(ToolInvocation(cmd=cmd, cwd=str(repo_path), timeout=timeout))

        if result.not_installed:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "swiftformat"),
            )
        if result.timed_out:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "swiftformat", timeout=timeout),
            )

        # exit 0 = clean, 1 = would reformat, anything else = crash
        if result.exit_code not in (0, 1):
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(
                    ErrorCode.BINARY_CRASHED, "swiftformat", exit_code=result.exit_code
                ),
            )

        # swiftformat writes lint output to stderr
        output = result.stderr or result.stdout or ""
        dirty_files = []
        for line in output.splitlines():
            m = _REFORMAT_RE.match(line.strip())
            if m:
                dirty_files.append(_make_relative(m.group(1), repo_path))

        if not dirty_files:
            return PluginResult(
                plugin_name=self.name,
                summary={"files_to_reformat": 0},
            )

        findings = [
            {
                "file": path,
                "line": 0,
                "severity": "info",
                "category": "formatting",
                "message": "File needs formatting — run `swiftformat .` to fix automatically.",
                "rule_id": "swiftformat",
            }
            for path in dirty_files
        ]

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"files_to_reformat": len(dirty_files)},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**swiftformat**: {result.error}"
        if not result.findings:
            return ""

        count = result.summary.get("files_to_reformat", len(result.findings))
        lines = ["<details>"]
        noun = "file" if count == 1 else "files"
        lines.append(
            f"<summary>🎨 <b>SwiftFormat ({count} {noun} need formatting)</b>"
            f" — run <code>swiftformat .</code> to fix all</summary>\n"
        )
        lines.append("| File |")
        lines.append("|------|")
        for f in result.findings:
            lines.append(f"| `{f.get('file', '')}` |")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("swiftformat")
def build_swiftformat_plugin() -> SwiftFormatPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return SwiftFormatPlugin()
