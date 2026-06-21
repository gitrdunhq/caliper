"""Mypy/Pyright plugin — deterministic cross-file type checking.
# tested-by: tests/unit/test_mypy_plugin.py

Prefers pyright (faster, stricter) when available, falls back to mypy.
Only error-level findings are reported — notes are excluded.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import structlog

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin

logger = structlog.get_logger(__name__)

_MYPY_LINE_RE = re.compile(
    r"^(.+?):(\d+)(?::\d+)?:\s+(error|warning|note):\s+(.+?)(?:\s+\[(.+)\])?$"
)

_MYPY_SEVERITY_MAP = {"error": "high", "warning": "medium", "note": "info"}
_PYRIGHT_SEVERITY_MAP = {"error": "high", "warning": "medium", "information": "low"}


class MypyPlugin(ScannerPlugin):
    def __init__(self) -> None:
        self._tool: str | None = None

    @property
    def name(self) -> str:
        return "mypy"

    @property
    def description(self) -> str:
        return "Cross-file type checking (mypy/pyright)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix == ".py" for f in files)

    def _detect_tool(self) -> str | None:
        if self._tool:
            return self._tool
        for tool in ("pyright", "mypy"):
            if shutil.which(tool):
                self._tool = tool
                return tool
        return None

    def run(
        self,
        files: list[str],
        repo_path: Path,
        timeout: int = 60,
    ) -> PluginResult:
        tool = self._detect_tool()
        if not tool:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "mypy/pyright"),
            )

        if tool == "pyright":
            return self._run_pyright(files, repo_path, timeout)
        return self._run_mypy(files, repo_path, timeout)

    def _run_mypy(self, files: list[str], repo_path: Path, timeout: int) -> PluginResult:
        py_files = [f for f in files if f.endswith(".py")]
        if not py_files:
            return PluginResult(plugin_name=self.name)

        try:
            r = subprocess.run(
                ["mypy", "--no-error-summary", "--show-column-numbers", *py_files],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                cwd=str(repo_path),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "mypy", timeout=timeout),
            )

        findings = []
        for line in r.stdout.splitlines():
            m = _MYPY_LINE_RE.match(line)
            if not m:
                continue
            severity = _MYPY_SEVERITY_MAP.get(m.group(3), "info")
            if severity == "info":
                continue
            findings.append(
                {
                    "file": m.group(1),
                    "line": int(m.group(2)),
                    "severity": severity,
                    "message": m.group(4),
                    "rule": m.group(5) or "mypy",
                    "category": "type-error",
                }
            )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"errors": len(findings), "tool": "mypy"},
        )

    def _run_pyright(self, files: list[str], repo_path: Path, timeout: int) -> PluginResult:
        py_files = [f for f in files if f.endswith(".py")]
        if not py_files:
            return PluginResult(plugin_name=self.name)

        try:
            r = subprocess.run(
                ["pyright", "--outputjson", *py_files],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                cwd=str(repo_path),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "pyright", timeout=timeout),
            )

        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.PARSE_ERROR, "pyright"),
            )

        findings = []
        for diag in data.get("generalDiagnostics", []):
            severity = _PYRIGHT_SEVERITY_MAP.get(diag.get("severity", ""), "info")
            if severity == "info":
                continue
            line_num = diag.get("range", {}).get("start", {}).get("line", 0) + 1
            findings.append(
                {
                    "file": diag.get("file", "?"),
                    "line": line_num,
                    "severity": severity,
                    "message": diag.get("message", ""),
                    "rule": diag.get("rule", "pyright"),
                    "category": "type-error",
                }
            )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"errors": len(findings), "tool": "pyright"},
        )

    def _render_inline(self, result: PluginResult) -> str:
        if result.error:
            return f"**mypy**: {result.error}"
        if not result.findings:
            return ""
        tool = result.summary.get("tool", "mypy")
        lines = [
            "<details open>",
            f"<summary>🔬 <b>Type Errors — {tool} ({len(result.findings)})</b></summary>\n",
        ]
        for f in result.findings:
            icon = {"high": "🔴", "medium": "🟡"}.get(f["severity"], "🔵")
            lines.append(f"{icon} **`{f['file']}:{f['line']}`** — `{f['rule']}`")
            lines.append(f"> {f['message'][:200]}\n")
        lines.append("</details>\n")
        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("mypy")
def build_mypy_plugin() -> MypyPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return MypyPlugin()
