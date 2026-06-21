"""Complexity plugin — Lizard CCN + Radon MI.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

from pathlib import Path

from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from eedom.plugins._runners.complexity_runner import run_complexity as _run

_CODE_EXTS = {".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".java", ".rs", ".c", ".cpp", ".swift"}


class ComplexityPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "complexity"

    @property
    def description(self) -> str:
        return "Cyclomatic complexity (Lizard) + maintainability index (Radon)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix in _CODE_EXTS for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            data = _run(files, str(repo_path))
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

        if data.get("error"):
            return PluginResult(
                plugin_name=self.name,
                error=data["error"],
            )
        return PluginResult(
            plugin_name=self.name,
            findings=data.get("functions", []),
            summary=data.get("summary", {}),
        )

    @staticmethod
    def _ccn_int(f: dict) -> int:
        """Coerce cyclomatic_complexity to int; return 0 if unparseable."""
        try:
            return int(f.get("cyclomatic_complexity", 0))
        except (TypeError, ValueError):
            return 0

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        ctx["high_ccn"] = [f for f in result.findings if self._ccn_int(f) > 10]
        return ctx

    def _render_inline(
        self,
        result: PluginResult,
    ) -> str:
        if result.error:
            return f"**complexity**: {result.error}"
        if not result.findings:
            return ""
        s = result.summary
        avg = s.get("avg_cyclomatic_complexity", 0)
        mx = s.get("max_cyclomatic_complexity", 0)
        nloc = s.get("total_nloc", 0)
        lines = ["<details>"]
        lines.append(
            f"<summary>📊 <b>Complexity (avg CCN: {avg}, max: {mx}, {nloc} NLOC)</b></summary>\n"
        )
        high = [f for f in result.findings if self._ccn_int(f) > 10]
        if high:
            lines.append("**⚠️ High complexity (CCN > 10):**\n")
            lines.append("| Function | File | CCN | MI | NLOC |")
            lines.append("|----------|------|-----|----|------|")
            for f in high:
                mi = f.get("maintainability_index", "?")
                lines.append(
                    f"| `{f['function']}` | `{f['file']}`"
                    f" | {f['cyclomatic_complexity']}"
                    f" | {mi} | {f['nloc']} |"
                )
            lines.append("")
        max_rows = 25
        lines.append("| Function | CCN | MI | NLOC |")
        lines.append("|----------|-----|----|------|")
        for f in result.findings[:max_rows]:
            mi = f.get("maintainability_index", "?")
            lines.append(
                f"| `{f['function']}` | {f['cyclomatic_complexity']} | {mi} | {f['nloc']} |"
            )
        remaining = len(result.findings) - max_rows
        if remaining > 0:
            lines.append(f"\n*...{remaining} more functions (see SARIF for full list)*")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("complexity")
def build_complexity_plugin() -> ComplexityPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return ComplexityPlugin()
