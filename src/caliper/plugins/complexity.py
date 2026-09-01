"""Complexity plugin — Lizard CCN + Radon MI.
# tested-by: tests/unit/test_plugin_registry.py
# tested-by: tests/unit/test_complexity_plugin.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.config import CaliperSettings
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.plugins._runners.complexity_runner import run_complexity as _run

_CODE_EXTS = {".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".java", ".rs", ".c", ".cpp", ".swift"}
_DEFAULT_CCN = 10  # a function is a finding only when its CCN exceeds this


class ComplexityPlugin(ScannerPlugin):
    def __init__(self, settings: CaliperSettings | None = None) -> None:
        self._timeout = (settings or CaliperSettings()).scanner_timeout

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
            data = _run(files, str(repo_path), timeout=self._timeout)
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

        if data.get("error"):
            return PluginResult(
                plugin_name=self.name,
                error=data["error"],
            )
        threshold = self._ccn_threshold(repo_path)
        functions = data.get("functions", [])
        summary = dict(data.get("summary", {}))
        # Only functions over the threshold are findings; every function still
        # feeds the summary so avg/max/NLOC stay honest. Before this, each of
        # the ~6k functions in a mid-size repo was its own note-level finding.
        summary["functions_scanned"] = len(functions)
        summary["ccn_threshold"] = threshold
        return PluginResult(
            plugin_name=self.name,
            findings=[f for f in functions if self._ccn_int(f) > threshold],
            summary=summary,
        )

    @staticmethod
    def _ccn_threshold(repo_path: Path) -> int:
        """`thresholds.complexity.ccn` from .caliper.yaml, default 10; fail-open to 10."""
        from caliper.core.repo_config import load_repo_config

        try:
            raw = (
                load_repo_config(repo_path)
                .thresholds.get("complexity", {})
                .get("ccn", _DEFAULT_CCN)
            )
            return int(raw)
        except (ValueError, TypeError, OSError):
            return _DEFAULT_CCN

    @staticmethod
    def _ccn_int(f: dict) -> int:
        """Coerce cyclomatic_complexity to int; return 0 if unparseable."""
        try:
            return int(f.get("cyclomatic_complexity", 0))
        except (TypeError, ValueError):
            return 0

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        threshold = self._ccn_int(
            {"cyclomatic_complexity": result.summary.get("ccn_threshold", _DEFAULT_CCN)}
        )
        ctx["high_ccn"] = [f for f in result.findings if self._ccn_int(f) > threshold]
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
        threshold = s.get("ccn_threshold", _DEFAULT_CCN)
        scanned = s.get("functions_scanned")
        high = [
            f
            for f in result.findings
            if self._ccn_int(f) > self._ccn_int({"cyclomatic_complexity": threshold})
        ]
        if high:
            scanned_note = f" of {scanned} scanned" if scanned is not None else ""
            lines.append(
                f"**⚠️ High complexity (CCN > {threshold}, {len(high)}{scanned_note}):**\n"
            )
        max_rows = 25
        lines.append("| Function | File | CCN | MI | NLOC |")
        lines.append("|----------|------|-----|----|------|")
        for f in result.findings[:max_rows]:
            mi = f.get("maintainability_index", "?")
            lines.append(
                f"| `{f['function']}` | `{f['file']}` | {f['cyclomatic_complexity']}"
                f" | {mi} | {f['nloc']} |"
            )
        remaining = len(result.findings) - max_rows
        if remaining > 0:
            lines.append(f"\n*...{remaining} more functions (see SARIF for full list)*")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("complexity")
def build_complexity_plugin(settings: CaliperSettings | None = None) -> ComplexityPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return ComplexityPlugin(settings=settings)
