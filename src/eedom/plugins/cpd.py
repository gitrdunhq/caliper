"""PMD CPD plugin — copy-paste detection.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

from pathlib import Path

from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from eedom.plugins._runners.cpd_runner import run_cpd as _run

_CODE_EXTS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".rb",
    ".java",
    ".kt",
    ".swift",
    ".rs",
    ".css",
}


class CpdPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "cpd"

    @property
    def description(self) -> str:
        return "Copy-paste detection — token-based duplication (12 languages)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

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
            findings=data.get("duplicates", []),
            summary={
                "total": data.get("duplicate_count", 0),
                "files_scanned": data.get("files_scanned", 0),
            },
            error=data.get("error", ""),
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**cpd**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>📋 <b>Duplicated Code ({len(result.findings)})</b></summary>\n")
        for d in result.findings[:10]:
            lines.append(f"**{d['lines']} lines, {d['tokens']} tokens** ({d['language']})")
            for loc in d["locations"]:
                lines.append(f"- `{loc['file']}:{loc['start_line']}-{loc['end_line']}`")
            if d.get("fragment"):
                lines.append(f"```\n{d['fragment'][:150]}\n```")
            lines.append("")
        lines.append("</details>\n")
        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("cpd")
def build_cpd_plugin() -> CpdPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return CpdPlugin()
