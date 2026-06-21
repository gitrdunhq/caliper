"""kube-linter plugin — K8s/Helm manifest validation.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

from pathlib import Path

from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from eedom.plugins._runners.kube_linter_runner import run_kube_linter as _run


class KubeLinterPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "kube-linter"

    @property
    def description(self) -> str:
        return "K8s/Helm security — schema validation, resource limits, privileged containers"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.infra

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix in (".yaml", ".yml") for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            data = _run(files, str(repo_path))
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

        return PluginResult(
            plugin_name=self.name,
            findings=data.get("findings", []),
            summary={"total": data.get("finding_count", 0)},
            error=data.get("error", ""),
        )

    def _render_inline(self, result: PluginResult) -> str:
        if result.error:
            return f"**kube-linter**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>☸️ <b>K8s/Helm ({len(result.findings)})</b></summary>\n")
        for f in result.findings[:15]:
            lines.append(
                f"**{f.get('check', '?')}** —"
                f" `{f.get('object_kind', '?')}/{f.get('object_name', '?')}`"
            )
            lines.append(f"> {f.get('message', '')[:200]}")
            if f.get("remediation"):
                lines.append(f"> 💡 {f['remediation'][:200]}")
            lines.append("")
        lines.append("</details>\n")
        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("kube-linter")
def build_kube_linter_plugin() -> KubeLinterPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return KubeLinterPlugin()
