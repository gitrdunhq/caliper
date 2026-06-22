"""cdk-nag plugin — CDK CloudFormation security scanning.
# tested-by: tests/unit/test_cdk_nag_plugin.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.plugins._runners.cdk_nag_runner import run_cdk_nag as _run


class CdkNagPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "cdk-nag"

    @property
    def description(self) -> str:
        return "CDK security — validates synthesized CloudFormation against AWS best practices"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.infra

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return (repo_path / "cdk.json").exists() or (repo_path / "cdk.out").is_dir()

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        skip_synth = not (repo_path / "cdk.json").exists()
        try:
            data = _run(str(repo_path), skip_synth=skip_synth)
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
            return f"**cdk-nag**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>☁️ <b>CDK/CloudFormation ({len(result.findings)})</b></summary>\n")
        for f in result.findings[:15]:
            severity_icon = "🔴" if f.get("severity") == "critical" else "🟡"
            lines.append(f"{severity_icon} **{f.get('rule_id', '?')}** — `{f.get('file', '?')}`")
            lines.append(f"> {f.get('message', '')[:200]}")
            resources = f.get("logical_resource_ids", [])
            if resources:
                lines.append(f"> Resources: `{'`, `'.join(resources[:5])}`")
            lines.append("")
        lines.append("</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("cdk-nag")
def build_cdk_nag_plugin() -> CdkNagPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return CdkNagPlugin()
