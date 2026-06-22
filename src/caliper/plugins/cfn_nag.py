"""cfn-nag plugin — CloudFormation template security scanning.
# tested-by: tests/unit/test_cfn_nag_plugin.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.plugins._runners.cfn_nag_runner import run_cfn_nag as _run


class CfnNagPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "cfn-nag"

    @property
    def description(self) -> str:
        return (
            "CloudFormation security — IAM wildcards, open security groups, unencrypted resources"
        )

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.infra

    @staticmethod
    def _resolve(f: str, repo_path: Path) -> Path:
        p = Path(f)
        return p if p.is_absolute() else repo_path / f

    def _is_cfn(self, f: str, repo_path: Path) -> bool:
        p = self._resolve(f, repo_path)
        if p.suffix not in (".json", ".yaml", ".yml") or not p.exists():
            return False
        try:
            content = p.read_text(errors="ignore")[:500]
            return "AWSTemplateFormatVersion" in content or "Resources" in content
        except OSError:
            return False

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(self._is_cfn(f, repo_path) for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        cfn_files = [f for f in files if self._is_cfn(f, repo_path)]

        if not cfn_files:
            return PluginResult(plugin_name=self.name, summary={"status": "skipped"})

        try:
            data = _run(cfn_files, str(repo_path))
        except FileNotFoundError:
            from caliper.core.errors import ErrorCode, error_msg

            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "cfn-nag"),
            )
        except subprocess.TimeoutExpired:
            from caliper.core.errors import ErrorCode, error_msg

            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "cfn-nag", timeout=60),
            )
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
            return f"**cfn-nag**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>☁️ <b>CloudFormation ({len(result.findings)})</b></summary>\n")
        for f in result.findings[:15]:
            severity_icon = "🔴" if f.get("severity") == "critical" else "🟡"
            lines.append(f"{severity_icon} **{f.get('rule_id', '?')}** — `{f.get('file', '?')}`")
            lines.append(f"> {f.get('message', '')[:200]}")
            lines.append("")
        lines.append("</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("cfn-nag")
def build_cfn_nag_plugin() -> CfnNagPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return CfnNagPlugin()
