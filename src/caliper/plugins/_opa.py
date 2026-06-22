"""OPA plugin — policy enforcement.
# tested-by: tests/unit/test_plugin_registry.py

Special plugin: consumes findings from other plugins, not raw files.
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.policy import OpaEvaluator


class OpaPlugin(ScannerPlugin):
    def __init__(self, policy_path: str = "./policies") -> None:
        self._policy_path = policy_path

    @property
    def name(self) -> str:
        return "opa"

    @property
    def description(self) -> str:
        return "Policy enforcement — 6 Rego rules (deny/warn/approve)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    @property
    def depends_on(self) -> list[str]:
        """Run after all scan plugins — replaces the former hard-coded name check."""
        return ["*"]

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return Path(self._policy_path).exists()

    def run(
        self,
        files: list[str],
        repo_path: Path,
        findings: list[dict] | None = None,
        package_metadata: dict | None = None,
    ) -> PluginResult:
        if findings is None:
            findings = []
        if package_metadata is None:
            package_metadata = {}

        try:
            opa = OpaEvaluator(self._policy_path)
            from caliper.core.models import (
                Finding,
                FindingCategory,
                normalize_severity,
            )

            typed_findings = []
            for f in findings:
                try:
                    category = FindingCategory(f.get("category", "vulnerability"))
                except ValueError:
                    category = FindingCategory.vulnerability
                typed_findings.append(
                    Finding(
                        severity=normalize_severity(f.get("severity", "info")),
                        category=category,
                        description=f.get("summary", f.get("description", "")),
                        source_tool=f.get("source_tool", "plugin"),
                        package_name=f.get("package", ""),
                        version=f.get("version", ""),
                        advisory_id=f.get("id", ""),
                        license_id=f.get("license", ""),
                    )
                )

            evaluation = opa.evaluate(typed_findings, package_metadata)
            return PluginResult(
                plugin_name=self.name,
                findings=[
                    {
                        "decision": evaluation.decision.value,
                        "triggered_rules": evaluation.triggered_rules,
                        "constraints": evaluation.constraints,
                        "policy_version": evaluation.policy_bundle_version,
                    }
                ],
                summary={
                    "decision": evaluation.decision.value,
                    "rules_triggered": len(evaluation.triggered_rules),
                },
            )
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**OPA**: {result.error}"
        if not result.findings:
            return ""
        d = result.findings[0]
        decision = d.get("decision", "?")
        rules = d.get("triggered_rules", [])
        icon = {
            "approve": "🟢",
            "reject": "🔴",
            "needs_review": "🟡",
            "approve_with_constraints": "🟠",
        }.get(decision, "⚪")
        lines = [f"{icon} **Policy: {decision}**"]
        if rules:
            for r in rules:
                lines.append(f"- {r}")
        return "\n".join(lines)
