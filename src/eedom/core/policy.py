"""OPA policy evaluation wrapper.
# tested-by: tests/unit/test_policy.py

Invokes OPA as a subprocess to evaluate the review policy against
scanner findings and package metadata. Never raises -- all failures
degrade gracefully to needs_review.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import structlog

from eedom.core.models import (
    DecisionVerdict,
    Finding,
    FindingCategory,
    PolicyEvaluation,
)

log = structlog.get_logger()

# Severity ordering for OPA input (not used for dedup here, just for reference)
_SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")

_DEFAULT_RULES_ENABLED = {
    "critical_vuln": True,
    "forbidden_license": True,
    "package_age": True,
    "malicious_package": True,
    "transitive_count": True,
    "supply_chain_diff": True,
}

_DEFAULT_CONFIG = {
    "forbidden_licenses": [],
    "max_transitive_deps": 200,
    "min_package_age_days": 90,
    "rules_enabled": dict(_DEFAULT_RULES_ENABLED),
}

_FALLBACK_POLICY_VERSION = "unknown"


def build_opa_input(
    findings: list[Finding],
    package_metadata: dict,
    config: dict | None = None,
) -> dict:
    """Construct the OPA-expected input shape per INPUT_SCHEMA.md.

    Args:
        findings: Normalized scanner findings.
        package_metadata: Package metadata dict with name, version, ecosystem, etc.
        config: Optional policy config overrides.

    Returns:
        Dict matching the OPA input schema with findings, package, and config keys.
    """
    opa_findings = []
    for f in findings:
        entry: dict = {
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "category": f.category.value if hasattr(f.category, "value") else str(f.category),
            "description": f.description,
            "package_name": f.package_name,
            "version": f.version,
            "advisory_id": f.advisory_id or "",
            "source_tool": f.source_tool,
        }
        if f.category == FindingCategory.license and f.license_id:
            entry["license_id"] = f.license_id
        opa_findings.append(entry)

    merged_config = dict(_DEFAULT_CONFIG)
    if config:
        for key, value in config.items():
            if key == "rules_enabled" and isinstance(value, dict):
                merged_rules = dict(_DEFAULT_RULES_ENABLED)
                merged_rules.update(value)
                merged_config["rules_enabled"] = merged_rules
            else:
                merged_config[key] = value

    return {
        "findings": opa_findings,
        "pkg": package_metadata,
        "config": merged_config,
    }


class OpaEvaluator:
    """Evaluates review policy by invoking the OPA binary.

    All failures degrade to needs_review -- this class never raises.
    """

    def __init__(
        self,
        policy_path: str,
        timeout: int = 10,
        policy_base_dir: str | None = None,
    ) -> None:
        if policy_base_dir is not None:
            resolved = Path(policy_path).resolve()
            resolved_base = Path(policy_base_dir).resolve()
            try:
                resolved.relative_to(resolved_base)
            except ValueError as exc:
                raise ValueError(
                    f"Policy path {policy_path!r} resolves to {resolved}, "
                    f"which is outside policy directory {resolved_base}"
                ) from exc
            self._policy_path = str(resolved)
        else:
            self._policy_path = policy_path
        self._timeout = timeout

    def evaluate(
        self,
        findings: list[Finding],
        package_metadata: dict,
        config: dict | None = None,
    ) -> PolicyEvaluation:
        """Evaluate findings against the OPA review policy.

        Args:
            findings: Scanner findings to evaluate.
            package_metadata: Package metadata dict.
            config: Optional policy-config overrides (e.g. to enable/disable
                specific ``rules_enabled`` for a focused, standalone evaluation).

        Returns:
            PolicyEvaluation with the decision, triggered rules, and constraints.
        """
        try:
            return self._run_opa(findings, package_metadata, config)
        except subprocess.TimeoutExpired:
            log.warning("opa_evaluation_timed_out", timeout=self._timeout)
            return PolicyEvaluation(
                decision=DecisionVerdict.needs_review,
                triggered_rules=[],
                policy_bundle_version=_FALLBACK_POLICY_VERSION,
                note="OPA evaluation timed out",
            )
        except FileNotFoundError:
            log.warning("opa_binary_not_found")
            return PolicyEvaluation(
                decision=DecisionVerdict.needs_review,
                triggered_rules=[],
                policy_bundle_version=_FALLBACK_POLICY_VERSION,
                note="OPA binary not found",
            )
        except Exception as exc:
            log.warning("opa_evaluation_failed", error=str(exc))
            return PolicyEvaluation(
                decision=DecisionVerdict.needs_review,
                triggered_rules=[],
                policy_bundle_version=_FALLBACK_POLICY_VERSION,
                note=f"OPA evaluation failed: {exc}",
            )

    def _run_opa(
        self,
        findings: list[Finding],
        package_metadata: dict,
        config: dict | None = None,
    ) -> PolicyEvaluation:
        """Execute OPA subprocess and parse the result."""
        opa_input = build_opa_input(findings, package_metadata, config)

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=True,
        ) as tmp:
            json.dump(opa_input, tmp)
            tmp.flush()

            cmd = [
                "opa",
                "eval",
                "-d",
                self._policy_path,
                "-i",
                tmp.name,
                "data.policy",
                "--format",
                "json",
            ]

            log.debug("opa_eval_start", cmd=cmd)
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

        return self._parse_opa_output(proc.stdout)

    def _parse_opa_output(self, stdout: str) -> PolicyEvaluation:
        """Parse OPA JSON output into a PolicyEvaluation."""
        data = json.loads(stdout)

        if "errors" in data:
            error_msg = data["errors"][0].get("message", "unknown OPA error")
            log.warning("opa_parse_error", error=error_msg)
            return PolicyEvaluation(
                decision=DecisionVerdict.needs_review,
                triggered_rules=[],
                policy_bundle_version=self._read_policy_version(),
                note=f"OPA policy error: {error_msg}",
            )

        # OPA eval output shape: {"result": [{"expressions": [{"value": {...}}]}]}
        try:
            expressions = data["result"][0]["expressions"]
            value = expressions[0]["value"]
        except (KeyError, IndexError, TypeError) as exc:
            log.warning("opa_unexpected_result", error=str(exc))
            return PolicyEvaluation(
                decision=DecisionVerdict.needs_review,
                triggered_rules=[],
                policy_bundle_version=self._read_policy_version(),
                note=f"OPA returned unexpected result shape: {exc}",
            )

        deny_messages: list[str] = list(value.get("deny", []))
        warn_messages: list[str] = list(value.get("warn", []))
        raw_decision: str = value.get("decision", "approve")

        decision = self._map_decision(raw_decision, deny_messages, warn_messages)
        triggered_rules = deny_messages + warn_messages
        constraints = warn_messages if decision == DecisionVerdict.approve_with_constraints else []

        return PolicyEvaluation(
            decision=decision,
            triggered_rules=triggered_rules,
            constraints=constraints,
            policy_bundle_version=self._read_policy_version(),
        )

    @staticmethod
    def _map_decision(
        raw: str,
        deny: list[str],
        warn: list[str],
    ) -> DecisionVerdict:
        """Map OPA decision string to DecisionVerdict enum."""
        if raw == "reject" or len(deny) > 0:
            return DecisionVerdict.reject
        if raw == "approve_with_constraints" or (len(deny) == 0 and len(warn) > 0):
            return DecisionVerdict.approve_with_constraints
        return DecisionVerdict.approve

    def _read_policy_version(self) -> str:
        """Read policy bundle version from VERSION file if it exists."""
        version_file = Path(self._policy_path) / "VERSION"
        if version_file.is_file():
            return version_file.read_text().strip()
        return _FALLBACK_POLICY_VERSION
