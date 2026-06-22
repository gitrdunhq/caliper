# tested-by: tests/unit/test_opa_adapter.py
"""OpaRegoAdapter — adapts OPA policy engine behind PolicyEnginePort.

Uses ToolRunnerPort to execute the OPA binary, keeping this adapter free
of subprocess concerns. All failures degrade to needs_review — never raises.
"""

from __future__ import annotations

import json
import tempfile

import structlog

from caliper.core.policy_port import PolicyDecision, PolicyInput
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

log = structlog.get_logger()

_OPA_TIMEOUT = 10

_OPA_DEFAULT_CONFIG = {
    "forbidden_licenses": [],
    "max_transitive_deps": 200,
    "min_package_age_days": 90,
    "rules_enabled": {
        "critical_vuln": True,
        "forbidden_license": True,
        "package_age": True,
        "malicious_package": True,
        "transitive_count": True,
        "supply_chain_diff": True,
    },
}


class OpaRegoAdapter:
    """Evaluates policy against scanner findings via OPA binary through ToolRunnerPort.

    Implements PolicyEnginePort. Builds OPA input JSON, delegates execution
    to ToolRunnerPort, and maps OPA deny/warn output to PolicyDecision.
    """

    def __init__(
        self, policy_path: str, tool_runner: ToolRunnerPort, timeout: int = _OPA_TIMEOUT
    ) -> None:
        self._policy_path = policy_path
        self._tool_runner = tool_runner
        self._timeout = timeout

    def evaluate(self, input: PolicyInput) -> PolicyDecision:
        """Evaluate findings against the OPA policy bundle.

        Returns a PolicyDecision. Degrades gracefully to needs_review on
        timeout or when OPA is not installed. Never raises.
        """
        opa_input = self._build_opa_input(input)

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=True) as tmp:
                json.dump(opa_input, tmp)
                tmp.flush()

                invocation = ToolInvocation(
                    cmd=[
                        "opa",
                        "eval",
                        "-d",
                        self._policy_path,
                        "-i",
                        tmp.name,
                        "--format",
                        "json",
                        "data.policy",
                    ],
                    cwd=".",
                    timeout=self._timeout,
                )
                result = self._tool_runner.run(invocation)
        except Exception as exc:  # noqa: BLE001
            log.error(
                "opa_adapter_exception",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return PolicyDecision(verdict="needs_review")

        if result.timed_out or result.not_installed:
            log.warning(
                "opa_adapter_degraded",
                timed_out=result.timed_out,
                not_installed=result.not_installed,
            )
            return PolicyDecision(verdict="needs_review")

        return self._parse_output(result.stdout)

    def _build_opa_input(self, input: PolicyInput) -> dict:
        findings = [
            {
                "id": f.id,
                "severity": f.severity,
                "message": f.message,
            }
            for f in input.findings
        ]
        merged_config = dict(_OPA_DEFAULT_CONFIG)
        if input.config:
            merged_config.update(input.config)
        return {
            "findings": findings,
            "pkg": input.packages[0] if input.packages else {},
            "config": merged_config,
        }

    def _parse_output(self, stdout: str) -> PolicyDecision:
        try:
            data = json.loads(stdout)
            value = data["result"][0]["expressions"][0]["value"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            log.warning("opa_adapter_parse_error", error=str(exc))
            return PolicyDecision(verdict="needs_review")

        deny: list[str] = list(value.get("deny", []))
        warn: list[str] = list(value.get("warn", []))

        triggered = deny + warn  # the rules that fired — surfaced to the user via the memo
        if deny:
            return PolicyDecision(
                verdict="reject",
                deny_reasons=deny,
                warn_reasons=warn,
                triggered_rules=triggered,
            )
        if warn:
            return PolicyDecision(
                verdict="approve_with_constraints",
                warn_reasons=warn,
                triggered_rules=triggered,
            )
        return PolicyDecision(verdict="approve")


from caliper.core.registries import POLICY_ENGINES  # noqa: E402  (registration wiring)


@POLICY_ENGINES.register("opa")
def build_opa_engine(
    *, policy_path: str, tool_runner: ToolRunnerPort, timeout: int = _OPA_TIMEOUT
) -> OpaRegoAdapter:
    """Construct the OPA Rego policy adapter (the input.pkg quirk stays inside it)."""
    return OpaRegoAdapter(policy_path=policy_path, tool_runner=tool_runner, timeout=timeout)
