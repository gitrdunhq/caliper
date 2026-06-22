# tested-by: tests/unit/test_opa_adapter.py
"""Contract tests for OpaRegoAdapter implementing PolicyEnginePort.

All tests import from caliper.core.opa_adapter which does not exist yet.
Every test here is expected to fail with ImportError (RED phase of TDD).
"""

from __future__ import annotations

import json

from caliper.core.opa_adapter import OpaRegoAdapter  # noqa: F401 — does not exist yet (RED)
from caliper.core.plugin import PluginFinding
from caliper.core.policy_port import PolicyDecision, PolicyEnginePort, PolicyInput
from caliper.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class FakeToolRunner:
    """Fake ToolRunnerPort implementation for unit tests.

    Stores the last ToolInvocation for assertion and returns a
    pre-configured ToolResult.
    """

    def __init__(self, result: ToolResult) -> None:
        self._result = result
        self.invocations: list[ToolInvocation] = []

    def run(self, invocation: ToolInvocation) -> ToolResult:
        self.invocations.append(invocation)
        return self._result


def _opa_stdout(deny: list[str] | None = None, warn: list[str] | None = None) -> str:
    """Build a minimal valid OPA eval JSON response."""
    value: dict = {
        "deny": deny or [],
        "warn": warn or [],
    }
    return json.dumps({"result": [{"expressions": [{"value": value}]}]})


def _ok_result(deny: list[str] | None = None, warn: list[str] | None = None) -> ToolResult:
    return ToolResult(
        exit_code=0,
        stdout=_opa_stdout(deny=deny, warn=warn),
        stderr="",
    )


def _make_finding(**kwargs) -> PluginFinding:
    defaults = dict(id="VULN-001", severity="high", message="test finding")
    defaults.update(kwargs)
    return PluginFinding(**defaults)


def _make_input(
    findings: list[PluginFinding] | None = None,
    packages: list[dict] | None = None,
    config: dict | None = None,
) -> PolicyInput:
    return PolicyInput(
        findings=findings or [],
        packages=packages or [{"name": "requests", "version": "2.28.0"}],
        config=config or {},
    )


# ---------------------------------------------------------------------------
# 1. Structural contract: OpaRegoAdapter satisfies PolicyEnginePort
# ---------------------------------------------------------------------------


class TestOpaRegoAdapterProtocol:
    def test_implements_policy_engine_port(self):
        """OpaRegoAdapter must be recognised as a PolicyEnginePort at runtime."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        assert isinstance(adapter, PolicyEnginePort)

    def test_tool_runner_parameter_satisfies_protocol(self):
        """FakeToolRunner must satisfy ToolRunnerPort so the test helper is valid."""
        assert isinstance(FakeToolRunner(_ok_result()), ToolRunnerPort)


# ---------------------------------------------------------------------------
# 2. Verdict mapping
# ---------------------------------------------------------------------------


class TestVerdictMapping:
    def test_deny_rules_produce_reject_verdict(self):
        """OPA deny messages must produce verdict='reject'."""
        runner = FakeToolRunner(_ok_result(deny=["CVE-2024-0001: critical vuln"]))
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert decision.verdict == "reject"

    def test_warn_only_produces_approve_with_constraints(self):
        """OPA warn messages with no deny must produce verdict='approve_with_constraints'."""
        runner = FakeToolRunner(_ok_result(warn=["package age < 30 days"]))
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert decision.verdict == "approve_with_constraints"

    def test_empty_deny_and_warn_produces_approve(self):
        """Empty deny and warn lists must produce verdict='approve'."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert decision.verdict == "approve"

    def test_timeout_produces_needs_review(self):
        """A timed-out ToolResult must degrade to verdict='needs_review'."""
        timed_out = ToolResult(exit_code=-1, stdout="", stderr="", timed_out=True)
        runner = FakeToolRunner(timed_out)
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert decision.verdict == "needs_review"

    def test_not_installed_produces_needs_review(self):
        """A not_installed ToolResult must degrade to verdict='needs_review'."""
        missing = ToolResult(exit_code=127, stdout="", stderr="", not_installed=True)
        runner = FakeToolRunner(missing)
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert decision.verdict == "needs_review"


# ---------------------------------------------------------------------------
# 3. Reason population
# ---------------------------------------------------------------------------


class TestReasonPopulation:
    def test_deny_reasons_populated_from_opa_deny(self):
        """deny_reasons must contain each message returned in OPA's deny set."""
        deny_msgs = ["CVE-2024-0001: critical", "forbidden license: GPL-3.0"]
        runner = FakeToolRunner(_ok_result(deny=deny_msgs))
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert set(deny_msgs) == set(decision.deny_reasons)

    def test_warn_reasons_populated_from_opa_warn(self):
        """warn_reasons must contain each message returned in OPA's warn set."""
        warn_msgs = ["high transitive dep count: 250"]
        runner = FakeToolRunner(_ok_result(warn=warn_msgs))
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert set(warn_msgs) == set(decision.warn_reasons)

    def test_deny_reasons_empty_when_approve(self):
        """deny_reasons must be empty when OPA returns no deny messages."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert decision.deny_reasons == []

    def test_warn_reasons_empty_when_full_approve(self):
        """warn_reasons must be empty when OPA returns no warn messages."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())
        assert decision.warn_reasons == []


# ---------------------------------------------------------------------------
# 4. Tool runner delegation
# ---------------------------------------------------------------------------


class TestToolRunnerDelegation:
    def test_evaluate_calls_tool_runner_exactly_once(self):
        """evaluate() must call ToolRunnerPort.run() exactly once per invocation."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        adapter.evaluate(_make_input())
        assert len(runner.invocations) == 1

    def test_tool_invocation_contains_opa_command(self):
        """ToolInvocation cmd must begin with 'opa' so the correct binary is called."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        adapter.evaluate(_make_input())
        invocation = runner.invocations[0]
        assert invocation.cmd[0] == "opa"

    def test_tool_invocation_references_policy_path(self):
        """ToolInvocation cmd must reference the policy_path passed to the constructor."""
        policy_path = "/custom/policy/dir"
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path=policy_path, tool_runner=runner)
        adapter.evaluate(_make_input())
        invocation = runner.invocations[0]
        assert policy_path in invocation.cmd

    def test_opa_not_called_when_not_installed(self):
        """evaluate() must not raise even when OPA is not installed."""
        missing = ToolResult(
            exit_code=127, stdout="", stderr="opa: command not found", not_installed=True
        )
        runner = FakeToolRunner(missing)
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        # Must not raise; degrades gracefully
        decision = adapter.evaluate(_make_input())
        assert isinstance(decision, PolicyDecision)


# ---------------------------------------------------------------------------
# 5. Return type contract
# ---------------------------------------------------------------------------


class TestReturnTypeContract:
    def test_evaluate_returns_policy_decision_instance(self):
        """evaluate() must always return a PolicyDecision regardless of OPA output."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        result = adapter.evaluate(_make_input())
        assert isinstance(result, PolicyDecision)

    def test_evaluate_returns_policy_decision_on_timeout(self):
        """evaluate() must return PolicyDecision even when ToolResult.timed_out is True."""
        timed_out = ToolResult(exit_code=-1, stdout="", stderr="", timed_out=True)
        runner = FakeToolRunner(timed_out)
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        result = adapter.evaluate(_make_input())
        assert isinstance(result, PolicyDecision)

    def test_evaluate_with_findings_does_not_raise(self):
        """evaluate() must not raise when PolicyInput contains non-empty findings."""
        runner = FakeToolRunner(_ok_result(deny=["CVE-2024-9999: critical"]))
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        findings = [_make_finding(id="CVE-2024-9999", severity="critical")]
        decision = adapter.evaluate(_make_input(findings=findings))
        assert decision.verdict == "reject"


# ---------------------------------------------------------------------------
# 6. Unexpected exception handling — never raises contract
# ---------------------------------------------------------------------------


class _ExplodingRunner:
    """Simulates a tool runner that raises an unexpected exception."""

    def run(self, invocation: ToolInvocation) -> ToolResult:
        raise RuntimeError("Unexpected tool runner explosion")


class TestUnexpectedExceptionHandling:
    def test_evaluate_handles_unexpected_tool_runner_exception(self):
        """evaluate() must degrade to needs_review when tool_runner raises unexpectedly."""
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=_ExplodingRunner())
        result = adapter.evaluate(_make_input())
        assert result.verdict == "needs_review"
        assert result.deny_reasons == []
        assert result.warn_reasons == []

    def test_evaluate_returns_policy_decision_on_unexpected_exception(self):
        """evaluate() must return a PolicyDecision instance even on unexpected exceptions."""
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=_ExplodingRunner())
        result = adapter.evaluate(_make_input())
        assert isinstance(result, PolicyDecision)


# ---------------------------------------------------------------------------
# 7. Regression P03-2 — triggered_rules must be populated
# ---------------------------------------------------------------------------


class TestTriggeredRulesRegression:
    def test_triggered_rules_populated_on_reject(self):
        """triggered_rules must contain deny + warn messages on a reject verdict
        (regression for P03-2: triggered_rules was previously always empty)."""
        deny_msgs = ["CVE-2024-0001: critical vuln"]
        warn_msgs = ["high transitive dep count"]
        runner = FakeToolRunner(_ok_result(deny=deny_msgs, warn=warn_msgs))
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())

        assert decision.verdict == "reject"
        assert set(deny_msgs).issubset(
            set(decision.triggered_rules)
        ), "triggered_rules must include deny messages"
        assert set(warn_msgs).issubset(
            set(decision.triggered_rules)
        ), "triggered_rules must include warn messages when deny is present"

    def test_triggered_rules_populated_on_approve_with_constraints(self):
        """triggered_rules must contain warn messages on approve_with_constraints
        (regression for P03-2)."""
        warn_msgs = ["package age < 30 days"]
        runner = FakeToolRunner(_ok_result(warn=warn_msgs))
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())

        assert decision.verdict == "approve_with_constraints"
        assert set(warn_msgs).issubset(
            set(decision.triggered_rules)
        ), "triggered_rules must include warn messages on approve_with_constraints"

    def test_triggered_rules_empty_on_full_approve(self):
        """triggered_rules must be empty when both deny and warn are empty."""
        runner = FakeToolRunner(_ok_result())
        adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=runner)
        decision = adapter.evaluate(_make_input())

        assert decision.verdict == "approve"
        assert decision.triggered_rules == []
