"""Contract tests for PolicyEnginePort, PolicyInput, and PolicyDecision.
# tested-by: tests/unit/test_policy_port.py

RED phase for issue #156 — these tests import symbols that do not exist yet.
They are expected to fail with ImportError until the production code is added.
"""

from __future__ import annotations

import pytest

from caliper.core.plugin import PluginFinding

# These imports will raise ImportError until src/caliper/core/policy_port.py exists.
from caliper.core.policy_port import PolicyDecision, PolicyEnginePort, PolicyInput

# ---------------------------------------------------------------------------
# PolicyInput construction
# ---------------------------------------------------------------------------


class TestPolicyInputConstruction:
    def test_can_construct_with_empty_findings(self):
        inp = PolicyInput(findings=[], packages=[], config={})
        assert inp.findings == []
        assert inp.packages == []
        assert inp.config == {}

    def test_can_construct_with_plugin_findings(self):
        finding = PluginFinding(id="CVE-2024-001", severity="high", message="critical vuln")
        inp = PolicyInput(
            findings=[finding],
            packages=[{"name": "requests", "version": "2.28.0", "ecosystem": "pypi"}],
            config={"rules_enabled": {"critical_vuln": True}},
        )
        assert len(inp.findings) == 1
        assert inp.findings[0].id == "CVE-2024-001"

    def test_findings_field_accepts_list_of_plugin_finding(self):
        findings = [
            PluginFinding(id=f"CVE-{i}", severity="medium", message=f"vuln {i}") for i in range(3)
        ]
        inp = PolicyInput(findings=findings, packages=[], config={})
        assert len(inp.findings) == 3

    def test_packages_field_is_list_of_dicts(self):
        packages = [
            {"name": "flask", "version": "2.0.0", "ecosystem": "pypi"},
            {"name": "express", "version": "4.18.0", "ecosystem": "npm"},
        ]
        inp = PolicyInput(findings=[], packages=packages, config={})
        assert inp.packages[0]["name"] == "flask"
        assert inp.packages[1]["ecosystem"] == "npm"

    def test_config_field_accepts_rules_enabled_dict(self):
        config = {
            "rules_enabled": {"critical_vuln": True, "forbidden_license": False},
            "max_transitive_deps": 100,
        }
        inp = PolicyInput(findings=[], packages=[], config=config)
        assert inp.config["rules_enabled"]["critical_vuln"] is True
        assert inp.config["max_transitive_deps"] == 100


# ---------------------------------------------------------------------------
# PolicyDecision construction and fields
# ---------------------------------------------------------------------------


class TestPolicyDecisionConstruction:
    def test_can_construct_approve_decision(self):
        decision = PolicyDecision(
            verdict="approve",
            deny_reasons=[],
            warn_reasons=[],
            triggered_rules=[],
        )
        assert decision.verdict == "approve"

    def test_can_construct_reject_decision_with_reasons(self):
        decision = PolicyDecision(
            verdict="reject",
            deny_reasons=["critical CVE found: CVE-2024-001"],
            warn_reasons=[],
            triggered_rules=["critical_vuln"],
        )
        assert decision.verdict == "reject"
        assert "CVE-2024-001" in decision.deny_reasons[0]

    def test_can_construct_approve_with_constraints(self):
        decision = PolicyDecision(
            verdict="approve_with_constraints",
            deny_reasons=[],
            warn_reasons=["high transitive dep count: 250"],
            triggered_rules=["transitive_count"],
        )
        assert decision.verdict == "approve_with_constraints"
        assert len(decision.warn_reasons) == 1

    def test_can_construct_needs_review(self):
        decision = PolicyDecision(
            verdict="needs_review",
            deny_reasons=[],
            warn_reasons=[],
            triggered_rules=[],
        )
        assert decision.verdict == "needs_review"

    def test_deny_reasons_is_list(self):
        decision = PolicyDecision(
            verdict="reject",
            deny_reasons=["reason one", "reason two"],
            warn_reasons=[],
            triggered_rules=[],
        )
        assert isinstance(decision.deny_reasons, list)
        assert len(decision.deny_reasons) == 2

    def test_warn_reasons_is_list(self):
        decision = PolicyDecision(
            verdict="approve_with_constraints",
            deny_reasons=[],
            warn_reasons=["warn a", "warn b"],
            triggered_rules=[],
        )
        assert isinstance(decision.warn_reasons, list)

    def test_triggered_rules_is_list(self):
        decision = PolicyDecision(
            verdict="reject",
            deny_reasons=["bad license"],
            warn_reasons=[],
            triggered_rules=["forbidden_license"],
        )
        assert "forbidden_license" in decision.triggered_rules


# ---------------------------------------------------------------------------
# Verdict semantics
# ---------------------------------------------------------------------------


class TestPolicyDecisionVerdictSemantics:
    def test_no_deny_reasons_verdict_is_approve(self):
        decision = PolicyDecision(
            verdict="approve",
            deny_reasons=[],
            warn_reasons=[],
            triggered_rules=[],
        )
        assert decision.deny_reasons == []
        assert decision.verdict == "approve"

    def test_with_deny_reasons_verdict_is_reject(self):
        decision = PolicyDecision(
            verdict="reject",
            deny_reasons=["critical vulnerability"],
            warn_reasons=[],
            triggered_rules=["critical_vuln"],
        )
        assert len(decision.deny_reasons) > 0
        assert decision.verdict == "reject"

    def test_only_warn_reasons_is_not_reject(self):
        decision = PolicyDecision(
            verdict="approve_with_constraints",
            deny_reasons=[],
            warn_reasons=["medium vuln detected"],
            triggered_rules=["medium_vuln"],
        )
        assert decision.deny_reasons == []
        assert decision.verdict != "reject"

    def test_verdict_values_are_known_strings(self):
        known_verdicts = {"approve", "reject", "approve_with_constraints", "needs_review"}
        for verdict in known_verdicts:
            d = PolicyDecision(
                verdict=verdict,
                deny_reasons=[],
                warn_reasons=[],
                triggered_rules=[],
            )
            assert d.verdict in known_verdicts


# ---------------------------------------------------------------------------
# PolicyEnginePort is a Protocol
# ---------------------------------------------------------------------------


class TestPolicyEnginePortIsProtocol:
    def test_policy_engine_port_is_a_protocol(self):
        """PolicyEnginePort must be a typing.Protocol, not an ABC."""
        import typing

        # Protocol classes have __protocol_attrs__ or are instances of _ProtocolMeta
        # The reliable check is that it comes from typing.Protocol lineage.
        assert hasattr(PolicyEnginePort, "__protocol_attrs__") or (
            typing.Protocol in getattr(PolicyEnginePort, "__mro__", [])
        )

    def test_policy_engine_port_is_runtime_checkable(self):
        """PolicyEnginePort must support isinstance() checks at runtime."""
        # This will raise TypeError if the Protocol is not @runtime_checkable.
        try:
            isinstance(object(), PolicyEnginePort)
        except TypeError as exc:
            pytest.fail(f"PolicyEnginePort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_policy_engine_port_has_evaluate_method(self):
        assert hasattr(
            PolicyEnginePort, "evaluate"
        ), "PolicyEnginePort must declare an 'evaluate' method"


# ---------------------------------------------------------------------------
# Fake implementation satisfies the Protocol
# ---------------------------------------------------------------------------


class _FakePolicyEngine:
    """Minimal fake that should satisfy PolicyEnginePort."""

    def evaluate(self, input: PolicyInput) -> PolicyDecision:
        if not input.findings:
            return PolicyDecision(
                verdict="approve",
                deny_reasons=[],
                warn_reasons=[],
                triggered_rules=[],
            )
        return PolicyDecision(
            verdict="reject",
            deny_reasons=["findings present"],
            warn_reasons=[],
            triggered_rules=["critical_vuln"],
        )


class TestFakeImplementationSatisfiesProtocol:
    def test_fake_is_instance_of_protocol(self):
        fake = _FakePolicyEngine()
        assert isinstance(fake, PolicyEnginePort)

    def test_fake_returns_approve_for_empty_findings(self):
        fake = _FakePolicyEngine()
        inp = PolicyInput(findings=[], packages=[], config={})
        result = fake.evaluate(inp)
        assert result.verdict == "approve"
        assert result.deny_reasons == []

    def test_fake_returns_reject_for_non_empty_findings(self):
        fake = _FakePolicyEngine()
        finding = PluginFinding(id="CVE-X", severity="critical", message="bad")
        inp = PolicyInput(findings=[finding], packages=[], config={})
        result = fake.evaluate(inp)
        assert result.verdict == "reject"
        assert len(result.deny_reasons) > 0

    def test_evaluate_return_type_is_policy_decision(self):
        fake = _FakePolicyEngine()
        inp = PolicyInput(findings=[], packages=[], config={})
        result = fake.evaluate(inp)
        assert isinstance(result, PolicyDecision)
