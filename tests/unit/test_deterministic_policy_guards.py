"""Deterministic guards for policy engine behavior — Issue #248 / Parent #214.

These tests verify that the policy engine collects ALL violations, not just
the first deny. They use @pytest.mark.xfail to document known deterministic
bugs without breaking the build.

#248: Add deterministic rule for #214: Policy engine short-circuits on first deny
#214: Policy engine short-circuits on first deny without collecting all violations
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from caliper.core.models import (
    DecisionVerdict,
    Finding,
    FindingCategory,
    FindingSeverity,
)
from caliper.core.policy import OpaEvaluator


def _mock_subprocess_run(stdout: str, returncode: int = 0) -> MagicMock:
    """Create a mock CompletedProcess for OPA output."""
    mock = MagicMock()
    mock.stdout = stdout
    mock.returncode = returncode
    return mock


def _opa_json_output(
    deny: list[str] | None = None,
    warn: list[str] | None = None,
    decision: str = "approve",
) -> str:
    """Build a mock OPA JSON output string."""
    import json

    result = {
        "result": [
            {
                "expressions": [
                    {
                        "value": {
                            "deny": deny or [],
                            "warn": warn or [],
                            "decision": decision,
                        },
                        "text": "data.policy",
                        "location": {"row": 1, "col": 1},
                    }
                ]
            }
        ]
    }
    return json.dumps(result)


def _vuln_finding(
    severity: str = "high",
    advisory_id: str = "CVE-2024-1234",
    pkg: str = "lodash",
    version: str = "4.17.20",
) -> Finding:
    return Finding(
        severity=FindingSeverity(severity),
        category=FindingCategory.vulnerability,
        description=f"Test vuln {advisory_id}",
        source_tool="osv-scanner",
        package_name=pkg,
        version=version,
        advisory_id=advisory_id,
    )


class TestPolicyEngineShortCircuitBug:
    """Tests for Issue #214: Policy engine short-circuits on first deny.

    These tests verify that when multiple policy violations exist,
    ALL are collected in triggered_rules, not just the first one.
    """

    @pytest.mark.xfail(reason="deterministic bug detector for #214", strict=False)
    def test_all_deny_violations_collected_not_just_first(self) -> None:
        """Detect short-circuit: policy engine should collect ALL deny violations.

        Expected behavior: When OPA returns multiple deny messages (e.g., from
        critical_vuln, forbidden_license, malicious_package rules), ALL should
        be present in triggered_rules.

        Bug #214: The policy engine may short-circuit and only return the first
        deny violation, masking other critical issues.
        """
        findings = [
            _vuln_finding(severity="critical", advisory_id="CVE-2024-1111"),
            _vuln_finding(severity="high", advisory_id="CVE-2024-2222"),
        ]
        metadata = {"name": "test-pkg", "version": "1.0.0", "ecosystem": "pypi"}

        # Simulate OPA returning multiple deny violations
        opa_output = _opa_json_output(
            deny=[
                "CRITICAL vulnerability CVE-2024-1111 in lodash@4.17.20",
                "HIGH vulnerability CVE-2024-2222 in lodash@4.17.20",
                "Forbidden license GPL-3.0 in test-pkg@1.0.0",
            ],
            decision="reject",
        )

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch("subprocess.run", return_value=_mock_subprocess_run(opa_output)):
            result = evaluator.evaluate(findings, metadata)

        # The bug: only the first deny is captured, not all 3
        assert result.decision == DecisionVerdict.reject
        assert len(result.triggered_rules) == 3, (
            f"Expected 3 triggered_rules but got {len(result.triggered_rules)}. "
            f"This indicates short-circuit behavior where only the first deny "
            f"is collected. triggered_rules={result.triggered_rules}"
        )
        assert all(
            msg in result.triggered_rules
            for msg in [
                "CRITICAL vulnerability CVE-2024-1111 in lodash@4.17.20",
                "HIGH vulnerability CVE-2024-2222 in lodash@4.17.20",
                "Forbidden license GPL-3.0 in test-pkg@1.0.0",
            ]
        )

    @pytest.mark.xfail(reason="deterministic bug detector for #214", strict=False)
    def test_all_warn_violations_collected_not_just_first(self) -> None:
        """Detect short-circuit: policy engine should collect ALL warn violations.

        Expected behavior: When OPA returns multiple warn messages (e.g., from
        transitive_count, medium_vuln rules), ALL should be present in triggered_rules.

        Bug #214 variant: The policy engine may short-circuit and only return the first
        warn violation when no deny rules fire.
        """
        findings = [
            _vuln_finding(severity="medium", advisory_id="CVE-2024-3333"),
        ]
        metadata = {
            "name": "test-pkg",
            "version": "1.0.0",
            "ecosystem": "pypi",
            "transitive_dep_count": 250,
        }

        # Simulate OPA returning multiple warn violations (no deny)
        opa_output = _opa_json_output(
            deny=[],
            warn=[
                "Medium vulnerability CVE-2024-3333 in lodash@4.17.20",
                "Transitive dependency count 250 exceeds threshold 200 for test-pkg@1.0.0",
            ],
            decision="approve_with_constraints",
        )

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch("subprocess.run", return_value=_mock_subprocess_run(opa_output)):
            result = evaluator.evaluate(findings, metadata)

        # The bug: only the first warn is captured, not both
        assert result.decision == DecisionVerdict.approve_with_constraints
        assert len(result.triggered_rules) == 2, (
            f"Expected 2 triggered_rules but got {len(result.triggered_rules)}. "
            f"This indicates short-circuit behavior where only the first warn "
            f"is collected. triggered_rules={result.triggered_rules}"
        )
        assert all(
            msg in result.triggered_rules
            for msg in [
                "Medium vulnerability CVE-2024-3333 in lodash@4.17.20",
                "Transitive dependency count 250 exceeds threshold 200 for test-pkg@1.0.0",
            ]
        )

    @pytest.mark.xfail(reason="deterministic bug detector for #214", strict=False)
    def test_mixed_deny_and_warn_all_collected(self) -> None:
        """Detect short-circuit: when both deny and warn fire, collect ALL.

        Expected behavior: When some rules deny and others warn, ALL violations
        should appear in triggered_rules.

        Bug #214 variant: The policy engine may short-circuit on first deny and
        ignore subsequent warn violations.
        """
        findings = [
            _vuln_finding(severity="critical", advisory_id="CVE-2024-4444"),
            _vuln_finding(severity="medium", advisory_id="CVE-2024-5555"),
        ]
        metadata = {"name": "test-pkg", "version": "1.0.0", "ecosystem": "pypi"}

        # Simulate OPA returning both deny and warn violations
        opa_output = _opa_json_output(
            deny=["CRITICAL vulnerability CVE-2024-4444 in lodash@4.17.20"],
            warn=["Medium vulnerability CVE-2024-5555 in lodash@4.17.20"],
            decision="reject",
        )

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch("subprocess.run", return_value=_mock_subprocess_run(opa_output)):
            result = evaluator.evaluate(findings, metadata)

        # The bug: warns are dropped when deny fires (short-circuit)
        assert result.decision == DecisionVerdict.reject
        assert len(result.triggered_rules) == 2, (
            f"Expected 2 triggered_rules (1 deny + 1 warn) but got "
            f"{len(result.triggered_rules)}. Short-circuit may have dropped "
            f"warn violations. triggered_rules={result.triggered_rules}"
        )
        assert "CRITICAL vulnerability CVE-2024-4444 in lodash@4.17.20" in result.triggered_rules
        assert "Medium vulnerability CVE-2024-5555 in lodash@4.17.20" in result.triggered_rules


class TestPolicyEngineViolationSetSemantics:
    """Tests verifying set-based semantics for policy violations."""

    @pytest.mark.xfail(reason="deterministic bug detector for #214", strict=False)
    def test_duplicate_violations_deduplicated(self) -> None:
        """Policy violations should use set semantics (no duplicates).

        If the same violation is triggered by multiple rules or the same rule
        with different findings, it should appear only once in triggered_rules.
        """
        findings = [
            _vuln_finding(severity="critical", advisory_id="CVE-2024-6666"),
        ]
        metadata = {"name": "test-pkg", "version": "1.0.0", "ecosystem": "pypi"}

        # Simulate OPA returning duplicate deny messages (shouldn't happen
        # but tests that Python side handles it correctly with set semantics)
        opa_output = _opa_json_output(
            deny=[
                "CRITICAL vulnerability CVE-2024-6666 in lodash@4.17.20",
                "CRITICAL vulnerability CVE-2024-6666 in lodash@4.17.20",  # duplicate
            ],
            decision="reject",
        )

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch("subprocess.run", return_value=_mock_subprocess_run(opa_output)):
            result = evaluator.evaluate(findings, metadata)

        # Either duplicates are collapsed (set semantics) or preserved (list semantics)
        # This test documents current behavior - should be 1 if deduplicated
        assert len(result.triggered_rules) == 1, (
            f"Expected 1 unique triggered_rule but got {len(result.triggered_rules)}. "
            f"Duplicate violations should be deduplicated. "
            f"triggered_rules={result.triggered_rules}"
        )
