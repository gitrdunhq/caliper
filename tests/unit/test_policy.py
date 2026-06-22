"""Tests for caliper.core.policy — OPA evaluation wrapper."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from caliper.core.models import (
    DecisionVerdict,
    Finding,
    FindingCategory,
    FindingSeverity,
)
from caliper.core.policy import OpaEvaluator, build_opa_input

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


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


def _opa_json_output(
    deny: list[str] | None = None,
    warn: list[str] | None = None,
    decision: str = "approve",
) -> str:
    """Build a mock OPA JSON output string."""
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


def _mock_subprocess_run(stdout: str, returncode: int = 0) -> MagicMock:
    """Create a mock CompletedProcess."""
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.stdout = stdout
    mock.returncode = returncode
    return mock


# ---------------------------------------------------------------------------
# OPA returns deny -> decision is reject
# ---------------------------------------------------------------------------


class TestOpaEvaluator:
    """Tests for the OpaEvaluator class."""

    def test_opa_deny_returns_reject(self) -> None:
        """When OPA returns deny messages, decision should be reject."""
        findings = [_vuln_finding()]
        metadata = {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
        opa_output = _opa_json_output(
            deny=["CRITICAL vulnerability CVE-2024-1234 in lodash@4.17.20"],
            decision="reject",
        )

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch("subprocess.run", return_value=_mock_subprocess_run(opa_output)):
            result = evaluator.evaluate(findings, metadata)

        assert result.decision == DecisionVerdict.reject
        assert len(result.triggered_rules) > 0

    def test_opa_allow_returns_approve(self) -> None:
        """When OPA returns no deny and no warn, decision should be approve."""
        findings: list[Finding] = []
        metadata = {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}
        opa_output = _opa_json_output(deny=[], warn=[], decision="approve")

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch("subprocess.run", return_value=_mock_subprocess_run(opa_output)):
            result = evaluator.evaluate(findings, metadata)

        assert result.decision == DecisionVerdict.approve
        assert result.triggered_rules == []

    def test_opa_warn_returns_approve_with_constraints(self) -> None:
        """When OPA returns warn but no deny, decision is approve_with_constraints."""
        findings = [_vuln_finding(severity="medium")]
        metadata = {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
        opa_output = _opa_json_output(
            warn=["Medium vulnerability CVE-2024-1234 in lodash@4.17.20"],
            decision="approve_with_constraints",
        )

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch("subprocess.run", return_value=_mock_subprocess_run(opa_output)):
            result = evaluator.evaluate(findings, metadata)

        assert result.decision == DecisionVerdict.approve_with_constraints
        assert len(result.constraints) > 0 or len(result.triggered_rules) > 0

    def test_opa_timeout_returns_needs_review(self) -> None:
        """When OPA times out, decision should be needs_review with note."""
        findings = [_vuln_finding()]
        metadata = {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}

        evaluator = OpaEvaluator(policy_path="/fake/policies", timeout=1)
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="opa", timeout=1),
        ):
            result = evaluator.evaluate(findings, metadata)

        assert result.decision == DecisionVerdict.needs_review
        assert result.note is not None
        assert "timed out" in result.note.lower()

    def test_opa_binary_missing_returns_needs_review(self) -> None:
        """When OPA binary is not found, decision should be needs_review with note."""
        findings = [_vuln_finding()]
        metadata = {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch(
            "subprocess.run",
            side_effect=FileNotFoundError("opa: command not found"),
        ):
            result = evaluator.evaluate(findings, metadata)

        assert result.decision == DecisionVerdict.needs_review
        assert result.note is not None
        assert "not found" in result.note.lower()

    def test_opa_generic_error_returns_needs_review(self) -> None:
        """Any other OPA error should return needs_review with descriptive note."""
        findings = [_vuln_finding()]
        metadata = {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}

        evaluator = OpaEvaluator(policy_path="/fake/policies")
        with patch(
            "subprocess.run",
            side_effect=RuntimeError("Unexpected OPA crash"),
        ):
            result = evaluator.evaluate(findings, metadata)

        assert result.decision == DecisionVerdict.needs_review
        assert result.note is not None
        assert len(result.note) > 0


class TestBuildOpaInput:
    """Tests for the build_opa_input helper."""

    def test_constructs_correct_shape(self) -> None:
        """Input JSON matches the INPUT_SCHEMA.md expected structure."""
        findings = [
            _vuln_finding(),
            Finding(
                severity=FindingSeverity.low,
                category=FindingCategory.license,
                description="GPL-3.0 detected",
                source_tool="scancode",
                package_name="some-lib",
                version="1.0.0",
                license_id="GPL-3.0",
            ),
        ]
        metadata = {
            "name": "lodash",
            "version": "4.17.20",
            "ecosystem": "npm",
            "scope": "runtime",
            "environment_sensitivity": "internet-facing",
            "first_published_date": "2012-04-01T00:00:00Z",
            "transitive_dep_count": 5,
        }

        result = build_opa_input(findings, metadata)

        # Top-level keys
        assert "findings" in result
        assert "pkg" in result
        assert "config" in result

        # Findings shape
        assert len(result["findings"]) == 2
        f0 = result["findings"][0]
        assert f0["severity"] == "high"
        assert f0["category"] == "vulnerability"
        assert f0["advisory_id"] == "CVE-2024-1234"
        assert f0["package_name"] == "lodash"
        assert f0["source_tool"] == "osv-scanner"

        # License finding has license_id
        f1 = result["findings"][1]
        assert f1["license_id"] == "GPL-3.0"

        # Package metadata
        assert result["pkg"]["name"] == "lodash"
        assert result["pkg"]["version"] == "4.17.20"
        assert result["pkg"]["ecosystem"] == "npm"

        # Config has rules_enabled with all defaults true
        rules = result["config"]["rules_enabled"]
        assert rules["critical_vuln"] is True
        assert rules["forbidden_license"] is True
        assert rules["package_age"] is True
        assert rules["malicious_package"] is True
        assert rules["transitive_count"] is True

    def test_custom_config_overrides(self) -> None:
        """Custom config dict merges into the default config."""
        findings: list[Finding] = []
        metadata = {
            "name": "pkg",
            "version": "1.0.0",
            "ecosystem": "pypi",
        }
        custom_config = {
            "forbidden_licenses": ["GPL-3.0", "AGPL-3.0"],
            "max_transitive_deps": 100,
            "rules_enabled": {"critical_vuln": False},
        }

        result = build_opa_input(findings, metadata, config=custom_config)

        assert result["config"]["forbidden_licenses"] == ["GPL-3.0", "AGPL-3.0"]
        assert result["config"]["max_transitive_deps"] == 100
        assert result["config"]["rules_enabled"]["critical_vuln"] is False


# ---------------------------------------------------------------------------
# Security: path traversal in policy_path
# ---------------------------------------------------------------------------


class TestOpaEvaluatorPathTraversal:
    def test_traversal_via_dotdot_rejected(self) -> None:
        """policy_path that escapes the policy_base_dir via ../ must raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir) / "policies"
            policy_dir.mkdir()
            (policy_dir / "safe.rego").write_text("package policy\nallow = true")

            outside = Path(tmpdir) / "malicious.rego"
            outside.write_text("package policy\nallow = false")

            traversal = str(policy_dir / ".." / "malicious.rego")

            with pytest.raises(ValueError, match="outside policy directory"):
                OpaEvaluator(
                    policy_path=traversal,
                    timeout=10,
                    policy_base_dir=str(policy_dir),
                )

    def test_absolute_path_outside_base_rejected(self) -> None:
        """An absolute policy_path outside policy_base_dir must raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir) / "policies"
            policy_dir.mkdir()

            with pytest.raises(ValueError, match="outside policy directory"):
                OpaEvaluator(
                    policy_path="/etc/passwd",
                    timeout=10,
                    policy_base_dir=str(policy_dir),
                )

    def test_valid_path_within_base_accepted(self) -> None:
        """A policy_path inside policy_base_dir must not raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir) / "policies"
            policy_dir.mkdir()
            policy_file = policy_dir / "valid.rego"
            policy_file.write_text("package policy")

            # Must not raise
            evaluator = OpaEvaluator(
                policy_path=str(policy_file),
                timeout=10,
                policy_base_dir=str(policy_dir),
            )
            assert evaluator is not None

    def test_no_policy_base_dir_preserves_existing_behaviour(self) -> None:
        """Without policy_base_dir, OpaEvaluator accepts any path (backward compat)."""
        evaluator = OpaEvaluator(policy_path="/fake/policies")
        assert evaluator is not None
