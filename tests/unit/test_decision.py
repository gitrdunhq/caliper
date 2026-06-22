"""Tests for caliper.core.decision — decision assembly."""

from __future__ import annotations

from caliper.core.decision import assemble_decision
from caliper.core.models import (
    DecisionVerdict,
    Finding,
    FindingCategory,
    FindingSeverity,
    OperatingMode,
    PolicyEvaluation,
    RequestType,
    ReviewRequest,
    ScanResult,
    ScanResultStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _request(mode: str = "advise") -> ReviewRequest:
    return ReviewRequest(
        request_type=RequestType.new_package,
        ecosystem="npm",
        package_name="lodash",
        target_version="4.17.21",
        team="platform",
        scope="runtime",
        operating_mode=OperatingMode(mode),
    )


def _policy_eval(
    decision: str = "approve",
    rules: list[str] | None = None,
    constraints: list[str] | None = None,
) -> PolicyEvaluation:
    return PolicyEvaluation(
        decision=DecisionVerdict(decision),
        triggered_rules=rules or [],
        constraints=constraints or [],
        policy_bundle_version="0.1.0",
    )


def _finding(severity: str = "high", advisory_id: str = "CVE-2024-1234") -> Finding:
    return Finding(
        severity=FindingSeverity(severity),
        category=FindingCategory.vulnerability,
        description=f"Test vuln {advisory_id}",
        source_tool="osv-scanner",
        package_name="lodash",
        version="4.17.20",
        advisory_id=advisory_id,
    )


def _scan_result(tool: str = "osv-scanner", status: str = "success") -> ScanResult:
    return ScanResult(
        tool_name=tool,
        status=ScanResultStatus(status),
        findings=[],
        duration_seconds=1.5,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAssembleDecision:
    """Tests for the assemble_decision function."""

    def test_policy_reject_advise_mode(self) -> None:
        """Policy reject in advise mode: should_comment=True, should_mark_unstable=True."""
        request = _request(mode="advise")
        policy = _policy_eval(
            decision="reject",
            rules=["CRITICAL vulnerability CVE-2024-1234 in lodash@4.17.20"],
        )
        findings = [_finding()]
        scans = [_scan_result()]

        result = assemble_decision(
            request=request,
            findings=findings,
            scan_results=scans,
            policy_evaluation=policy,
            evidence_bundle_path="/evidence/bundle.tar.gz",
            pipeline_duration=5.2,
        )

        assert result.decision == DecisionVerdict.reject
        assert result.should_comment is True
        assert result.should_mark_unstable is True
        assert result.evidence_bundle_path == "/evidence/bundle.tar.gz"

    def test_policy_approve_monitor_mode(self) -> None:
        """Policy approve in monitor mode: should_comment=False, should_mark_unstable=False."""
        request = _request(mode="monitor")
        policy = _policy_eval(decision="approve")

        result = assemble_decision(
            request=request,
            findings=[],
            scan_results=[_scan_result()],
            policy_evaluation=policy,
            evidence_bundle_path=None,
            pipeline_duration=2.0,
        )

        assert result.decision == DecisionVerdict.approve
        assert result.should_comment is False
        assert result.should_mark_unstable is False

    def test_policy_needs_review(self) -> None:
        """Policy needs_review maps to decision needs_review."""
        request = _request(mode="advise")
        policy = _policy_eval(decision="needs_review")

        result = assemble_decision(
            request=request,
            findings=[],
            scan_results=[_scan_result()],
            policy_evaluation=policy,
            evidence_bundle_path=None,
            pipeline_duration=3.5,
        )

        assert result.decision == DecisionVerdict.needs_review
        assert result.should_comment is True
        assert result.should_mark_unstable is True

    def test_policy_approve_with_constraints_advise_mode(self) -> None:
        """Approve with constraints in advise mode: comment=True, mark_unstable=False."""
        request = _request(mode="advise")
        policy = _policy_eval(
            decision="approve_with_constraints",
            rules=["Medium vulnerability CVE-2024-5678"],
            constraints=["Review medium-severity findings before production use"],
        )

        result = assemble_decision(
            request=request,
            findings=[_finding(severity="medium", advisory_id="CVE-2024-5678")],
            scan_results=[_scan_result()],
            policy_evaluation=policy,
            evidence_bundle_path=None,
            pipeline_duration=4.0,
        )

        assert result.decision == DecisionVerdict.approve_with_constraints
        assert result.should_comment is True
        assert result.should_mark_unstable is False

    def test_pipeline_duration_captured(self) -> None:
        """Pipeline duration is correctly recorded in the decision."""
        request = _request()
        policy = _policy_eval(decision="approve")

        result = assemble_decision(
            request=request,
            findings=[],
            scan_results=[_scan_result()],
            policy_evaluation=policy,
            evidence_bundle_path=None,
            pipeline_duration=12.345,
        )

        assert result.pipeline_duration_seconds == 12.345

    def test_all_fields_assembled(self) -> None:
        """All fields from inputs appear in the assembled decision."""
        request = _request()
        findings = [_finding()]
        scans = [_scan_result("osv-scanner"), _scan_result("trivy")]
        policy = _policy_eval(decision="reject", rules=["rule-1"])

        result = assemble_decision(
            request=request,
            findings=findings,
            scan_results=scans,
            policy_evaluation=policy,
            evidence_bundle_path="/evidence/test.tar.gz",
            pipeline_duration=7.7,
        )

        assert result.request == request
        assert result.findings == findings
        assert len(result.scan_results) == 2
        assert result.policy_evaluation == policy
        assert result.evidence_bundle_path == "/evidence/test.tar.gz"
