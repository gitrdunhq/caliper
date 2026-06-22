"""Decision assembly — combines policy evaluation with request context."""

# tested-by: tests/unit/test_decision.py

from __future__ import annotations

from caliper.core.models import (
    Finding,
    PolicyEvaluation,
    ReviewDecision,
    ReviewRequest,
    ScanResult,
)


def assemble_decision(
    request: ReviewRequest,
    findings: list[Finding],
    scan_results: list[ScanResult],
    policy_evaluation: PolicyEvaluation,
    evidence_bundle_path: str | None,
    pipeline_duration: float,
) -> ReviewDecision:
    return ReviewDecision(
        request=request,
        decision=policy_evaluation.decision,
        findings=findings,
        scan_results=scan_results,
        policy_evaluation=policy_evaluation,
        evidence_bundle_path=evidence_bundle_path,
        pipeline_duration_seconds=pipeline_duration,
    )
