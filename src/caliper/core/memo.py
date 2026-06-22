"""Decision memo generation — human-readable Markdown for PR comments."""

# tested-by: tests/unit/test_memo.py

from __future__ import annotations

from caliper.core.models import (
    DecisionVerdict,
    FindingSeverity,
    ReviewDecision,
    ScanResultStatus,
)

_VERDICT_BADGE: dict[DecisionVerdict, str] = {
    DecisionVerdict.approve: "🟢 APPROVED",
    DecisionVerdict.reject: "🔴 REJECTED",
    DecisionVerdict.needs_review: "🟡 NEEDS REVIEW",
    DecisionVerdict.approve_with_constraints: "🟠 APPROVED WITH CONSTRAINTS",
}

_STATUS_ICON: dict[ScanResultStatus, str] = {
    ScanResultStatus.success: "✅ success",
    ScanResultStatus.failed: "❌ failed",
    ScanResultStatus.timeout: "⏱️ timeout",
    ScanResultStatus.skipped: "⏭️ skipped",
}

_MAX_MEMO_LENGTH = 3900


def generate_memo(decision: ReviewDecision) -> str:
    req = decision.request
    badge = _VERDICT_BADGE.get(decision.decision, str(decision.decision))
    parts: list[str] = []

    parts.append(f"## {badge}")
    parts.append("")
    parts.append(f"**Package:** {req.package_name}@{req.target_version} ({req.ecosystem})")
    parts.append(f"**Team:** {req.team} | **Scope:** {req.scope}")
    parts.append(f"**Decision:** {decision.decision.value}")
    parts.append("")

    severity_counts: dict[str, int] = {s.value: 0 for s in FindingSeverity}
    for f in decision.findings:
        severity_counts[f.severity.value] += 1

    if any(v > 0 for v in severity_counts.values()):
        parts.append("### Findings Summary")
        parts.append("| Severity | Count |")
        parts.append("|----------|-------|")
        for sev in FindingSeverity:
            count = severity_counts[sev.value]
            if count > 0:
                parts.append(f"| {sev.value.capitalize()} | {count} |")
        parts.append("")

    pol = decision.policy_evaluation
    if pol.triggered_rules:
        parts.append("### Triggered Policy Rules")
        for rule in pol.triggered_rules[:10]:
            parts.append(f"- {rule}")
        if len(pol.triggered_rules) > 10:
            parts.append(f"- ... and {len(pol.triggered_rules) - 10} more")
        parts.append("")

    if decision.scan_results:
        parts.append("### Scanner Results")
        parts.append("| Scanner | Status | Duration |")
        parts.append("|---------|--------|----------|")
        for sr in decision.scan_results:
            status_text = _STATUS_ICON.get(sr.status, sr.status.value)
            parts.append(f"| {sr.tool_name} | {status_text} | {sr.duration_seconds:.1f}s |")
        parts.append("")

    needs_explanation = decision.decision in (
        DecisionVerdict.reject,
        DecisionVerdict.needs_review,
    )

    if needs_explanation:
        parts.append("### Why")
        if pol.triggered_rules:
            for rule in pol.triggered_rules[:5]:
                parts.append(f"- {rule}")
        elif pol.note:
            parts.append(f"- {pol.note}")
        else:
            parts.append("- Policy evaluation triggered a non-approval decision.")
        parts.append("")

        parts.append("### What To Do")
        if decision.decision == DecisionVerdict.reject:
            parts.append("- Review the findings above and address the triggered policy rules.")
            parts.append("- Consider using an approved alternative package if available.")
            parts.append(
                "- If this is a false positive, request an exception through the bypass process."
            )
        else:
            parts.append("- This request requires manual review by a security engineer.")
            parts.append("- The automated policy evaluation could not reach a definitive decision.")
        parts.append("")

    if decision.decision == DecisionVerdict.approve_with_constraints and pol.constraints:
        parts.append("### Constraints")
        for c in pol.constraints:
            parts.append(f"- {c}")
        parts.append("")

    parts.append("---")
    parts.append(
        f"*caliper | Policy v{pol.policy_bundle_version} "
        f"| Pipeline: {decision.pipeline_duration_seconds:.1f}s*"
    )

    memo = "\n".join(parts)
    if len(memo) > _MAX_MEMO_LENGTH:
        memo = memo[: _MAX_MEMO_LENGTH - 20] + "\n\n*[truncated]*"
    return memo
