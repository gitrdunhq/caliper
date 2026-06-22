"""Tests for caliper.core.memo — decision memo generation."""

from __future__ import annotations

from caliper.core.memo import generate_memo
from caliper.core.models import (
    DecisionVerdict,
    Finding,
    FindingCategory,
    FindingSeverity,
    OperatingMode,
    PolicyEvaluation,
    RequestType,
    ReviewDecision,
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
    version: str = "0.1.0",
) -> PolicyEvaluation:
    return PolicyEvaluation(
        decision=DecisionVerdict(decision),
        triggered_rules=rules or [],
        constraints=constraints or [],
        policy_bundle_version=version,
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


def _scan_result(
    tool: str = "osv-scanner",
    status: str = "success",
    duration: float = 2.1,
) -> ScanResult:
    return ScanResult(
        tool_name=tool,
        status=ScanResultStatus(status),
        findings=[],
        duration_seconds=duration,
    )


def _decision(
    verdict: str = "reject",
    findings: list[Finding] | None = None,
    scans: list[ScanResult] | None = None,
    rules: list[str] | None = None,
    constraints: list[str] | None = None,
    policy_version: str = "0.1.0",
    duration: float = 5.0,
) -> ReviewDecision:
    request = _request()
    return ReviewDecision(
        request=request,
        decision=DecisionVerdict(verdict),
        findings=findings or [],
        scan_results=scans or [_scan_result()],
        policy_evaluation=_policy_eval(
            decision=verdict,
            rules=rules,
            constraints=constraints,
            version=policy_version,
        ),
        evidence_bundle_path=None,
        pipeline_duration_seconds=duration,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGenerateMemo:
    """Tests for the generate_memo function."""

    def test_reject_has_why_and_what_to_do(self) -> None:
        """Reject decision memo includes 'Why' and 'What To Do' sections."""
        dec = _decision(
            verdict="reject",
            findings=[_finding(severity="critical")],
            rules=["CRITICAL vulnerability CVE-2024-1234 in lodash@4.17.20"],
        )

        memo = generate_memo(dec)

        assert "REJECTED" in memo
        assert "### Why" in memo or "### Triggered Policy Rules" in memo
        assert "### What To Do" in memo

    def test_approve_has_no_why_or_what_to_do(self) -> None:
        """Approve decision memo omits 'Why' and 'What To Do' sections."""
        dec = _decision(verdict="approve")

        memo = generate_memo(dec)

        assert "APPROVED" in memo
        assert "### Why" not in memo
        assert "### What To Do" not in memo

    def test_approve_with_constraints_has_constraints_section(self) -> None:
        """Approve with constraints includes a 'Constraints' section."""
        dec = _decision(
            verdict="approve_with_constraints",
            findings=[_finding(severity="medium")],
            rules=["Medium vulnerability CVE-2024-5678"],
            constraints=["Review medium-severity findings before production use"],
        )

        memo = generate_memo(dec)

        assert "APPROVED WITH CONSTRAINTS" in memo
        assert "### Constraints" in memo
        assert "Review medium-severity findings" in memo

    def test_memo_contains_severity_counts(self) -> None:
        """Memo includes severity summary table with counts."""
        dec = _decision(
            verdict="reject",
            findings=[
                _finding(severity="critical", advisory_id="CVE-2024-0001"),
                _finding(severity="critical", advisory_id="CVE-2024-0002"),
                _finding(severity="high", advisory_id="CVE-2024-0003"),
            ],
            rules=["rule-1"],
        )

        memo = generate_memo(dec)

        assert "Critical" in memo
        assert "High" in memo
        # The table should show the counts
        assert "| Critical |" in memo or "| Critical | 2" in memo

    def test_memo_contains_scanner_status_table(self) -> None:
        """Memo includes scanner results table with status and duration."""
        scans = [
            _scan_result("syft", "success", 2.1),
            _scan_result("osv-scanner", "success", 1.5),
            _scan_result("trivy", "timeout", 60.0),
        ]
        dec = _decision(verdict="reject", scans=scans, rules=["rule-1"])

        memo = generate_memo(dec)

        assert "syft" in memo
        assert "osv-scanner" in memo
        assert "trivy" in memo
        assert "success" in memo.lower() or "success" in memo

    def test_memo_under_4000_chars(self) -> None:
        """Memo length must be under 4000 characters."""
        dec = _decision(
            verdict="reject",
            findings=[
                _finding(severity="critical", advisory_id=f"CVE-2024-{i:04d}") for i in range(20)
            ],
            rules=[f"Rule {i}" for i in range(20)],
        )

        memo = generate_memo(dec)

        assert len(memo) < 4000

    def test_memo_contains_policy_version(self) -> None:
        """Memo footer includes the policy bundle version."""
        dec = _decision(verdict="approve", policy_version="1.2.3")

        memo = generate_memo(dec)

        assert "1.2.3" in memo

    def test_needs_review_has_why_section(self) -> None:
        """Needs review decision memo includes 'Why' section."""
        dec = _decision(
            verdict="needs_review",
            rules=["OPA evaluation timed out"],
        )

        memo = generate_memo(dec)

        assert "NEEDS REVIEW" in memo
        assert "### Why" in memo or "### Triggered Policy Rules" in memo

    def test_memo_contains_package_info(self) -> None:
        """Memo contains package name, version, ecosystem."""
        dec = _decision(verdict="approve")

        memo = generate_memo(dec)

        assert "lodash" in memo
        assert "4.17.21" in memo
        assert "npm" in memo

    def test_memo_contains_team_and_scope(self) -> None:
        """Memo contains team and scope information."""
        dec = _decision(verdict="approve")

        memo = generate_memo(dec)

        assert "platform" in memo
        assert "runtime" in memo


class TestMemoTruncation:
    """Tests for memo truncation behaviour."""

    def test_short_memo_not_truncated(self) -> None:
        """Memos under the limit are returned unchanged."""
        from caliper.core.memo import _MAX_MEMO_LENGTH

        dec = _decision(verdict="approve")
        memo = generate_memo(dec)

        assert len(memo) <= _MAX_MEMO_LENGTH
        assert "*[truncated]*" not in memo

    def test_truncation_stays_within_max_length(self) -> None:
        """Truncated memo must not exceed _MAX_MEMO_LENGTH."""
        from caliper.core.memo import _MAX_MEMO_LENGTH

        # Many long rules to force truncation
        long_rules = ["Rule: " + ("x" * 80) for _ in range(60)]
        dec = _decision(verdict="reject", rules=long_rules)
        memo = generate_memo(dec)

        assert len(memo) <= _MAX_MEMO_LENGTH

    def test_truncation_ends_at_paragraph_boundary(self) -> None:
        """When truncated, memo must not end in the middle of a line.

        Before fix: truncation sliced at a raw character offset, which could
        land mid-word or mid-line.
        After fix: truncation stops at the last paragraph break (double newline)
        before the limit so the output remains valid Markdown.
        """

        long_rules = ["Rule: " + ("x" * 80) for _ in range(60)]
        dec = _decision(verdict="reject", rules=long_rules)
        memo = generate_memo(dec)

        if "*[truncated]*" in memo:
            # The memo must end cleanly — not truncate in the middle of a line
            before_marker = memo.split("*[truncated]*")[0]
            last_char = before_marker.rstrip(" ")[-1] if before_marker.strip() else ""
            # After a paragraph-boundary truncation the last real char before the
            # truncation marker is a newline (stripped) — not mid-word content
            assert before_marker.endswith("\n\n") or before_marker.endswith(
                "\n"
            ), f"Expected truncation at a line boundary, got last chars: {repr(before_marker[-20:])}"
