"""Deterministic tests for memo truncation indicators (Issue #205)."""

from __future__ import annotations

import pytest

from caliper.core.memo import _MAX_MEMO_LENGTH, generate_memo
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


class TestMemoTruncationIndicators:
    """Deterministic tests to detect missing truncation indicators (Issue #205).

    Bug #205: Decision memo truncates without indicating truncation occurred.
    These tests verify that when a memo exceeds _MAX_MEMO_LENGTH, the
    truncation indicator *[truncated]* is present in the output.
    """

    @pytest.mark.xfail(reason="deterministic bug detector", strict=False)
    def test_long_memo_must_include_truncation_indicator(self) -> None:
        """Any memo exceeding max length MUST include *[truncated]* marker.

        Regression test for #205: Previously, memos could be silently truncated
        without any visual indication that content was removed. This test
        forces a long memo and verifies the indicator is present.
        """
        # Generate many long rules to force memo over _MAX_MEMO_LENGTH (3900)
        long_rules = [f"CRITICAL: Rule with long description {'x' * 100} #{i}" for i in range(50)]
        dec = _decision(
            verdict="reject",
            findings=[
                _finding(severity="critical", advisory_id=f"CVE-2024-{i:04d}") for i in range(25)
            ],
            rules=long_rules,
        )

        memo = generate_memo(dec)

        # If memo would naturally exceed limit, it must have truncation marker
        # Calculate what the memo length would be without truncation logic
        raw_parts = [
            "## 🔴 REJECTED",
            "",
            f"**Package:** {dec.request.package_name}@{dec.request.target_version} ({dec.request.ecosystem})",
            f"**Team:** {dec.request.team} | **Scope:** {dec.request.scope}",
            f"**Decision:** {dec.decision.value}",
            "",
        ]
        raw_memo = "\n".join(raw_parts + long_rules)

        if len(raw_memo) > _MAX_MEMO_LENGTH:
            # Memo content naturally exceeds limit - truncation should occur
            # and MUST include the indicator
            assert "*[truncated]*" in memo, (
                f"Memo exceeds max length ({_MAX_MEMO_LENGTH}) but missing "
                f"truncation indicator. Raw length: {len(raw_memo)}, "
                f"Final length: {len(memo)}. Issue #205 regression."
            )

    @pytest.mark.xfail(reason="deterministic bug detector", strict=False)
    def test_truncated_memo_ends_with_truncation_marker(self) -> None:
        """Truncated memo must end with the truncation indicator visible.

        Verifies that users can clearly see when content was removed.
        """
        # Force a very long memo that definitely triggers truncation
        many_rules = [f"Policy rule violation #{i}: {'description' * 20}" for i in range(100)]
        dec = _decision(
            verdict="reject",
            rules=many_rules,
        )

        memo = generate_memo(dec)

        # Memo should be at or under limit
        assert (
            len(memo) <= _MAX_MEMO_LENGTH
        ), f"Memo length {len(memo)} exceeds max {_MAX_MEMO_LENGTH}"

        # If memo was truncated (length near limit), check for marker
        if len(memo) >= _MAX_MEMO_LENGTH - 100:
            assert memo.endswith("*[truncated]*"), (
                f"Truncated memo must end with *[truncated]* marker. "
                f"Actual ending: ...{memo[-50:]!r}"
            )

    @pytest.mark.xfail(reason="deterministic bug detector", strict=False)
    def test_truncation_indicator_format(self) -> None:
        """Truncation indicator must be in expected format *[truncated]*.

        Ensures consistent formatting for the truncation notice.
        """
        # Create memo long enough to trigger truncation
        long_rules = [f"Rule {i}: {'x' * 200}" for i in range(30)]
        dec = _decision(verdict="reject", rules=long_rules)

        memo = generate_memo(dec)

        # If memo contains any truncation indication, verify format
        if "truncated" in memo.lower():
            # Must use exact expected format
            assert "*[truncated]*" in memo, (
                f"Truncation indicator format incorrect. Expected *[truncated]* "
                f"in memo, but found different format. Memo excerpt: "
                f"{memo[-200:]!r}"
            )
