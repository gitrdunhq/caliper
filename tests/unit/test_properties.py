"""Property-based tests for Dependency Review invariants.

# tested-by: tests/unit/test_properties.py

Tests use Hypothesis @given strategies to verify system invariants that must
hold for all inputs, not just hand-picked examples.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.diff import _parse_requirements
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
from caliper.core.normalizer import _SEVERITY_RANK, normalize_findings
from caliper.data.alternatives import categorize_package
from caliper.data.scanners.osv import _cvss_score_to_severity

# ---------------------------------------------------------------------------
# Reusable strategies — refactored using @st.composite for clarity
# ---------------------------------------------------------------------------


@st.composite
def _finding_strategy(draw: st.DrawFn) -> Finding:
    """Build a Finding with drawn values for property testing."""
    return Finding(
        severity=draw(st.sampled_from(list(FindingSeverity))),
        category=draw(st.sampled_from(list(FindingCategory))),
        description=draw(st.text(min_size=1, max_size=100)),
        source_tool=draw(st.text(min_size=1, max_size=20)),
        package_name=draw(st.text(min_size=1, max_size=50)),
        version=draw(st.text(min_size=1, max_size=20)),
        advisory_id=draw(st.one_of(st.none(), st.text(min_size=1, max_size=20))),
    )


@st.composite
def _scan_result_strategy(draw: st.DrawFn) -> ScanResult:
    """Build a ScanResult with drawn values for property testing."""
    return ScanResult(
        tool_name=draw(st.text(min_size=1, max_size=20)),
        status=draw(st.sampled_from(list(ScanResultStatus))),
        findings=draw(st.lists(_finding_strategy(), min_size=0, max_size=10)),
        duration_seconds=draw(
            st.floats(min_value=0.0, max_value=60.0, allow_nan=False, allow_infinity=False)
        ),
        message=draw(st.one_of(st.none(), st.text(max_size=100))),
    )


# Non-license categories — findings with these go through the dedup path
_non_license_categories = [c for c in FindingCategory if c != FindingCategory.license]


def _build_decision(
    mode: OperatingMode,
    verdict: DecisionVerdict,
    findings: list[Finding],
    triggered_rules: list[str],
    scan_results: list[ScanResult] | None = None,
) -> ReviewDecision:
    """Build a minimal ReviewDecision for property testing."""
    request = ReviewRequest(
        request_type=RequestType.new_package,
        ecosystem="pypi",
        package_name="test-pkg",
        target_version="1.0.0",
        team="test-team",
        operating_mode=mode,
    )
    policy_eval = PolicyEvaluation(
        decision=verdict,
        triggered_rules=triggered_rules,
        policy_bundle_version="1.0.0",
    )
    return ReviewDecision(
        request=request,
        decision=verdict,
        findings=findings,
        scan_results=scan_results or [],
        policy_evaluation=policy_eval,
        pipeline_duration_seconds=1.0,
    )


# ---------------------------------------------------------------------------
# 1. CVSS score → severity is monotonically non-decreasing
# ---------------------------------------------------------------------------


@given(score=st.floats(min_value=0.0, max_value=10.0, allow_nan=False))
@settings(max_examples=200)
def test_cvss_severity_monotonic(score: float) -> None:
    """Higher CVSS scores must never produce lower severity (NVD thresholds)."""
    sev = _cvss_score_to_severity(score)
    if score >= 9.0:
        assert sev == FindingSeverity.critical
    elif score >= 7.0:
        assert sev == FindingSeverity.high
    elif score >= 4.0:
        assert sev == FindingSeverity.medium
    else:
        assert sev == FindingSeverity.low


# ---------------------------------------------------------------------------
# 2. Normalizer never increases finding count
# ---------------------------------------------------------------------------


@given(scan_results=st.lists(_scan_result_strategy(), min_size=0, max_size=10))
@settings(max_examples=200)
def test_normalize_never_adds_findings(scan_results: list[ScanResult]) -> None:
    """Normalization can only reduce or maintain finding count, never increase it.

    Deduplication collapses multiple findings with the same key into one.
    Non-license findings are deduplicated; license findings are kept as-is.
    Either way, output count cannot exceed input count.
    """
    total_input = sum(len(r.findings) for r in scan_results)
    merged, _ = normalize_findings(scan_results)
    assert len(merged) <= total_input


# ---------------------------------------------------------------------------
# 3. Normalizer dedup keeps highest severity
# ---------------------------------------------------------------------------


@given(
    pkg_name=st.text(min_size=1, max_size=30),
    version=st.text(min_size=1, max_size=20),
    category=st.sampled_from(_non_license_categories),
    advisory_id=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
    sev1=st.sampled_from(list(FindingSeverity)),
    sev2=st.sampled_from(list(FindingSeverity)),
)
@settings(max_examples=200)
def test_dedup_keeps_higher_severity(
    pkg_name: str,
    version: str,
    category: FindingCategory,
    advisory_id: str | None,
    sev1: FindingSeverity,
    sev2: FindingSeverity,
) -> None:
    """When two findings share a dedup key, the higher severity survives.

    The dedup key is (advisory_id, category, package_name, version).
    When keys collide, the finding with the higher _SEVERITY_RANK wins.
    If ranks are equal, the first-encountered finding is retained.
    """
    finding1 = Finding(
        severity=sev1,
        category=category,
        description="first finding",
        source_tool="tool-a",
        package_name=pkg_name,
        version=version,
        advisory_id=advisory_id,
    )
    finding2 = Finding(
        severity=sev2,
        category=category,
        description="second finding",
        source_tool="tool-b",
        package_name=pkg_name,
        version=version,
        advisory_id=advisory_id,
    )

    scan_results = [
        ScanResult(
            tool_name="tool-a",
            status=ScanResultStatus.success,
            findings=[finding1],
            duration_seconds=1.0,
        ),
        ScanResult(
            tool_name="tool-b",
            status=ScanResultStatus.success,
            findings=[finding2],
            duration_seconds=1.0,
        ),
    ]
    merged, _ = normalize_findings(scan_results)

    # Exactly one finding survives because both share the same dedup key
    assert len(merged) == 1

    rank1 = _SEVERITY_RANK[sev1]
    rank2 = _SEVERITY_RANK[sev2]
    # When ranks are equal, first-encountered (sev1) is kept (strict > condition)
    expected_sev = sev1 if rank1 >= rank2 else sev2
    assert merged[0].severity == expected_sev


# ---------------------------------------------------------------------------
# 4. Decision memo is always under 4000 chars
# ---------------------------------------------------------------------------


@given(
    mode=st.sampled_from(list(OperatingMode)),
    verdict=st.sampled_from(list(DecisionVerdict)),
    findings=st.lists(_finding_strategy(), min_size=0, max_size=100),
    triggered_rules=st.lists(st.text(min_size=1, max_size=200), min_size=0, max_size=50),
)
@settings(max_examples=200)
def test_memo_always_under_limit(
    mode: OperatingMode,
    verdict: DecisionVerdict,
    findings: list[Finding],
    triggered_rules: list[str],
) -> None:
    """Memo must stay under 4000 characters regardless of finding/rule count.

    The memo truncates at _MAX_MEMO_LENGTH (3900) and appends a truncation
    marker, so the absolute maximum output length is _MAX_MEMO_LENGTH chars.
    """
    decision = _build_decision(mode, verdict, findings, triggered_rules)
    memo = generate_memo(decision)
    assert len(memo) <= _MAX_MEMO_LENGTH
    assert len(memo) < 4000


# ---------------------------------------------------------------------------
# 5. Decision assembly preserves operating mode semantics
# ---------------------------------------------------------------------------


@given(
    mode=st.sampled_from(list(OperatingMode)),
    verdict=st.sampled_from(list(DecisionVerdict)),
)
@settings(max_examples=200)
def test_monitor_mode_never_comments(mode: OperatingMode, verdict: DecisionVerdict) -> None:
    """Monitor mode must never set should_comment=True regardless of verdict."""
    decision = _build_decision(mode, verdict, [], [])
    if mode == OperatingMode.monitor:
        assert decision.should_comment is False
        assert decision.should_mark_unstable is False


@given(verdict=st.sampled_from(list(DecisionVerdict)))
@settings(max_examples=200)
def test_advise_mode_comments_on_non_approve(verdict: DecisionVerdict) -> None:
    """Advise mode must comment on reject, needs_review, and approve_with_constraints.

    Only the bare 'approve' verdict suppresses the PR comment in advise mode.
    """
    decision = _build_decision(OperatingMode.advise, verdict, [], [])
    if verdict == DecisionVerdict.approve:
        assert decision.should_comment is False
    else:
        assert decision.should_comment is True


# ---------------------------------------------------------------------------
# 6. All ScanResult factory methods produce valid status
# ---------------------------------------------------------------------------


@given(
    name=st.text(min_size=1, max_size=50),
    timeout_sec=st.integers(min_value=1, max_value=3600),
)
@settings(max_examples=200)
def test_scan_result_timeout_has_timeout_status(name: str, timeout_sec: int) -> None:
    """ScanResult.timeout must produce status=timeout with correct tool_name and no findings."""
    result = ScanResult.timeout(name, timeout_sec)
    assert result.status == ScanResultStatus.timeout
    assert result.tool_name == name
    assert result.findings == []


@given(
    name=st.text(min_size=1, max_size=50),
    message=st.text(min_size=1, max_size=200),
)
@settings(max_examples=200)
def test_scan_result_failed_has_failed_status(name: str, message: str) -> None:
    """ScanResult.failed must produce status=failed with correct tool_name and no findings."""
    result = ScanResult.failed(name, message)
    assert result.status == ScanResultStatus.failed
    assert result.tool_name == name
    assert result.findings == []


@given(name=st.text(min_size=1, max_size=50))
@settings(max_examples=200)
def test_scan_result_not_installed_has_failed_status(name: str) -> None:
    """ScanResult.not_installed must produce status=failed with a not-installed message."""
    result = ScanResult.not_installed(name)
    assert result.status == ScanResultStatus.failed
    assert result.tool_name == name
    assert result.findings == []
    assert result.message is not None
    assert "not installed" in result.message.lower()


@given(
    name=st.text(min_size=1, max_size=50),
    message=st.text(min_size=1, max_size=200),
)
@settings(max_examples=200)
def test_scan_result_skipped_has_skipped_status(name: str, message: str) -> None:
    """ScanResult.skipped must produce status=skipped with correct tool_name and no findings."""
    result = ScanResult.skipped(name, message)
    assert result.status == ScanResultStatus.skipped
    assert result.tool_name == name
    assert result.findings == []


# ---------------------------------------------------------------------------
# 7. Requirements parsing round-trips
# ---------------------------------------------------------------------------


@given(
    packages=st.lists(
        st.from_regex(r"[a-z][a-z0-9-]{0,20}", fullmatch=True),
        min_size=1,
        max_size=20,
    )
)
@settings(max_examples=200)
def test_requirements_parse_round_trip(packages: list[str]) -> None:
    """Packages written as requirements.txt pin lines should all be extractable.

    Each unique package name written as 'name==1.0.0' must appear as a key
    in the dict returned by _parse_requirements.
    """
    content = "\n".join(f"{pkg}==1.0.0" for pkg in packages)
    parsed = _parse_requirements(content)
    # All unique package names from input must appear in the parsed output
    assert set(packages) == set(parsed.keys())


# ---------------------------------------------------------------------------
# 8. Package categorization is stable (deterministic)
# ---------------------------------------------------------------------------


@given(name=st.text(min_size=1, max_size=50))
@settings(max_examples=200)
def test_categorize_is_deterministic(name: str) -> None:
    """Same package name always gets the same category.

    categorize_package is a pure function backed by a static lookup table
    with a deterministic 'unknown' fallback — no state, no I/O.
    """
    cat1 = categorize_package(name)
    cat2 = categorize_package(name)
    assert cat1 == cat2
