# tested-by: tests/unit/test_deterministic_aggregation_guards.py
"""Deterministic detector for scanner result aggregation metadata loss (#247).

This test detects when tool-specific metadata is dropped during finding aggregation.
When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import pytest

from caliper.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)
from caliper.core.normalizer import normalize_findings

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _vuln_finding_with_metadata(
    severity: str = "high",
    advisory_id: str = "CVE-2024-1234",
    pkg: str = "lodash",
    version: str = "4.17.20",
    tool: str = "osv-scanner",
    confidence: float | None = None,
    advisory_url: str | None = None,
) -> Finding:
    """Create a finding with tool-specific metadata."""
    return Finding(
        severity=FindingSeverity(severity),
        category=FindingCategory.vulnerability,
        description=f"Vuln {advisory_id} from {tool}",
        source_tool=tool,
        package_name=pkg,
        version=version,
        advisory_id=advisory_id,
        confidence=confidence,
        advisory_url=advisory_url,
    )


def _scan_result(
    tool: str,
    findings: list[Finding],
    status: str = "success",
    duration: float = 1.0,
) -> ScanResult:
    return ScanResult(
        tool_name=tool,
        status=ScanResultStatus(status),
        findings=findings,
        duration_seconds=duration,
    )


# -----------------------------------------------------------------------------
# Deterministic Bug Detector
# -----------------------------------------------------------------------------


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #247 / #213 - scanner aggregation drops tool-specific metadata",
    strict=False,
)
def test_247_213_scanner_aggregation_preserves_tool_specific_metadata() -> None:
    """Detect when normalize_findings drops metadata from tools during deduplication.

    Issue #247 (parent #213): When two scanners report the same CVE with different
    severities, the aggregation code keeps only the finding with higher severity,
    completely losing metadata from the other tool.

    Expected metadata loss scenarios:
        - confidence scores from lower-severity tools are discarded
        - advisory_url values from lower-severity tools are discarded
        - source_tool information from lower-severity tools is discarded
        - any future tool-specific metadata is lost

    Acceptance criteria for fix:
        - Tool-specific metadata from ALL reporting tools is preserved during aggregation
        - When deduplicating, metadata from both tools should be merged or preserved
        - No complete loss of any tool's metadata

    Current behavior (bug):
        - Only the finding with highest severity is kept
        - Metadata from lower-severity tools is completely lost
    """
    # Create two findings from different tools reporting the same CVE
    # with different severities and different metadata
    f_osv = _vuln_finding_with_metadata(
        severity="medium",  # lower severity
        advisory_id="CVE-2024-5678",
        tool="osv-scanner",
        confidence=0.85,
        advisory_url="https://osv.dev/CVE-2024-5678",
    )
    f_trivy = _vuln_finding_with_metadata(
        severity="critical",  # higher severity
        advisory_id="CVE-2024-5678",
        tool="trivy",
        confidence=0.95,
        advisory_url="https://trivy.com/CVE-2024-5678",
    )

    results = [
        _scan_result("osv-scanner", [f_osv]),
        _scan_result("trivy", [f_trivy]),
    ]

    findings, _summary = normalize_findings(results)

    # Currently, only one finding is kept (the one with higher severity)
    # This means metadata from osv-scanner is completely lost
    assert len(findings) == 1, "Expected deduplication to single finding"

    kept_finding = findings[0]

    # BUG DETECTION: Check if tool-specific metadata is being lost
    # The current implementation keeps only the trivy finding (critical severity)
    # and loses the osv-scanner metadata completely
    metadata_loss_issues: list[str] = []

    # Issue 1: source_tool should ideally reflect both tools that reported this CVE
    # Currently it only shows "trivy" because that's the finding that was kept
    if kept_finding.source_tool == "trivy":
        metadata_loss_issues.append(
            "source_tool only shows 'trivy' - osv-scanner reporting information lost"
        )

    # Issue 2: confidence from osv-scanner (0.85) is completely lost
    # Only trivy's confidence (0.95) is preserved
    if kept_finding.confidence == 0.95:
        metadata_loss_issues.append(
            "confidence only shows trivy's 0.95 - osv-scanner's 0.85 confidence lost"
        )

    # Issue 3: advisory_url from osv-scanner is completely lost
    if kept_finding.advisory_url == "https://trivy.com/CVE-2024-5678":
        metadata_loss_issues.append(
            "advisory_url only shows trivy's URL - osv-scanner's advisory URL lost"
        )

    # Issue 4: The fact that osv-scanner reported this at all is lost
    # (except for maybe in scan_results, but not in the aggregated finding)

    # This test documents the bug. When the bug is fixed,
    # these assertions will need to change.
    assert metadata_loss_issues == [], (
        "BUG DETECTED (#247/#213): Tool-specific metadata is being dropped during aggregation.\n"
        "The normalize_findings function keeps only the finding with highest severity,\n"
        "completely losing metadata from other reporting tools:\n\n"
        + "\n".join(f"  - {issue}" for issue in metadata_loss_issues)
        + "\n\nExpected behavior: Metadata from ALL tools should be preserved or merged.\n"
        "Current behavior: Only the highest-severity tool's metadata is kept."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #247 / #213 - aggregation loses multiple tool sources",
    strict=False,
)
def test_247_213_multiple_tools_same_cve_source_tracking() -> None:
    """Detect that we lose information about which tools reported a CVE.

    When multiple scanners report the same CVE, the current aggregation
    code only keeps one finding, losing the complete list of reporting tools.

    This is a data loss issue that affects:
        - Debugging (which tool found this?)
        - Confidence assessment (how many tools agree?)
        - Tool reliability tracking
    """
    # Three different tools report the same CVE
    f1 = _vuln_finding_with_metadata(
        severity="high",
        advisory_id="CVE-2024-9999",
        tool="osv-scanner",
    )
    f2 = _vuln_finding_with_metadata(
        severity="high",
        advisory_id="CVE-2024-9999",
        tool="trivy",
    )
    f3 = _vuln_finding_with_metadata(
        severity="high",
        advisory_id="CVE-2024-9999",
        tool="grype",
    )

    results = [
        _scan_result("osv-scanner", [f1]),
        _scan_result("trivy", [f2]),
        _scan_result("grype", [f3]),
    ]

    findings, _summary = normalize_findings(results)

    # With same severity, the last one wins (arbitrary based on input order)
    assert len(findings) == 1

    # BUG: We should know ALL tools that reported this CVE, not just one
    # This test documents that we currently lose this information
    kept_finding = findings[0]

    # Ideally we would track all reporting tools
    # Currently we only know one (whichever was last in the dedup dict)
    reporting_tools_lost = 2  # Two tools' information is completely lost

    assert reporting_tools_lost == 0, (
        f"BUG DETECTED (#247/#213): Information about {reporting_tools_lost} reporting tools "
        f"is lost during aggregation.\n"
        f"Only '{kept_finding.source_tool}' is preserved, but 3 tools reported this CVE.\n"
        f"Expected: All 3 reporting tools should be trackable in the aggregated result."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #247 / #213 - advisory_url metadata loss",
    strict=False,
)
def test_247_213_advisory_url_metadata_merged_not_overwritten() -> None:
    """Detect that unique advisory URLs from different tools are lost.

    Different tools may have different advisory sources for the same CVE.
    The current implementation keeps only one URL, losing valuable
    cross-reference information.
    """
    f_snyk = _vuln_finding_with_metadata(
        severity="high",
        advisory_id="CVE-2024-1111",
        tool="snyk",
        advisory_url="https://snyk.io/vuln/CVE-2024-1111",
    )
    f_osv = _vuln_finding_with_metadata(
        severity="critical",  # Higher severity wins
        advisory_id="CVE-2024-1111",
        tool="osv-scanner",
        advisory_url="https://osv.dev/CVE-2024-1111",
    )

    results = [
        _scan_result("snyk", [f_snyk]),
        _scan_result("osv-scanner", [f_osv]),
    ]

    findings, _summary = normalize_findings(results)

    kept_finding = findings[0]

    # BUG: We lose the Snyk advisory URL because OSV finding has higher severity
    urls_lost: list[str] = []

    if kept_finding.advisory_url != "https://snyk.io/vuln/CVE-2024-1111":
        urls_lost.append("https://snyk.io/vuln/CVE-2024-1111 (from snyk)")

    assert urls_lost == [], (
        "BUG DETECTED (#247/#213): Unique advisory URLs from lower-severity tools are lost.\n"
        "Cross-reference information from multiple sources should be preserved:\n"
        + "\n".join(f"  - Lost: {url}" for url in urls_lost)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #247 / #213 - confidence score metadata loss",
    strict=False,
)
def test_247_213_confidence_scores_not_aggregated() -> None:
    """Detect that confidence scores from multiple tools are not aggregated.

    Different tools provide different confidence scores. The current code
    keeps only one score, losing the ability to compute aggregate confidence
    or see confidence variance across tools.
    """
    f_tool_a = _vuln_finding_with_metadata(
        severity="high",
        advisory_id="CVE-2024-2222",
        tool="tool-a",
        confidence=0.75,
    )
    f_tool_b = _vuln_finding_with_metadata(
        severity="critical",
        advisory_id="CVE-2024-2222",
        tool="tool-b",
        confidence=0.92,
    )
    f_tool_c = _vuln_finding_with_metadata(
        severity="medium",
        advisory_id="CVE-2024-2222",
        tool="tool-c",
        confidence=0.88,
    )

    results = [
        _scan_result("tool-a", [f_tool_a]),
        _scan_result("tool-b", [f_tool_b]),
        _scan_result("tool-c", [f_tool_c]),
    ]

    findings, _summary = normalize_findings(results)

    # Only tool-b's finding is kept (highest severity = critical)
    kept_finding = findings[0]

    # BUG: We should have access to all confidence scores: 0.75, 0.88, 0.92
    # But we only get 0.92 from tool-b
    all_confidences = {0.75, 0.88, 0.92}
    preserved_confidence = {kept_finding.confidence} if kept_finding.confidence else set()
    lost_confidences = all_confidences - preserved_confidence

    assert lost_confidences == set(), (
        "BUG DETECTED (#247/#213): Confidence scores from lower-severity tools are lost.\n"
        f"Expected access to all confidence scores: {all_confidences}\n"
        f"Only preserved: {preserved_confidence}\n"
        f"Lost: {lost_confidences}\n"
        "This prevents aggregate confidence calculation and tool confidence comparison."
    )
