"""Tests for caliper.core.normalizer — finding normalization and dedup."""

from __future__ import annotations

from hypothesis import assume, given
from hypothesis import strategies as st

from caliper.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)
from caliper.core.normalizer import normalize_findings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vuln_finding(
    severity: str = "high",
    advisory_id: str = "CVE-2024-1234",
    pkg: str = "lodash",
    version: str = "4.17.20",
    tool: str = "osv-scanner",
) -> Finding:
    return Finding(
        severity=FindingSeverity(severity),
        category=FindingCategory.vulnerability,
        description=f"Vuln {advisory_id}",
        source_tool=tool,
        package_name=pkg,
        version=version,
        advisory_id=advisory_id,
    )


def _license_finding(
    license_id: str = "GPL-3.0",
    pkg: str = "some-lib",
    version: str = "1.0.0",
    tool: str = "scancode",
) -> Finding:
    return Finding(
        severity=FindingSeverity.low,
        category=FindingCategory.license,
        description=f"License {license_id} detected",
        source_tool=tool,
        package_name=pkg,
        version=version,
        license_id=license_id,
    )


def _no_advisory_finding(
    description: str = "hardcoded secret detected",
    tool: str = "CAL-005",
    category: FindingCategory = FindingCategory.code_smell,
) -> Finding:
    """A finding with no advisory_id — secret-scan / code-smell / detector
    findings that aren't vuln advisories (#234)."""
    return Finding(
        severity=FindingSeverity.high,
        category=category,
        description=description,
        source_tool=tool,
        package_name="caliper",
        version="",
        advisory_id=None,
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNormalizeFindings:
    """Tests for the normalize_findings function."""

    def test_no_overlap_all_findings_preserved(self) -> None:
        """When scanners report different vulns, all findings are kept."""
        f1 = _vuln_finding(advisory_id="CVE-2024-0001", tool="osv-scanner")
        f2 = _vuln_finding(advisory_id="CVE-2024-0002", tool="trivy")
        results = [
            _scan_result("osv-scanner", [f1]),
            _scan_result("trivy", [f2]),
        ]

        findings, summary = normalize_findings(results)

        assert len(findings) == 2
        advisory_ids = {f.advisory_id for f in findings}
        assert advisory_ids == {"CVE-2024-0001", "CVE-2024-0002"}

    def test_same_cve_from_two_scanners_deduplicated(self) -> None:
        """Same CVE reported by two scanners is deduplicated to one finding."""
        f1 = _vuln_finding(advisory_id="CVE-2024-1234", tool="osv-scanner")
        f2 = _vuln_finding(advisory_id="CVE-2024-1234", tool="trivy")
        results = [
            _scan_result("osv-scanner", [f1]),
            _scan_result("trivy", [f2]),
        ]

        findings, summary = normalize_findings(results)

        assert len(findings) == 1
        assert findings[0].advisory_id == "CVE-2024-1234"

    def test_same_cve_different_severity_keeps_higher(self) -> None:
        """When two scanners disagree on severity, the higher one wins."""
        f_medium = _vuln_finding(
            advisory_id="CVE-2024-5678",
            severity="medium",
            tool="osv-scanner",
        )
        f_critical = _vuln_finding(
            advisory_id="CVE-2024-5678",
            severity="critical",
            tool="trivy",
        )
        results = [
            _scan_result("osv-scanner", [f_medium]),
            _scan_result("trivy", [f_critical]),
        ]

        findings, summary = normalize_findings(results)

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.critical

    def test_license_findings_not_deduplicated(self) -> None:
        """License findings from different tools are NOT deduplicated."""
        f1 = _license_finding(license_id="GPL-3.0", tool="scancode")
        f2 = _license_finding(license_id="GPL-3.0", tool="trivy")
        results = [
            _scan_result("scancode", [f1]),
            _scan_result("trivy", [f2]),
        ]

        findings, summary = normalize_findings(results)

        # Both license findings should be preserved
        license_findings = [f for f in findings if f.category == FindingCategory.license]
        assert len(license_findings) == 2

    def test_severity_summary_counts_correct(self) -> None:
        """Severity summary accurately reflects the deduplicated findings."""
        findings_list = [
            _vuln_finding(advisory_id="CVE-2024-0001", severity="critical"),
            _vuln_finding(advisory_id="CVE-2024-0002", severity="critical"),
            _vuln_finding(advisory_id="CVE-2024-0003", severity="high"),
            _vuln_finding(advisory_id="CVE-2024-0004", severity="medium"),
            _vuln_finding(advisory_id="CVE-2024-0005", severity="low"),
        ]
        results = [_scan_result("osv-scanner", findings_list)]

        _, summary = normalize_findings(results)

        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["info"] == 0

    def test_empty_scan_results_returns_empty(self) -> None:
        """Empty scan results produce empty findings and zero counts."""
        findings, summary = normalize_findings([])

        assert findings == []
        assert summary == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def test_scan_results_with_no_findings(self) -> None:
        """Scan results that have no findings produce empty output."""
        results = [
            _scan_result("osv-scanner", []),
            _scan_result("trivy", []),
        ]

        findings, summary = normalize_findings(results)

        assert findings == []
        assert summary["critical"] == 0

    def test_unrelated_no_advisory_findings_not_collapsed(self) -> None:
        """Two unrelated findings that both lack an advisory_id (e.g. two
        different detector hits sharing category/package_name/version) must
        not collapse into one — regression for #234."""
        f1 = _no_advisory_finding(description="hardcoded secret in config.py")
        f2 = _no_advisory_finding(description="SQL injection in query builder")
        results = [_scan_result("detectors", [f1, f2])]

        findings, _ = normalize_findings(results)

        assert len(findings) == 2
        descriptions = {f.description for f in findings}
        assert descriptions == {
            "hardcoded secret in config.py",
            "SQL injection in query builder",
        }


class TestProperties:
    """Property-based tests mapped to the CLAUDE.md formal property table.

    Domain: Uniqueness. Type: INVARIANT ("different inputs -> different
    outputs"). Two findings that lack an advisory_id (not vuln advisories —
    secret-scan / code-smell / detector findings) but differ in a
    distinguishing field (source_tool or description) must never be dedup'd
    into the same finding, even when category/package_name/version collide.
    """

    @given(
        tool_a=st.text(min_size=1, max_size=20),
        tool_b=st.text(min_size=1, max_size=20),
        desc_a=st.text(min_size=1, max_size=50),
        desc_b=st.text(min_size=1, max_size=50),
    )
    def test_no_advisory_findings_never_collapse(
        self, tool_a: str, tool_b: str, desc_a: str, desc_b: str
    ) -> None:
        assume((tool_a, desc_a) != (tool_b, desc_b))

        f1 = _no_advisory_finding(description=desc_a, tool=tool_a)
        f2 = _no_advisory_finding(description=desc_b, tool=tool_b)
        results = [_scan_result("detectors", [f1, f2])]

        findings, _ = normalize_findings(results)

        assert len(findings) == 2
