"""Deterministic normalizer guards — tests that detect normalizer-specific bugs.

# tested-by: tests/unit/test_deterministic_normalizer_guards.py

These tests detect specific code patterns in the normalizer that indicate
known bugs. Marked with xfail to track until fixed.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from caliper.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)
from caliper.core.normalizer import normalize_findings

# =============================================================================
# Issue #209: Normalizer dedup key ignores severity causing higher-severity loss
# =============================================================================


def _get_normalizer_source_info():
    """Get source info for normalizer.py to parse AST."""
    from caliper.core import normalizer

    source_path = Path(inspect.getfile(normalizer))
    source = source_path.read_text()
    return ast.parse(source), source_path, source


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


@pytest.mark.xfail(
    reason="deterministic bug detector #209: normalizer dedup key ignores severity",
    strict=False,
)
def test_normalizer_dedup_key_missing_severity():
    """Detect that normalizer dedup key doesn't include severity field.

    Bug #209: The dedup key is (advisory_id, category, package_name, version)
    without severity. When findings with different severities are deduplicated,
    the order-dependent logic in lines 42-45 attempts to keep the highest
    severity, but the dedup key itself doesn't distinguish severities.

    Current code (normalizer.py:40):
        key = (f.advisory_id, f.category, f.package_name, f.version)

    This means the dedup dictionary treats findings with different severities
    as the same entry. While there's logic to prefer higher severity, the
    fundamental issue is that severity should be part of what makes a finding
    unique for proper deduplication.

    Fix #209: Add severity to the dedup key OR verify severity preservation
    works correctly in all edge cases.
    """
    tree, source_path, source_text = _get_normalizer_source_info()

    # Look for the dedup key construction
    found_vulnerable_key = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            # Check for key assignment
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "key":
                    # Check if it's a tuple without severity
                    if isinstance(node.value, ast.Tuple):
                        elements = ast.dump(node.value)
                        # Check if advisory_id is present but severity is not
                        if "advisory_id" in elements and "severity" not in elements:
                            found_vulnerable_key = True
                            pytest.fail(
                                f"BUG DETECTED: dedup key at {source_path} lacks severity.\n"
                                f"Current key: (advisory_id, category, package_name, version)\n"
                                f"Bug #209: The dedup key ignores severity, which can cause\n"
                                f"higher-severity findings to be lost in edge cases.\n"
                                f"The order-dependent severity comparison may fail when\n"
                                f"findings arrive in certain sequences.\n"
                                f"Fix #209: Add severity to the dedup key or ensure\n"
                                f"severity preservation handles all edge cases."
                            )

    # Fallback: check raw source for the specific vulnerable pattern
    if "key = (f.advisory_id, f.category, f.package_name, f.version)" in source_text:
        pytest.fail(
            "BUG DETECTED: normalizer.py uses dedup key without severity.\n"
            "Line: key = (f.advisory_id, f.category, f.package_name, f.version)\n"
            "Bug #209: The dedup key ignores severity field, which can cause\n"
            "higher-severity findings to be lost in certain processing orders.\n"
            "Fix: Add f.severity to the dedup key tuple."
        )

    if not found_vulnerable_key:
        # If we didn't find the pattern, either it's fixed or structure changed
        # Look for evidence that severity is now in the key
        if "f.severity" in source_text and "key = (" in source_text:
            # Severity might be in the key now - test passes (no xfail)
            pass
        else:
            pytest.fail(
                "Could not find dedup key construction in normalizer.py. "
                "The test may need updating if the normalizer structure changed."
            )


@pytest.mark.xfail(
    reason="deterministic bug detector #209: severity dedup logic may lose higher severity",
    strict=False,
)
def test_normalizer_severity_dedup_preserves_highest():
    """Verify that normalizer dedup logic preserves highest severity in edge cases.

    Bug #209: The current dedup logic uses order-dependent comparison to keep
    the highest severity. This test verifies that when findings with the same
    key but different severities are processed, the highest severity is always
    preserved regardless of input order.

    Edge case: When a high-severity finding is followed by a critical-severity
    finding with the same dedup key, the critical finding should win.

    The vulnerability is that the dedup key doesn't include severity, making
    the severity comparison order-dependent and potentially unreliable.
    """
    # Create findings with same key but different severities
    f_high = _vuln_finding(
        advisory_id="CVE-2024-TEST",
        severity="high",
        tool="scanner-a",
    )
    f_critical = _vuln_finding(
        advisory_id="CVE-2024-TEST",
        severity="critical",
        tool="scanner-b",
    )

    # Test case 1: High first, then critical
    results1 = [
        _scan_result("scanner-a", [f_high]),
        _scan_result("scanner-b", [f_critical]),
    ]
    findings1, _ = normalize_findings(results1)

    # Test case 2: Critical first, then high
    results2 = [
        _scan_result("scanner-b", [f_critical]),
        _scan_result("scanner-a", [f_high]),
    ]
    findings2, _ = normalize_findings(results2)

    # Both should result in exactly one finding with critical severity
    if len(findings1) != 1 or findings1[0].severity != FindingSeverity.critical:
        pytest.fail(
            f"BUG DETECTED: Severity preservation failed when high came first.\n"
            f"Expected: 1 finding with critical severity\n"
            f"Got: {len(findings1)} finding(s), severity={findings1[0].severity if findings1 else 'none'}\n"
            f"Bug #209: The dedup key lacks severity, causing unreliable\n"
            f"severity preservation when findings arrive in certain orders."
        )

    if len(findings2) != 1 or findings2[0].severity != FindingSeverity.critical:
        pytest.fail(
            f"BUG DETECTED: Severity preservation failed when critical came first.\n"
            f"Expected: 1 finding with critical severity\n"
            f"Got: {len(findings2)} finding(s), severity={findings2[0].severity if findings2 else 'none'}\n"
            f"Bug #209: The dedup key lacks severity, causing unreliable\n"
            f"severity preservation when findings arrive in certain orders."
        )

    # Additional edge case: Test with medium -> critical -> high order
    f_medium = _vuln_finding(
        advisory_id="CVE-2024-TEST2",
        severity="medium",
        tool="scanner-c",
    )
    f_critical2 = _vuln_finding(
        advisory_id="CVE-2024-TEST2",
        severity="critical",
        tool="scanner-d",
    )
    f_high2 = _vuln_finding(
        advisory_id="CVE-2024-TEST2",
        severity="high",
        tool="scanner-e",
    )

    results3 = [
        _scan_result("scanner-c", [f_medium]),
        _scan_result("scanner-d", [f_critical2]),
        _scan_result("scanner-e", [f_high2]),
    ]
    findings3, _ = normalize_findings(results3)

    if len(findings3) != 1 or findings3[0].severity != FindingSeverity.critical:
        pytest.fail(
            f"BUG DETECTED: Severity preservation failed with multiple scanners.\n"
            f"Expected: 1 finding with critical severity\n"
            f"Got: {len(findings3)} finding(s), severity={findings3[0].severity if findings3 else 'none'}\n"
            f"Input order: medium -> critical -> high\n"
            f"Bug #209: The dedup key lacks severity, causing unreliable\n"
            f"severity preservation in multi-scanner scenarios."
        )
