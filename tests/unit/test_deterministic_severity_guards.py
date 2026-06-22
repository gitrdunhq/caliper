"""Deterministic bug detector for hardcoded CVSS severity thresholds.
# tested-by: tests/unit/test_deterministic_severity_guards.py

Related to issue #194 and #228 - Vulnerability severity mapping uses hardcoded CVSS ranges.
These thresholds should be configurable rather than hardcoded.

This test uses AST analysis to detect hardcoded CVSS severity thresholds that should
be made configurable. The typical NVD CVSS v3 thresholds are:
- Critical: >= 9.0
- High: >= 7.0
- Medium: >= 4.0
- Low: < 4.0

When these values are hardcoded inline, they're difficult to customize for different
organizational policies or CVSS v4 (when it becomes widely adopted).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# Known CVSS threshold values from NVD/CVSS v3 rating scale
CVSS_THRESHOLD_VALUES = {9.0, 7.0, 4.0, 0.0}


def _is_cvss_threshold(node: ast.AST) -> bool:
    """Check if an AST node contains a CVSS threshold value.

    Args:
        node: An AST node (typically a Compare or Constant)

    Returns:
        True if the node contains a known CVSS threshold value
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        # Check if the numeric value is a known CVSS threshold
        return float(node.value) in CVSS_THRESHOLD_VALUES
    return False


def _find_hardcoded_cvss_in_function(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    source_file: Path,
) -> list[tuple[int, int, str, str]]:
    """Find hardcoded CVSS thresholds in a function definition.

    Args:
        func: A function definition AST node
        source_file: Path to the source file (for reporting)

    Returns:
        List of (line, col, function_name, context) tuples for each finding
    """
    findings: list[tuple[int, int, str, str]] = []
    func_name = func.name

    for node in ast.walk(func):
        # Look for comparison operations (e.g., score >= 9.0)
        if isinstance(node, ast.Compare):
            for comparator in node.comparators:
                if _is_cvss_threshold(comparator):
                    # Check if the comparison involves severity-related names
                    left_str = ast.unparse(node.left) if hasattr(ast, "unparse") else ""
                    if any(
                        keyword in left_str.lower() for keyword in ["score", "cvss", "severity"]
                    ):
                        context = f"comparison with {comparator.value}"
                        findings.append(
                            (node.lineno or 0, node.col_offset or 0, func_name, context)
                        )

        # Look for numeric constants in severity-related contexts
        elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            if float(node.value) in CVSS_THRESHOLD_VALUES:
                # This is a threshold value - check if it's in severity context
                # We'll report all threshold values in the function
                context = f"hardcoded threshold value: {node.value}"
                findings.append((node.lineno or 0, node.col_offset or 0, func_name, context))

    return findings


def _analyze_file_for_cvss_thresholds(file_path: Path) -> list[tuple[int, int, str, str]]:
    """Analyze a Python file for hardcoded CVSS severity thresholds.

    Args:
        file_path: Path to the Python file to analyze

    Returns:
        List of (line, col, function_name, context) tuples for each finding
    """
    findings: list[tuple[int, int, str, str]] = []

    try:
        content = file_path.read_text()
        tree = ast.parse(content)
    except (SyntaxError, UnicodeDecodeError) as e:
        pytest.skip(f"Could not parse {file_path}: {e}")
        return findings

    # Find all function definitions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if function name suggests CVSS/severity mapping
            func_name_lower = node.name.lower()
            is_severity_func = any(
                keyword in func_name_lower for keyword in ["severity", "cvss", "score"]
            )

            if is_severity_func:
                func_findings = _find_hardcoded_cvss_in_function(node, file_path)
                findings.extend(func_findings)

    return findings


@pytest.mark.xfail(
    reason="deterministic bug detector for #194 - hardcoded CVSS ranges", strict=False
)
def test_no_hardcoded_cvss_thresholds_in_osv_scanner() -> None:
    """Detect hardcoded CVSS severity thresholds in osv.py scanner.

    This test will fail (xfail) if hardcoded CVSS threshold values are detected
    in the severity mapping functions. The thresholds should be configurable
    rather than hardcoded to allow customization for different policies.
    """
    repo_root = Path(__file__).parent.parent.parent
    scanner_file = repo_root / "src" / "caliper" / "data" / "scanners" / "osv.py"

    if not scanner_file.exists():
        pytest.skip(f"Scanner file not found: {scanner_file}")

    findings = _analyze_file_for_cvss_thresholds(scanner_file)

    # Format findings for readable output
    if findings:
        finding_lines = [
            f"  Line {line}, col {col}: function '{func}' - {context}"
            for line, col, func, context in sorted(findings)
        ]
        pytest.fail(
            f"Hardcoded CVSS thresholds detected in {scanner_file}:\n"
            + "\n".join(finding_lines)
            + "\n\nThese thresholds should be configurable, not hardcoded."
        )


@pytest.mark.xfail(
    reason="deterministic bug detector for #194 - hardcoded CVSS ranges", strict=False
)
def test_no_hardcoded_cvss_thresholds_in_osv_plugin() -> None:
    """Detect hardcoded CVSS severity thresholds in osv_scanner plugin.

    This test will fail (xfail) if hardcoded CVSS threshold values are detected
    in the severity resolution methods. The thresholds should be configurable
    rather than hardcoded to allow customization for different policies.
    """
    repo_root = Path(__file__).parent.parent.parent
    plugin_file = repo_root / "src" / "caliper" / "plugins" / "osv_scanner.py"

    if not plugin_file.exists():
        pytest.skip(f"Plugin file not found: {plugin_file}")

    findings = _analyze_file_for_cvss_thresholds(plugin_file)

    # Format findings for readable output
    if findings:
        finding_lines = [
            f"  Line {line}, col {col}: function '{func}' - {context}"
            for line, col, func, context in sorted(findings)
        ]
        pytest.fail(
            f"Hardcoded CVSS thresholds detected in {plugin_file}:\n"
            + "\n".join(finding_lines)
            + "\n\nThese thresholds should be configurable, not hardcoded."
        )


@pytest.mark.xfail(
    reason="deterministic bug detector for #194 - hardcoded CVSS ranges", strict=False
)
def test_cvss_thresholds_are_configurable() -> None:
    """Verify that CVSS severity thresholds are sourced from configuration.

    This is a design-level test that checks whether the codebase properly
    separates severity threshold configuration from business logic.

    Ideal: Thresholds should be defined in a configuration module or
    loaded from settings, not inline in severity mapping functions.
    """
    repo_root = Path(__file__).parent.parent.parent

    # Define scanner and plugin files to check
    files_to_check = [
        repo_root / "src" / "caliper" / "data" / "scanners" / "osv.py",
        repo_root / "src" / "caliper" / "plugins" / "osv_scanner.py",
    ]

    all_findings: list[tuple[Path, int, int, str, str]] = []

    for file_path in files_to_check:
        if not file_path.exists():
            continue

        file_findings = _analyze_file_for_cvss_thresholds(file_path)
        for line, col, func, context in file_findings:
            all_findings.append((file_path, line, col, func, context))

    # If we found any hardcoded thresholds, the test fails (expected - xfail)
    if all_findings:
        finding_lines = [
            f"  {file_path.relative_to(repo_root)}:{line} - function '{func}'"
            for file_path, line, col, func, context in sorted(all_findings)
        ]
        pytest.fail(
            "Hardcoded CVSS severity thresholds detected.\n"
            f"Found {len(all_findings)} instances:\n"
            + "\n".join(finding_lines)
            + "\n\nRecommendation: Move thresholds to a configuration module "
            "and inject them into severity mapping functions."
        )
