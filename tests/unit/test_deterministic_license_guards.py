"""Deterministic guards for license SPDX standardization — Issue #229 / Parent #195.

These tests verify that license classification code uses SPDX standardization
instead of raw regex patterns on license classifiers or license text.
They use @pytest.mark.xfail to document known deterministic bugs without breaking the build.

#229: Add deterministic rule for #195: License classifier uses regex without SPDX standardization
#195: License classifier uses regex without SPDX standardization
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# SPDX license list URL for reference
_SPDX_LICENSE_LIST_URL = "https://spdx.org/licenses/"

# Regex patterns that indicate license classification without SPDX standardization
# These are common patterns that match license classifiers or license text
_NON_SPDX_LICENSE_PATTERNS: Sequence[re.Pattern[str]] = (
    # Matches on PyPI classifier style license strings (e.g., "License :: OSI Approved :: Apache")
    re.compile(r"License\s*::", re.IGNORECASE),
    # Matches on common license name variations without SPDX standardization
    re.compile(r"(?:apache|mit|gpl|lgpl|bsd|mpl|isc|unlicense)[\s\-]?\d?\.?\d?", re.IGNORECASE),
    # Matches on license field extraction from package metadata
    re.compile(r"['\"]license['\"]", re.IGNORECASE),
    # Matches on classifier list processing for licenses
    re.compile(r"classifier.*license|license.*classifier", re.IGNORECASE),
)

# SPDX standardization indicators - these are "good" patterns
_SPDX_STANDARDIZATION_PATTERNS: Sequence[re.Pattern[str]] = (
    re.compile(r"spdx|SPDX", re.IGNORECASE),
    re.compile(r"license_expression_spdx"),
    re.compile(r"spdx_id|spdx-id", re.IGNORECASE),
    re.compile(r"licenseid|license-id", re.IGNORECASE),
)

# Files that are allowed to use license-related regex (they implement SPDX handling)
_EXCLUDED_PATHS: set[str] = {
    # ScanCode scanner properly handles SPDX
    "src/caliper/data/scanners/scancode.py",
    "src/caliper/plugins/scancode.py",
}


def _python_files(root: Path) -> list[Path]:
    """Get all Python files under root, excluding __pycache__."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    """Get repo-relative path string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _contains_license_regex_without_spdx(tree: ast.Module) -> list[tuple[int, str, str]]:
    """Find regex patterns that match licenses without SPDX standardization.

    Returns list of (lineno, pattern_type, source_snippet) tuples for violations.
    A violation occurs when:
    1. A regex pattern matches license-related strings
    2. AND there's no SPDX standardization in the same context
    """
    violations: list[tuple[int, str, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Check if this string looks like a license-matching regex
            has_license_pattern = any(p.search(node.value) for p in _NON_SPDX_LICENSE_PATTERNS)
            has_spdx_pattern = any(p.search(node.value) for p in _SPDX_STANDARDIZATION_PATTERNS)

            if has_license_pattern and not has_spdx_pattern:
                violations.append((node.lineno, "license_regex", node.value[:50]))

        # Check for re.compile calls with license patterns
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "compile",
                "search",
                "match",
                "findall",
            ):
                func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else "re.call"
            elif isinstance(node.func, ast.Name) and node.func.id in (
                "compile",
                "search",
                "match",
                "findall",
            ):
                func_name = node.func.id

            if func_name and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    pattern = first_arg.value
                    has_license_pattern = any(p.search(pattern) for p in _NON_SPDX_LICENSE_PATTERNS)
                    has_spdx_pattern = any(
                        p.search(pattern) for p in _SPDX_STANDARDIZATION_PATTERNS
                    )

                    if has_license_pattern and not has_spdx_pattern:
                        violations.append((node.lineno, f"re.{func_name}", pattern[:50]))

    return violations


def _extracts_license_from_classifiers(tree: ast.Module) -> list[tuple[int, str]]:
    """Find code that extracts license info from classifiers without SPDX normalization.

    Returns list of (lineno, source_snippet) tuples.
    """
    violations: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        # Look for string operations on classifier data
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            content = node.value.lower()
            # Detect classifier license pattern
            if "classifier" in content and "license" in content:
                # Check if there's SPDX normalization nearby in the AST
                has_spdx_nearby = False
                for other_node in ast.walk(tree):
                    if other_node is not node and isinstance(other_node, ast.Constant):
                        if isinstance(other_node.value, str) and any(
                            p.search(other_node.value) for p in _SPDX_STANDARDIZATION_PATTERNS
                        ):
                            # Simple proximity check: same function scope
                            has_spdx_nearby = True
                            break

                if not has_spdx_nearby:
                    violations.append((node.lineno, node.value[:50]))

    return violations


class TestLicenseSPDXStandardization:
    """Tests for Issue #195: License classifier uses regex without SPDX standardization.

    These tests verify that license classification code uses proper SPDX
    standardization instead of ad-hoc regex patterns on license strings.
    """

    @pytest.mark.xfail(reason="deterministic bug detector for #195", strict=False)
    def test_no_license_regex_without_spdx_standardization(self) -> None:
        """Detect license classification using regex without SPDX normalization.

        Expected behavior: When matching or classifying licenses from PyPI
        classifiers or license fields, the code should:
        1. Use SPDX standard identifiers (e.g., "Apache-2.0", "MIT")
        2. Normalize license expressions to SPDX format
        3. Not rely on ad-hoc regex patterns for license classification

        Bug #195: Code uses regex patterns to match license classifiers or
        license text without converting to SPDX standard identifiers. This
        leads to inconsistent license identification across different sources.
        """
        violations: list[str] = []

        for path in _python_files(_SRC):
            rel = _rel(path)
            if rel in _EXCLUDED_PATHS:
                continue

            tree = _parse(path)
            regex_violations = _contains_license_regex_without_spdx(tree)

            for lineno, pattern_type, snippet in regex_violations:
                violations.append(f"{rel}:{lineno}: {pattern_type} without SPDX: {snippet!r}")

        assert violations == [], (
            "License classification must use SPDX standardization.\n"
            "Found regex patterns matching license strings without SPDX normalization:\n"
            + "\n".join(violations)
            + f"\n\nReference: {_SPDX_LICENSE_LIST_URL}"
        )

    @pytest.mark.xfail(reason="deterministic bug detector for #195", strict=False)
    def test_no_classifier_extraction_without_spdx_mapping(self) -> None:
        """Detect PyPI classifier extraction without SPDX identifier mapping.

        Expected behavior: When extracting license information from PyPI
        classifiers (e.g., "License :: OSI Approved :: Apache Software License"),
        the code should map these to SPDX identifiers like "Apache-2.0".

        Bug #195 variant: Code processes PyPI license classifiers but doesn't
        map them to standard SPDX identifiers, leading to inconsistent
        license representation across the system.
        """
        violations: list[str] = []

        for path in _python_files(_SRC):
            rel = _rel(path)
            if rel in _EXCLUDED_PATHS:
                continue

            tree = _parse(path)
            classifier_violations = _extracts_license_from_classifiers(tree)

            for lineno, snippet in classifier_violations:
                violations.append(
                    f"{rel}:{lineno}: classifier processing without SPDX: {snippet!r}"
                )

        assert violations == [], (
            "PyPI classifier license extraction must map to SPDX identifiers.\n"
            "Found classifier processing without SPDX mapping:\n"
            + "\n".join(violations)
            + f"\n\nReference: {_SPDX_LICENSE_LIST_URL}"
        )

    @pytest.mark.xfail(reason="deterministic bug detector for #195", strict=False)
    def test_pypi_license_field_normalization(self) -> None:
        """Detect direct use of PyPI 'license' field without SPDX normalization.

        Expected behavior: The 'license' field from PyPI metadata is free-form
        text and should be normalized to SPDX identifiers, not used directly.

        Bug #195 variant: Code uses the raw 'license' field from PyPI without
        normalizing to SPDX, leading to inconsistent license identifiers like
        "Apache 2.0", "Apache-2", "Apache License 2.0" for the same license.
        """
        violations: list[str] = []

        # Check pypi.py specifically for direct license field usage
        pypi_path = _SRC / "data" / "pypi.py"
        if pypi_path.exists():
            tree = _parse(pypi_path)

            for node in ast.walk(tree):
                # Look for license field access
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if node.value == "license":
                        # Check if this is a direct field access pattern
                        violations.append(
                            (_rel(pypi_path), node.lineno, "direct license field access")
                        )

        # Convert violations to strings
        violation_strs = [f"{rel}:{lineno}: {desc}" for rel, lineno, desc in violations]

        assert violations == [], (
            "PyPI license field must be normalized to SPDX, not used directly.\n"
            "Found direct license field access that may lack SPDX normalization:\n"
            + "\n".join(violation_strs)
            + f"\n\nReference: {_SPDX_LICENSE_LIST_URL}"
        )
