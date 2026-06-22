"""Deterministic detector for SBOM schema validation (Issue #230 / Parent #196).

# tested-by: tests/unit/test_deterministic_schema_guards.py

This module detects missing CycloneDX schema validation in parse_sbom_packages()
before processing SBOM data. The SBOM parser should validate that the input
conforms to the CycloneDX specification before extracting package information.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_SBOM_DIFF_PATH = _SRC / "core" / "sbom_diff.py"


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _find_parse_sbom_packages_function(tree: ast.Module) -> ast.FunctionDef | None:
    """Find the parse_sbom_packages function in the AST."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "parse_sbom_packages":
            return node
    return None


def _check_bomformat_validation(tree: ast.Module) -> list[str]:
    """Check if parse_sbom_packages validates bomFormat field.

    Issue #196: The SBOM parser should validate that the input has
    bomFormat: "CycloneDX" before processing to ensure it's a valid
    CycloneDX SBOM and not some other JSON structure.
    """
    violations: list[str] = []
    func_node = _find_parse_sbom_packages_function(tree)

    if func_node is None:
        violations.append(f"{_rel(_SBOM_DIFF_PATH)}: parse_sbom_packages function not found")
        return violations

    # Check if the function validates bomFormat field
    has_bomformat_check = False

    for node in ast.walk(func_node):
        # Check for string literals that reference bomFormat or CycloneDX
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node_value_lower = node.value.lower()
            if node_value_lower in {"bomformat", "cyclonedx", "bom_format"}:
                has_bomformat_check = True
                break

        # Check for dictionary access with bomFormat key
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                if node.slice.value.lower() in {"bomformat", "bom_format"}:
                    has_bomformat_check = True
                    break
            # Also check for .get() calls with bomFormat
            if isinstance(node.slice, ast.Constant) and node.slice.value == "bomFormat":
                has_bomformat_check = True
                break

        # Check for comparisons involving bomFormat
        if isinstance(node, ast.Compare):
            # Look for comparisons like sbom.get("bomFormat") == "CycloneDX"
            for child in ast.walk(node):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    if child.value in {"bomFormat", "CycloneDX"}:
                        has_bomformat_check = True
                        break

    if not has_bomformat_check:
        violations.append(
            f"{_rel(_SBOM_DIFF_PATH)}:{func_node.lineno}: "
            f"parse_sbom_packages() does not validate 'bomFormat' field before processing. "
            f"Issue #196: SBOM parser must validate CycloneDX schema before processing."
        )

    return violations


@pytest.mark.xfail(
    reason="deterministic bug detector for #196 / #230 - SBOM parser doesn't validate schema before processing",
    strict=False,
)
def test_196_sbom_parser_missing_schema_validation() -> None:
    """Detect missing CycloneDX schema validation in parse_sbom_packages().

    Issue #196: SBOM parser doesn't validate schema before processing.
    Issue #230: Deterministic detector for missing schema validation.

    The parse_sbom_packages() function in sbom_diff.py accepts any dict
    without validating it conforms to the CycloneDX specification.

    Missing validation:
    - No check for bomFormat: "CycloneDX" field
    - No check for specVersion field
    - No JSON schema validation
    - No validation of required CycloneDX structure

    Security/parsing risks:
    - Could process arbitrary JSON as if it were a valid SBOM
    - Silent failures on malformed input
    - Inability to distinguish between different SBOM formats

    Acceptance criteria for fix:
    - Validate bomFormat == "CycloneDX" before processing
    - Optionally validate specVersion
    - Reject SBOMs that don't conform to expected schema
    """
    if not _SBOM_DIFF_PATH.exists():
        pytest.skip(f"SBOM diff module not found at {_rel(_SBOM_DIFF_PATH)}")

    tree = _parse(_SBOM_DIFF_PATH)
    violations = _check_bomformat_validation(tree)

    assert violations == [], (
        "SBOM parser must validate CycloneDX schema before processing:\n"
        + "\n".join(violations)
        + "\n\nThe parse_sbom_packages() function should validate bomFormat == 'CycloneDX'"
        + "\nbefore extracting packages to ensure proper schema compliance (Issue #196)."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector for #196 / #230 - SBOM parser missing specVersion validation",
    strict=False,
)
def test_196_sbom_parser_missing_spec_version_validation() -> None:
    """Detect missing specVersion validation in parse_sbom_packages().

    Issue #196: SBOM parser should validate the CycloneDX specVersion
    to ensure compatibility with expected schema version.

    This detector checks if the parser validates the specVersion field
    before processing components.
    """
    if not _SBOM_DIFF_PATH.exists():
        pytest.skip(f"SBOM diff module not found at {_rel(_SBOM_DIFF_PATH)}")

    tree = _parse(_SBOM_DIFF_PATH)
    func_node = _find_parse_sbom_packages_function(tree)

    if func_node is None:
        pytest.skip("parse_sbom_packages function not found")

    # Check for specVersion validation
    has_specversion_check = False

    for node in ast.walk(func_node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.lower() in {"specversion", "spec_version"}:
                has_specversion_check = True
                break

        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                if node.slice.value in {"specVersion", "spec_version"}:
                    has_specversion_check = True
                    break

    violations: list[str] = []
    if not has_specversion_check:
        violations.append(
            f"{_rel(_SBOM_DIFF_PATH)}:{func_node.lineno}: "
            f"parse_sbom_packages() does not validate 'specVersion' field"
        )

    assert (
        violations == []
    ), "SBOM parser should validate specVersion for CycloneDX compatibility:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector for #196 / #230 - parse_sbom_packages missing structured validation",
    strict=False,
)
def test_196_sbom_parser_missing_structured_validation() -> None:
    """Detect that parse_sbom_packages has no structured schema validation.

    Issue #196: The function should validate the SBOM structure beyond
    just checking if it's a dict. It should verify:
    - Required CycloneDX fields are present
    - Components array structure is valid
    - Each component has required fields

    This test uses AST analysis to verify that no comprehensive validation
    logic exists in the parser.
    """
    if not _SBOM_DIFF_PATH.exists():
        pytest.skip(f"SBOM diff module not found at {_rel(_SBOM_DIFF_PATH)}")

    tree = _parse(_SBOM_DIFF_PATH)
    func_node = _find_parse_sbom_packages_function(tree)

    if func_node is None:
        pytest.skip("parse_sbom_packages function not found")

    # Check for comprehensive validation patterns
    has_validation_function_call = False
    has_schema_validation = False
    has_raise_for_invalid = False

    for node in ast.walk(func_node):
        # Check for raise statements that would reject invalid input
        if isinstance(node, ast.Raise):
            has_raise_for_invalid = True

        # Check for validation function calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                func_name = node.func.id.lower()
                if any(
                    pattern in func_name for pattern in {"validate", "assert", "verify", "check"}
                ):
                    has_validation_function_call = True

    violations: list[str] = []

    # The function currently only has a TypeError for non-dict inputs
    # but lacks semantic validation of the SBOM structure
    if not has_schema_validation and not has_validation_function_call:
        violations.append(
            f"{_rel(_SBOM_DIFF_PATH)}:{func_node.lineno}: "
            f"parse_sbom_packages() lacks structured CycloneDX schema validation. "
            f"Should validate: bomFormat, specVersion, components structure"
        )

    assert violations == [], (
        "SBOM parser must include structured schema validation:\n"
        + "\n".join(violations)
        + "\n\nRecommended validation steps:\n"
        + "1. Validate bomFormat == 'CycloneDX'\n"
        + "2. Validate specVersion is supported\n"
        + "3. Validate components array structure\n"
        + "4. Validate each component has required fields (name, version)"
    )
