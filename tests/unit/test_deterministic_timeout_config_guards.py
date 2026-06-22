"""Deterministic bug detector for scanner timeout configuration validation (#191, #225).

# tested-by: tests/unit/test_deterministic_timeout_config_guards.py

This test uses AST analysis to detect timeout configuration fields that lack
proper validation constraints (ge=1) at startup. All timeout values should be
positive integers to prevent misconfiguration.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Config files where timeout fields must have validation constraints (issue #191)
_CONFIG_TIMEOUT_FILES: tuple[Path, ...] = (
    _SRC / "core" / "config.py",
    _SRC / "agent" / "config.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_timeout_field(node: ast.AnnAssign) -> bool:
    """Check if an annotated assignment is a timeout configuration field.

    A field is considered a timeout field if:
    - The target name contains 'timeout'
    - The annotation type is 'int'
    """
    # Check target name contains 'timeout'
    if not isinstance(node.target, ast.Name):
        return False

    if "timeout" not in node.target.id.lower():
        return False

    # Check type annotation is int
    if isinstance(node.annotation, ast.Name):
        if node.annotation.id != "int":
            return False
    elif isinstance(node.annotation, ast.Subscript):
        # Handle Optional[int] or similar - check the base type
        if isinstance(node.annotation.value, ast.Name):
            if node.annotation.value.id not in ("Optional", "Union"):
                return False
        else:
            return False
    else:
        return False

    return True


def _has_validation_constraint(node: ast.AnnAssign) -> bool:
    """Check if a field has proper validation constraints via Field() or Annotated[].

    Proper validation for timeout fields means:
    - Using pydantic.Field() with ge= parameter (greater than or equal)
    - Or using Annotated[] with constrained types

    Returns True if validation is present, False otherwise.
    """
    # If no default value, it's not using Field() - violation
    if node.value is None:
        return False

    # Check if using Field() call
    if isinstance(node.value.func, ast.Name) and node.value.func.id == "Field":
        # Check for ge= (greater than or equal) parameter
        return any(keyword.arg == "ge" for keyword in node.value.keywords)

    # Simple default value (e.g., `timeout: int = 60`) without Field() = violation
    if isinstance(node.value, ast.Constant):
        return False

    # Any other pattern we don't recognize = assume no validation
    return False


def _get_field_name(node: ast.AnnAssign) -> str:
    """Extract the field name from an annotated assignment."""
    if isinstance(node.target, ast.Name):
        return node.target.id
    return "unknown"


def _get_line_number(node: ast.AnnAssign) -> int:
    """Get the line number of an AST node."""
    return getattr(node, "lineno", 0)


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #191 - Scanner timeout configuration is not validated at startup (#225)",
    strict=False,
)
def test_191_scanner_timeout_configuration_has_validation_constraints() -> None:
    """Detect timeout configuration fields without proper validation constraints.

    Issue #191 (detector #225): Timeout configuration fields in config classes
    must have validation constraints to ensure positive values at startup.

    Current violations:
        - scanner_timeout: int = 60 (no validation)
        - combined_scanner_timeout: int = 180 (no validation)
        - opa_timeout: int = 10 (no validation)
        - llm_timeout: int = 30 (no validation)
        - pipeline_timeout: int = 300 (no validation)
        - pypi_timeout: int = 10 (no validation)
        - semgrep_timeout: int = 120 (no validation, in agent/config.py)

    Acceptance criteria for fix:
        - All timeout fields use pydantic.Field() with ge=1 constraint
        - Validation occurs at config load time, not runtime
        - Invalid timeout values (<=0) are rejected at startup

    Example of correct implementation:
        scanner_timeout: int = Field(default=60, ge=1)
    """
    violations: list[str] = []

    for path in _CONFIG_TIMEOUT_FILES:
        if not path.exists():
            violations.append(f"{path}: file does not exist")
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            # Look for annotated assignments (type hints)
            if not isinstance(node, ast.AnnAssign):
                continue

            # Skip if not a timeout field
            if not _is_timeout_field(node):
                continue

            # Check if it has proper validation constraints
            if not _has_validation_constraint(node):
                field_name = _get_field_name(node)
                line_no = _get_line_number(node)
                violations.append(
                    f"{_rel(path)}:{line_no}: {field_name} missing validation constraint (add Field(ge=1))"
                )

    assert violations == [], (
        "Timeout configuration fields must have validation constraints (Field(ge=1)):\n"
        + "\n".join(violations)
        + "\n\nExample fix: timeout_field: int = Field(default=60, ge=1)"
    )
