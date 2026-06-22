# tested-by: tests/unit/test_deterministic_path_guards.py
"""Deterministic path construction guards for evidence store.

These tests intentionally encode path safety invariants as static checks.
They detect string concatenation used for path construction instead of
Path.joinpath or the Path `/` operator.

Issue #235 (parent #201): Evidence store paths must use Path.joinpath
rather than string concatenation to prevent path traversal vulnerabilities
and cross-platform compatibility issues.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_EVIDENCE_FILE = _SRC / "data" / "evidence.py"

# Path-related variable names that suggest path construction
_PATH_VAR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r".*path.*", re.IGNORECASE),
    re.compile(r".*dir.*", re.IGNORECASE),
    re.compile(r".*root.*", re.IGNORECASE),
    re.compile(r".*dest.*", re.IGNORECASE),
    re.compile(r".*tmp.*", re.IGNORECASE),
    re.compile(r".*key.*", re.IGNORECASE),
)

# Functions that should use Path objects, not strings
_PATH_CONSTRUCTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"os\.rename\s*\("),
    re.compile(r"os\.path\.join"),
    re.compile(r"tempfile\.\w+.*dir\s*="),
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_path_related_name(name: str) -> bool:
    """Check if a variable name suggests it's path-related."""
    return any(pattern.search(name) for pattern in _PATH_VAR_PATTERNS)


def _contains_string_concat(node: ast.AST) -> list[tuple[str, int]]:
    """
    Find all string concatenation operations in the AST.
    Returns list of (source_snippet, line_number) tuples.
    """
    violations: list[tuple[str, int]] = []

    for child in ast.walk(node):
        # Check for binary addition that might be string concatenation
        if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
            # Check if either operand involves path-like strings
            left_str = ast.unparse(child.left)
            right_str = ast.unparse(child.right)

            # Detect: str(path) + "/" + something
            # Detect: path + "/" + something
            # Detect: anything + "/" + path
            has_path_var = _is_path_related_name(left_str) or _is_path_related_name(right_str)
            has_separator = "/" in left_str or "/" in right_str

            if has_path_var and has_separator:
                source = ast.unparse(child)
                lineno = getattr(child, "lineno", 0)
                violations.append((source, lineno))

        # Check for f-strings that might be path construction
        if isinstance(child, ast.JoinedStr):
            source = ast.unparse(child)
            # Check if f-string contains path-like variables
            for value in child.values:
                if isinstance(value, ast.FormattedValue):
                    var_name = ast.unparse(value.value)
                    if _is_path_related_name(var_name):
                        if "/" in source or "\\" in source:
                            lineno = getattr(child, "lineno", 0)
                            violations.append((source, lineno))

    return violations


def _contains_os_path_join(node: ast.AST) -> list[tuple[str, int]]:
    """Find os.path.join calls which should be Path instead."""
    violations: list[tuple[str, int]] = []

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func_str = ast.unparse(child.func)
            if "os.path.join" in func_str:
                source = ast.unparse(child)
                lineno = getattr(child, "lineno", 0)
                violations.append((source, lineno))

    return violations


def _find_str_conversion_with_concat(tree: ast.Module) -> list[tuple[int, str]]:
    """
    Find instances where str() is used to convert a Path for string concatenation.
    This is a red flag for improper path construction.
    """
    violations: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        # Look for str(path_var) patterns followed by concatenation
        if isinstance(node, ast.Call):
            func_str = ast.unparse(node.func)
            if func_str == "str":
                # Check if the argument is a path-related variable
                if node.args:
                    arg_str = ast.unparse(node.args[0])
                    if _is_path_related_name(arg_str):
                        # Check if parent context involves concatenation
                        parent = getattr(node, "parent", None)
                        if isinstance(parent, ast.BinOp):
                            source = ast.unparse(parent)
                            if "/" in source or "+" in source:
                                lineno = getattr(node, "lineno", 0)
                                violations.append((lineno, source))

    return violations


@pytest.mark.xfail(
    reason="deterministic bug detector — issue #235 (parent #201)",
    strict=False,
)
def test_235_evidence_store_no_string_path_concatenation() -> None:
    """Detect string concatenation for path construction in evidence store.

    Issue #201: Evidence store paths constructed with string concatenation
    instead of Path.joinpath creates path traversal risks and platform issues.

    The fix requires:
        - Use Path / operator or Path.joinpath() for path construction
        - Avoid: str(path) + "/" + key
        - Avoid: f"{path}/{key}"
        - Avoid: os.path.join for path construction in pathlib-using code

    Acceptance criteria:
        - No string concatenation using + for path construction
        - No f-string path construction with / or \\ separators
        - Consistent use of Path operators throughout evidence.py
    """
    if not _EVIDENCE_FILE.exists():
        pytest.skip(f"Evidence file not found: {_EVIDENCE_FILE}")

    tree = _parse(_EVIDENCE_FILE)

    violations: list[str] = []

    # Find all string concatenations for paths
    concat_violations = _contains_string_concat(tree)
    for source, lineno in concat_violations:
        violations.append(
            f"{_rel(_EVIDENCE_FILE)}:{lineno}: " f"String concatenation for path: {source[:60]}..."
        )

    # Find os.path.join usage (should use Path / instead)
    join_violations = _contains_os_path_join(tree)
    for source, lineno in join_violations:
        violations.append(
            f"{_rel(_EVIDENCE_FILE)}:{lineno}: "
            f"os.path.join should be Path operator: {source[:60]}..."
        )

    assert violations == [], (
        "Evidence store must use Path operators (/ or joinpath) "
        "for path construction, not string concatenation:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_235_evidence_store_uses_pathlib_consistently() -> None:
    """Verify evidence store consistently uses pathlib.Path operators.

    This test checks that the evidence store implementation uses the Path
    `/` operator or `.joinpath()` method for all path construction,
    rather than converting to strings and using concatenation.
    """
    if not _EVIDENCE_FILE.exists():
        pytest.skip(f"Evidence file not found: {_EVIDENCE_FILE}")

    content = _EVIDENCE_FILE.read_text()
    tree = _parse(_EVIDENCE_FILE)

    violations: list[str] = []

    # Check for patterns that indicate string-based path construction
    problematic_patterns = [
        (r'\+\s*["\']/', "string concatenation with / separator"),
        (r'["\']/\s*\+', "string concatenation with / separator"),
        (r'f["\'][^"\']*\/[^"\']*\{[^}]*path', "f-string path construction"),
        (r'f["\'][^"\']*\\[^"\']*\{[^}]*path', "f-string path construction (Windows)"),
    ]

    lines = content.split("\n")
    for lineno, line in enumerate(lines, start=1):
        for pattern, description in problematic_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                violations.append(
                    f"{_rel(_EVIDENCE_FILE)}:{lineno}: {description}: {line.strip()[:60]}"
                )

    assert (
        violations == []
    ), "Evidence store must use Path operators instead of string manipulation:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_235_evidence_dir_uses_path_operator() -> None:
    """Specifically check that _evidence_dir uses Path / operator.

    The _evidence_dir method should return self._root / key,
    not any form of string concatenation.
    """
    if not _EVIDENCE_FILE.exists():
        pytest.skip(f"Evidence file not found: {_EVIDENCE_FILE}")

    tree = _parse(_EVIDENCE_FILE)

    violations: list[str] = []

    # Find the _evidence_dir function
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_evidence_dir":
            source = ast.unparse(node)

            # Check it uses Path / operator
            if "/" not in source or "+" in source:
                # If we see + or don't see /, check more carefully
                # Actually / is the Path operator, so we need to distinguish
                # Path operator (good) from string concatenation (bad)
                pass  # Will be caught by the concat check below
            # Check for string concatenation within the function
            concat_violations = _contains_string_concat(node)
            for concat_source, lineno in concat_violations:
                violations.append(
                    f"{_rel(_EVIDENCE_FILE)}:{lineno}: "
                    f"_evidence_dir uses string concat: {concat_source[:60]}"
                )

    assert violations == [], "_evidence_dir must use Path / operator exclusively:\n" + "\n".join(
        violations
    )
