# tested-by: tests/unit/test_deterministic_release_key_guards.py
"""Deterministic guards for release key verification logic.

Issue #249 (parent #215): Release key verification must fail closed when key is absent.

These tests use AST analysis to detect Python code that handles release key
verification and ensure it fails closed (blocks publish) when the key is absent.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files that might contain release key verification logic
_RELEASE_KEY_VERIFICATION_FILES: tuple[Path, ...] = (
    _SRC / "adapters" / "github_publisher.py",
    _SRC / "core" / "bootstrap.py",
    _SRC / "cli" / "main.py",
)

# Patterns indicating release key handling
_RELEASE_KEY_PATTERNS = [
    re.compile(r"release.?key", re.IGNORECASE),
    re.compile(r"ci[/_]release.?key", re.IGNORECASE),
    re.compile(r"verify.?key", re.IGNORECASE),
    re.compile(r"release.?unlock", re.IGNORECASE),
]


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _contains_release_key_reference(node: ast.AST) -> bool:
    """Check if AST node contains any release key related strings or names."""
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            for pattern in _RELEASE_KEY_PATTERNS:
                if pattern.search(child.value):
                    return True
        if isinstance(child, ast.Name):
            for pattern in _RELEASE_KEY_PATTERNS:
                if pattern.search(child.id):
                    return True
    return False


def _is_fail_open_guard(node: ast.If) -> bool:
    """Check if an if statement represents a fail-open guard pattern.

    A fail-open guard is one where:
    - The condition checks for absence/None/empty
    - The body contains exit(0), return True, or similar "allow" behavior
    """
    # Check if condition checks for absence (None, empty, etc.)
    condition_is_absence_check = False

    # Pattern: if not X, if X is None, if X == None, if len(X) == 0, etc.
    for child in ast.walk(node.test):
        # "not" operator
        if isinstance(child, ast.UnaryOp) and isinstance(child.op, ast.Not):
            condition_is_absence_check = True
            break
        # is None / == None
        if isinstance(child, ast.Compare):
            if any(isinstance(op, (ast.Is, ast.Eq)) for op in child.ops):
                if any(
                    isinstance(comp, ast.Constant) and comp.value is None
                    for comp in child.comparators
                ):
                    condition_is_absence_check = True
                    break
        # len(x) == 0
        if isinstance(child, ast.Compare):
            if any(isinstance(op, ast.Eq) for op in child.ops):
                for comp in child.comparators:
                    if isinstance(comp, ast.Constant) and comp.value == 0:
                        condition_is_absence_check = True
                        break

    if not condition_is_absence_check:
        return False

    # Check if body contains fail-open behavior (exit(0), return True, etc.)
    for stmt in node.body:
        for child in ast.walk(stmt):
            # exit(0), sys.exit(0), etc.
            if isinstance(child, ast.Call):
                func_name = None
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr

                if func_name in ("exit", "_exit"):
                    for arg in child.args:
                        if isinstance(arg, ast.Constant) and arg.value == 0:
                            return True  # exit(0) in absence branch = fail open

            # return True
            if isinstance(child, ast.Return):
                if child.value and isinstance(child.value, ast.Constant):
                    if child.value.value is True:
                        return True  # return True in absence branch = fail open

    return False


def _find_release_key_verification_functions(tree: ast.Module) -> list[tuple[str, int]]:
    """Find functions that handle release key verification.

    Returns list of (function_name, lineno) tuples.
    """
    verification_funcs: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if function name suggests release key handling
            name_matches = False
            for pattern in _RELEASE_KEY_PATTERNS:
                if pattern.search(node.name):
                    name_matches = True
                    break

            if name_matches or _contains_release_key_reference(node):
                verification_funcs.append((node.name, node.lineno))

    return verification_funcs


def _find_fail_open_branches(tree: ast.Module) -> list[tuple[int, str]]:
    """Find fail-open branches in the AST.

    Returns list of (lineno, context) tuples.
    """
    fail_open_branches: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            if _is_fail_open_guard(node):
                # Get some context about what is being checked
                context = "unknown condition"
                if isinstance(node.test, ast.Name):
                    context = f"if {node.test.id}"
                elif isinstance(node.test, ast.UnaryOp) and isinstance(node.test.operand, ast.Name):
                    context = f"if not {node.test.operand.id}"
                elif isinstance(node.test, ast.Compare):
                    if isinstance(node.test.left, ast.Name):
                        context = f"if {node.test.left.id} is None/empty"

                fail_open_branches.append((node.lineno, context))

    return fail_open_branches


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #249 - release key verification allows publish when key is absent",
    strict=False,
)
def test_249_release_key_verification_fails_closed_when_key_absent() -> None:
    """Detect fail-open guards in release key verification logic.

    Issue #249 (parent #215): When the release key (ci/release-key status) is absent,
    the verification logic must block publication (fail closed), not allow it.

    A fail-closed implementation should:
    - Exit with non-zero status or raise exception when key is absent
    - Return False/block when verification fails

    A fail-open implementation (the bug) would:
    - Exit with status 0 (success) when key is absent
    - Return True/allow when key is missing

    This test uses AST analysis to detect fail-open patterns in Python code
    that handles release key verification.
    """
    fail_open_violations: list[str] = []

    for path in _RELEASE_KEY_VERIFICATION_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        # Find functions that handle release key verification
        verification_funcs = _find_release_key_verification_functions(tree)

        if not verification_funcs:
            continue

        # For each verification function, check for fail-open branches
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if (node.name, node.lineno) in verification_funcs:
                    # This function handles release key verification
                    # Check all if statements within it
                    for child_node in ast.walk(node):
                        if isinstance(child_node, ast.If):
                            if _is_fail_open_guard(child_node):
                                fail_open_violations.append(
                                    f"{_rel(path)}:{child_node.lineno}: "
                                    f"{node.name}() has fail-open guard - "
                                    f"allows publish when key is absent ({child_node.lineno})"
                                )

    assert fail_open_violations == [], (
        "Release key verification must fail closed (block publish) when key is absent.\n"
        "Found fail-open guards that allow publish without key:\n" + "\n".join(fail_open_violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #249",
    strict=False,
)
def test_249_release_key_verification_handles_absent_key_explicitly() -> None:
    """Verify that release key verification explicitly handles absent key case.

    Any code handling release key verification must explicitly check for:
    - Absent/null/empty key status
    - And take appropriate fail-closed action (exit 1, return False, raise)

    This test ensures the verification logic exists and is not implicitly
    allowing publish when key status is unavailable.
    """
    found_verification_logic = False
    absent_key_handled = False

    for path in _RELEASE_KEY_VERIFICATION_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        text = path.read_text()

        # Check for release key references
        for pattern in _RELEASE_KEY_PATTERNS:
            if pattern.search(text):
                found_verification_logic = True
                break

        # Look for explicit absent key handling
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                # Check if this if handles absent/None/empty case
                is_absence_check = False
                for child in ast.walk(node.test):
                    if isinstance(child, ast.UnaryOp) and isinstance(child.op, ast.Not):
                        is_absence_check = True
                    elif isinstance(child, ast.Compare):
                        if any(isinstance(op, (ast.Is, ast.Eq)) for op in child.ops):
                            if any(
                                isinstance(c, ast.Constant) and c.value is None
                                for c in child.comparators
                            ):
                                is_absence_check = True

                if is_absence_check:
                    # Check if body has proper fail-closed handling
                    for stmt in node.body:
                        for child in ast.walk(stmt):
                            if isinstance(child, ast.Call):
                                func_name = None
                                if isinstance(child.func, ast.Name):
                                    func_name = child.func.id
                                elif isinstance(child.func, ast.Attribute):
                                    func_name = child.func.attr

                                # Fail-closed: exit(1), sys.exit(1), raise
                                if func_name in ("exit", "_exit"):
                                    for arg in child.args:
                                        if isinstance(arg, ast.Constant) and arg.value != 0:
                                            absent_key_handled = True

                            # raise statement in absence branch
                            if isinstance(child, ast.Raise):
                                absent_key_handled = True

    # If we found verification logic, it must handle absent key
    if found_verification_logic:
        assert absent_key_handled, (
            "Release key verification logic found but it does not explicitly "
            "handle absent key with fail-closed behavior (exit 1, raise, etc.).\n"
            "When ci/release-key status is absent, publication must be blocked."
        )
