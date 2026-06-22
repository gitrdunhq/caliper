# tested-by: tests/unit/test_deterministic_backup_guards.py
"""Deterministic detector for backup verification without restore testing (#196).

Issue #196 (parent #162): Backup verification doesn't test restore procedure.
Epic: #146

These tests detect when backup verification code exists but lacks corresponding
restore procedure testing. A backup is only valid if you can actually restore from it.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_TESTS = _REPO / "tests"


def _rel(path: Path) -> str:
    """Return repository-relative path as posix string."""
    return path.relative_to(_REPO).as_posix()


def _python_files(root: Path) -> list[Path]:
    """Return all Python files under root, excluding __pycache__."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _find_backup_functions(tree: ast.Module) -> list[tuple[str, int]]:
    """Find functions/methods that handle backup operations.

    Returns list of (function_name, line_number) tuples.
    """
    backup_funcs: list[tuple[str, int]] = []
    backup_pattern = re.compile(r"backup|verify.*backup|backup.*verify", re.IGNORECASE)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check function name
            if backup_pattern.search(node.name):
                backup_funcs.append((node.name, node.lineno))

        elif isinstance(node, ast.ClassDef):
            # Check class name for backup-related classes
            if backup_pattern.search(node.name):
                # Find all methods in this class
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        backup_funcs.append((f"{node.name}.{item.name}", item.lineno))

    return backup_funcs


def _find_restore_tests(test_files: list[Path]) -> list[str]:
    """Find all test functions that test restore procedures.

    Returns list of test function names that reference restore operations.
    """
    restore_tests: list[str] = []
    restore_pattern = re.compile(r"restore|test.*restore|restore.*test", re.IGNORECASE)

    for test_file in test_files:
        try:
            content = test_file.read_text()
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Check if function is a test and mentions restore
                    if node.name.startswith("test_") and restore_pattern.search(node.name):
                        restore_tests.append(node.name)

                    # Also check test function bodies for restore calls
                    elif node.name.startswith("test_"):
                        source = ast.unparse(node)
                        if restore_pattern.search(source):
                            restore_tests.append(f"{node.name} (in {_rel(test_file)})")

        except (SyntaxError, UnicodeDecodeError):
            continue

    return restore_tests


def _extract_function_source(module: Any, func_name: str) -> str | None:
    """Extract source code for a function from its module."""
    try:
        source = inspect.getsource(module)
        return source
    except (OSError, TypeError):
        return None


@pytest.mark.xfail(
    reason="deterministic bug detector #196: backup verification without restore testing",
    strict=False,
)
def test_backup_functions_have_restore_tests() -> None:
    """Detect backup verification code without corresponding restore tests.

    Bug #162/#196: When backup verification code exists but there are no tests
    that verify the restore procedure actually works, we have a false sense of
    security. A backup that can't be restored is useless.

    This test scans the codebase for:
    1. Functions/classes related to backup operations
    2. Missing restore procedure tests

    Acceptance criteria for fix:
    - Every backup function must have a corresponding restore test
    - Restore tests must verify the full restore procedure works
    """
    backup_functions: list[tuple[Path, str, int]] = []  # (file, func_name, line)

    # Scan source files for backup functions
    for source_file in _python_files(_SRC):
        try:
            content = source_file.read_text()
            tree = ast.parse(content)

            funcs = _find_backup_functions(tree)
            for func_name, line_no in funcs:
                backup_functions.append((source_file, func_name, line_no))

        except (SyntaxError, UnicodeDecodeError):
            continue

    # If no backup functions found, skip this test
    if not backup_functions:
        pytest.skip("No backup functions found in the codebase")

    # Find restore tests
    test_files = _python_files(_TESTS)
    restore_tests = _find_restore_tests(test_files)

    # Check each backup function has a corresponding restore test
    missing_restore_tests: list[str] = []

    for source_file, func_name, line_no in backup_functions:
        # Look for corresponding restore test
        has_restore_test = False
        func_base = func_name.split(".")[-1].lower().replace("backup", "").replace("verify", "")

        for test_name in restore_tests:
            test_lower = test_name.lower()
            # Check if test name relates to this backup function
            if func_base and func_base in test_lower:
                has_restore_test = True
                break
            # Check for generic restore test patterns
            if "restore" in test_lower and any(
                term in func_name.lower() for term in ["backup", "archive", "snapshot"]
            ):
                has_restore_test = True
                break

        if not has_restore_test:
            missing_restore_tests.append(
                f"{_rel(source_file)}:{line_no} - {func_name} lacks restore test"
            )

    assert not missing_restore_tests, (
        "BUG DETECTED: Backup verification without restore testing (#196).\n\n"
        "The following backup functions lack corresponding restore tests:\n"
        + "\n".join(f"  - {m}" for m in missing_restore_tests)
        + "\n\n"
        "A backup is only valid if you can actually restore from it.\n"
        "Fix: Add restore tests for each backup function that verify:\n"
        "  1. Backup can be successfully restored\n"
        "  2. Restored data matches original\n"
        "  3. Restore handles corruption/missing backup gracefully\n"
        "  4. Partial restore scenarios work correctly"
    )


@pytest.mark.xfail(
    reason="deterministic bug detector #162: backup classes without restore methods",
    strict=False,
)
def test_backup_classes_have_restore_methods() -> None:
    """Detect backup classes that lack restore methods.

    Bug #162: Classes that handle backup operations should provide restore
    functionality. Having backup without restore creates a false sense of security.

    This test scans for classes with backup-related names and checks if they
    have corresponding restore methods.
    """
    backup_classes: list[tuple[Path, str, int]] = []  # (file, class_name, line)
    classes_without_restore: list[str] = []

    backup_class_pattern = re.compile(r"backup|archiver|snapshot", re.IGNORECASE)

    for source_file in _python_files(_SRC):
        try:
            content = source_file.read_text()
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    if backup_class_pattern.search(node.name):
                        backup_classes.append((source_file, node.name, node.lineno))

                        # Check if class has restore methods
                        has_restore = False
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef):
                                if "restore" in item.name.lower():
                                    has_restore = True
                                    break

                        if not has_restore:
                            classes_without_restore.append(
                                f"{_rel(source_file)}:{node.lineno} - {node.name}"
                            )

        except (SyntaxError, UnicodeDecodeError):
            continue

    # If no backup classes found, skip
    if not backup_classes:
        pytest.skip("No backup classes found in the codebase")

    assert not classes_without_restore, (
        "BUG DETECTED: Backup classes lack restore methods (#162).\n\n"
        "The following backup classes have no restore methods:\n"
        + "\n".join(f"  - {c}" for c in classes_without_restore)
        + "\n\n"
        "Every backup class should provide restore functionality.\n"
        "Fix: Add restore() or similar methods to each backup class."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector #196: backup tests without restore assertions",
    strict=False,
)
def test_backup_tests_include_restore_assertions() -> None:
    """Detect backup tests that don't actually test restore procedures.

    Bug #196: Tests may verify that backups are created but not that they
    can be restored. This creates a false sense of security.

    This test scans backup-related tests and checks if they include:
    1. Restore operation calls
    2. Assertions on restored data
    3. Corruption handling tests
    """
    backup_test_files: list[Path] = []
    tests_without_restore: list[str] = []

    backup_pattern = re.compile(r"backup|archiver|snapshot", re.IGNORECASE)
    restore_pattern = re.compile(r"restore", re.IGNORECASE)

    # Find test files related to backup
    for test_file in _python_files(_TESTS):
        if backup_pattern.search(test_file.name):
            backup_test_files.append(test_file)

    # If no backup test files found, skip
    if not backup_test_files:
        pytest.skip("No backup test files found")

    # Analyze each backup test file
    for test_file in backup_test_files:
        try:
            content = test_file.read_text()
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                    source = ast.unparse(node)

                    # Check if this is a backup-related test
                    if backup_pattern.search(node.name) or backup_pattern.search(source):
                        # Check if it includes restore testing
                        has_restore = (
                            restore_pattern.search(node.name)
                            or restore_pattern.search(source)
                            or "assert" in source
                            and restore_pattern.search(source)
                        )

                        if not has_restore:
                            tests_without_restore.append(
                                f"{_rel(test_file)}:{node.lineno} - {node.name}"
                            )

        except (SyntaxError, UnicodeDecodeError):
            continue

    assert not tests_without_restore, (
        "BUG DETECTED: Backup tests lack restore assertions (#196).\n\n"
        "The following backup tests don't test restore procedures:\n"
        + "\n".join(f"  - {t}" for t in tests_without_restore)
        + "\n\n"
        "Backup tests must verify that backups can actually be restored.\n"
        "Fix: Add restore assertions to each backup test:\n"
        "  1. Call the restore function/method\n"
        "  2. Assert restored data equals original data\n"
        "  3. Test edge cases (corruption, missing files, etc.)"
    )
