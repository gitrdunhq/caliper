# tested-by: tests/unit/test_deterministic_version_guards.py
"""Deterministic detector for semver version comparison (Issue #227).

This module detects string comparison used for version comparison instead of
proper semantic versioning (semver) comparison in the _classify_version_change
function. Issue #193 describes the bug where InvalidVersion fallback uses
string comparison instead of semver, causing incorrect upgrade/downgrade
classifications.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_SBOM_DIFF_FILE = _SRC / "core" / "sbom_diff.py"


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _find_version_string_comparison(tree: ast.Module) -> list[tuple[int, str]]:
    """Find string comparison operations in version exception handlers."""
    violations: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                is_invalid_version_handler = False
                if handler.type:
                    handler_type_str = ast.unparse(handler.type)
                    if "InvalidVersion" in handler_type_str:
                        is_invalid_version_handler = True
                if is_invalid_version_handler:
                    for stmt in handler.body:
                        for child in ast.walk(stmt):
                            if isinstance(child, ast.Compare):
                                if any(isinstance(op, (ast.Lt, ast.Gt)) for op in child.ops):
                                    source = ast.unparse(child)
                                    lineno = getattr(child, "lineno", 0)
                                    left_str = ast.unparse(child.left)
                                    right_str = ""
                                    if child.comparators:
                                        right_str = ast.unparse(child.comparators[0])
                                    version_patterns = [
                                        r"old.*ver",
                                        r"new.*ver",
                                        r"old_ver",
                                        r"new_ver",
                                        r"old.*version",
                                        r"new.*version",
                                        r"version.*old",
                                        r"version.*new",
                                    ]
                                    has_version_var = any(
                                        re.search(pattern, left_str, re.IGNORECASE)
                                        or re.search(pattern, right_str, re.IGNORECASE)
                                        for pattern in version_patterns
                                    )
                                    if has_version_var:
                                        violations.append((lineno, source))
    return violations


def _find_classify_version_function(tree: ast.Module) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_classify_version_change":
            return node
    return None


def _find_string_comparison_in_function(func: ast.FunctionDef) -> list[tuple[int, str, str]]:
    violations: list[tuple[int, str, str]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Compare):
            if any(isinstance(op, (ast.Lt, ast.Gt)) for op in node.ops):
                source = ast.unparse(node)
                lineno = getattr(node, "lineno", 0)
                left_str = ast.unparse(node.left)
                right_str = ""
                if node.comparators:
                    right_str = ast.unparse(node.comparators[0])
                version_patterns = [
                    r"old.*ver",
                    r"new.*ver",
                    r"old_ver",
                    r"new_ver",
                    r"old.*version",
                    r"new.*version",
                    r"version.*old",
                    r"version.*new",
                    r"old_ver\b",
                    r"new_ver\b",
                ]
                has_version_var = any(
                    re.search(pattern, left_str, re.IGNORECASE)
                    or re.search(pattern, right_str, re.IGNORECASE)
                    for pattern in version_patterns
                )
                if has_version_var:
                    context = "unknown"
                    for parent in ast.walk(func):
                        if isinstance(parent, ast.Try):
                            parent_lineno = getattr(parent, "lineno", 0)
                            if lineno > parent_lineno:
                                for handler in parent.handlers:
                                    handler_start = getattr(handler, "lineno", 0)
                                    handler_end = getattr(handler, "end_lineno", handler_start + 10)
                                    if handler_start <= lineno <= handler_end:
                                        handler_type = (
                                            ast.unparse(handler.type)
                                            if handler.type
                                            else "Exception"
                                        )
                                        context = f"except {handler_type}"
                                        break
                                else:
                                    try_end = getattr(parent, "end_lineno", parent_lineno + 20)
                                    for handler in parent.handlers:
                                        handler_start = getattr(handler, "lineno", try_end)
                                        if parent_lineno < lineno < handler_start:
                                            context = "try block"
                                            break
                    violations.append((lineno, source, context))
    return violations


@pytest.mark.xfail(reason="deterministic bug detector — issue #227 (parent #193)", strict=False)
def test_227_classify_version_change_no_string_comparison_in_except() -> None:
    if not _SBOM_DIFF_FILE.exists():
        pytest.skip(f"SBOM diff file not found: {_SBOM_DIFF_FILE}")
    tree = _parse(_SBOM_DIFF_FILE)
    func = _find_classify_version_function(tree)
    if func is None:
        pytest.skip("_classify_version_change function not found")
    violations: list[str] = []
    comparison_violations = _find_string_comparison_in_function(func)
    for lineno, source, context in comparison_violations:
        if "except" in context.lower():
            violations.append(
                f"{_rel(_SBOM_DIFF_FILE)}:{lineno}: String comparison in {context}: {source}"
            )
    assert violations == [], (
        "_classify_version_change must not use string comparison in exception handlers (issue #193). "
        "Use semver-aware comparison instead:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector — issue #227 (parent #193)", strict=False)
def test_227_classify_version_change_uses_semver_not_string_comparison() -> None:
    if not _SBOM_DIFF_FILE.exists():
        pytest.skip(f"SBOM diff file not found: {_SBOM_DIFF_FILE}")
    content = _SBOM_DIFF_FILE.read_text()
    tree = _parse(_SBOM_DIFF_FILE)
    func = _find_classify_version_function(tree)
    if func is None:
        pytest.skip("_classify_version_change function not found")
    violations: list[str] = []
    func_start = getattr(func, "lineno", 0)
    func_end = getattr(func, "end_lineno", func_start + 50)
    lines = content.split("\n")
    in_function = False
    for lineno, line in enumerate(lines, start=1):
        if lineno == func_start:
            in_function = True
        if lineno > func_end:
            break
        if in_function:
            patterns = [
                r"old_ver\s*[<>]\s*new_ver",
                r"new_ver\s*[<>]\s*old_ver",
                r"old_version\s*[<>]\s*new_version",
                r"new_version\s*[<>]\s*old_version",
            ]
            for pattern in patterns:
                if re.search(pattern, line):
                    violations.append(
                        f"{_rel(_SBOM_DIFF_FILE)}:{lineno}: String version comparison detected: {line.strip()[:80]}"
                    )
                    break
    assert violations == [], (
        "_classify_version_change must use semver comparison, not string comparison. "
        'String comparison of versions produces incorrect results (e.g., "10.0.0" < "9.0.0" lexicographically):\n'
        + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector — issue #227 (parent #193)", strict=False)
def test_227_invalid_version_fallback_detected() -> None:
    if not _SBOM_DIFF_FILE.exists():
        pytest.skip(f"SBOM diff file not found: {_SBOM_DIFF_FILE}")
    tree = _parse(_SBOM_DIFF_FILE)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type:
                    handler_type = ast.unparse(handler.type)
                    if "InvalidVersion" in handler_type:
                        for stmt in handler.body:
                            stmt_str = ast.unparse(stmt)
                            if re.search(
                                r"\b(old_ver|new_ver|old_version|new_version)\b.*[<>]", stmt_str
                            ) or re.search(
                                r"[<>].*\b(old_ver|new_ver|old_version|new_version)\b", stmt_str
                            ):
                                lineno = getattr(stmt, "lineno", 0)
                                violations.append(
                                    f"{_rel(_SBOM_DIFF_FILE)}:{lineno}: InvalidVersion handler uses string comparison: {stmt_str[:80]}"
                                )
    assert violations == [], (
        "The InvalidVersion exception handler must not use string comparison. "
        "This is the bug described in issue #193.:\n" + "\n".join(violations)
    )
