# tested-by: tests/unit/test_deterministic_pool_guards.py
"""Deterministic connection pool guards for database connections.

These tests use AST analysis to detect ConnectionPool instantiation missing
max_size parameter in database connection code.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files where ConnectionPool must have explicit max_size (issue #186)
_CONNECTION_POOL_FILES: tuple[Path, ...] = (_SRC / "data" / "db.py",)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _call_name(node: ast.AST) -> str | None:
    """Extract the full name of a function call (e.g., 'ConnectionPool')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _has_explicit_max_size(node: ast.Call) -> bool:
    """Check if a ConnectionPool call has a non-None max_size parameter."""
    max_size_keywords = [kw for kw in node.keywords if kw.arg == "max_size"]
    if not max_size_keywords:
        return False
    # Check that max_size is not explicitly None
    for kw in max_size_keywords:
        if isinstance(kw.value, ast.Constant) and kw.value.value is None:
            return False
    return True


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #186 - Database connection pool doesn't have max size limit",
    strict=False,
)
def test_186_database_connection_pool_has_max_size_limit() -> None:
    """Detect ConnectionPool instantiation without max_size in database code.

    Issue #186: ConnectionPool instantiation must have explicit max_size parameter
    to prevent unbounded connection growth and resource exhaustion.

    Violations:
        - Any ConnectionPool() call without max_size= parameter
        - Any ConnectionPool() call with max_size=None

    Acceptance criteria for fix:
        - All ConnectionPool calls have explicit max_size=N (where N is a positive integer)
        - Connection pool has an upper bound to prevent resource exhaustion
    """
    violations: list[str] = []

    for path in _CONNECTION_POOL_FILES:
        if not path.exists():
            violations.append(f"{path}: file does not exist")
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _call_name(node.func)
            if call_name != "ConnectionPool":
                continue

            if not _has_explicit_max_size(node):
                violations.append(
                    f"{_rel(path)}:{node.lineno}: ConnectionPool without explicit max_size="
                )

    assert (
        violations == []
    ), "Database connection pool must have explicit max_size limit:\n" + "\n".join(violations)
