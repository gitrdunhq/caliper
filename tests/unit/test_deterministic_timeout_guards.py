# tested-by: tests/unit/test_deterministic_timeout_guards.py
"""Deterministic timeout guards for subprocess calls.

These tests use AST analysis to detect subprocess calls missing timeout parameters
in GitHub publisher and repo snapshot code.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files where subprocess calls must have explicit timeouts (issue #260)
_SUBPROCESS_TIMEOUT_FILES: tuple[Path, ...] = (
    _SRC / "adapters" / "github_publisher.py",
    _SRC / "adapters" / "repo_snapshot.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _call_name(node: ast.AST) -> str | None:
    """Extract the full name of a function call (e.g., 'subprocess.run')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _has_explicit_timeout(node: ast.Call) -> bool:
    """Check if a subprocess.run call has a non-None timeout parameter."""
    timeout_keywords = [kw for kw in node.keywords if kw.arg == "timeout"]
    if not timeout_keywords:
        return False
    # Check that timeout is not explicitly None
    for kw in timeout_keywords:
        if isinstance(kw.value, ast.Constant) and kw.value.value is None:
            return False
    return True


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #260 - GitHub publisher and repo snapshot subprocesses lack timeouts",
    strict=False,
)
def test_260_github_publisher_and_repo_snapshot_subprocesses_have_timeouts() -> None:
    """Detect subprocess.run calls without timeout in GitHub publisher and repo snapshot.

    Issue #260 (parent #226): subprocess calls in GitHub publishing and repo snapshot
    code must have explicit timeout parameters to prevent indefinite hangs.

    Violations:
        - Any subprocess.run() call without timeout= parameter
        - Any subprocess.run() call with timeout=None

    Acceptance criteria for fix:
        - All subprocess.run calls have explicit timeout=N (where N is a positive number)
        - No subprocess calls can hang indefinitely
    """
    violations: list[str] = []

    for path in _SUBPROCESS_TIMEOUT_FILES:
        if not path.exists():
            violations.append(f"{path}: file does not exist")
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _call_name(node.func)
            if call_name != "subprocess.run":
                continue

            if not _has_explicit_timeout(node):
                violations.append(
                    f"{_rel(path)}:{node.lineno}: subprocess.run without explicit timeout="
                )

    assert violations == [], (
        "GitHub publisher and repo snapshot subprocess calls must have explicit timeouts:\n"
        + "\n".join(violations)
    )
