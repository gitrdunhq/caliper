# tested-by: tests/unit/test_deterministic_jwt_guards.py
"""Deterministic JWT security guards for audience claim validation (#209).

These tests intentionally encode JWT security invariants as static checks.
They use @pytest.mark.xfail to allow the test suite to pass while
violations exist, documenting the security debt.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.

Issue #209: Add deterministic rule for #175 - JWT tokens don't include audience claim.
Parent #175: JWT tokens missing audience claim.
Epic #146: Security hardening.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files that may contain JWT token generation
_JWT_SOURCE_PATHS = (
    _SRC / "core" / "auth.py",
    _SRC / "webhook" / "auth.py",
    _SRC / "adapters" / "auth.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_jwt_encode_call(node: ast.AST) -> bool:
    """Check if an AST node is a jwt.encode() call."""
    if isinstance(node, ast.Call):
        func = node.func
        # Check for jwt.encode(...) or jwt_module.encode(...)
        if isinstance(func, ast.Attribute) and func.attr == "encode":
            return True
        # Check for encode(...) directly (if jwt was imported as such)
        if isinstance(func, ast.Name) and func.id == "encode":
            return True
    return False


def _get_call_keyword(node: ast.Call, keyword: str) -> ast.keyword | None:
    """Get a specific keyword argument from a call if present."""
    for kw in node.keywords:
        if kw.arg == keyword:
            return kw
    return None


def _has_dict_key(node: ast.AST | None, key: str) -> bool:
    """Check if a dict AST node contains the specified key."""
    if node is None:
        return False
    if isinstance(node, ast.Dict):
        for k in node.keys:
            if isinstance(k, ast.Constant) and k.value == key:
                return True
            if isinstance(k, ast.Str) and k.s == key:  # Python < 3.8 compatibility
                return True
    return False


def _find_jwt_encode_calls(tree: ast.Module) -> list[tuple[ast.Call, int]]:
    """Find all jwt.encode() calls in an AST with their line numbers."""
    calls: list[tuple[ast.Call, int]] = []
    for node in ast.walk(tree):
        if _is_jwt_encode_call(node) and isinstance(node, ast.Call):
            calls.append((node, node.lineno))
    return calls


def _check_jwt_encode_has_audience(call: ast.Call) -> bool:
    """Check if a jwt.encode() call includes the audience claim.

    The audience claim can be provided either:
    1. In the payload dict as 'aud' key
    2. As a separate 'audience' keyword argument (some JWT library variants)
    """
    # Check positional arguments: jwt.encode(payload, key, algorithm)
    # payload is the first positional argument
    if call.args:
        payload_arg = call.args[0]
        if _has_dict_key(payload_arg, "aud"):
            return True

    # Check for 'audience' keyword argument
    return _get_call_keyword(call, "audience") is not None


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #175/#209 - JWT tokens missing audience claim",
    strict=False,
)
def test_209_jwt_tokens_include_audience_claim() -> None:
    """Detect JWT token generation without audience claim.

    Issue #175 (via #209): JWT tokens must include the audience claim ('aud')
    to prevent token misuse across different services/contexts. This is a
    security best practice per RFC 7519.

    Violations detected:
        - jwt.encode() calls where payload dict lacks 'aud' key
        - Missing 'audience' keyword argument in jwt.encode()

    Acceptance criteria for fix:
        - All jwt.encode() calls include audience in payload or as argument
        - Audience claim must be explicitly set, not empty/None
    """
    violations: list[str] = []

    # Scan for JWT files - also search any Python file that might have jwt.encode
    jwt_files: list[Path] = []

    # Check known JWT paths
    for path in _JWT_SOURCE_PATHS:
        if path.exists():
            jwt_files.append(path)

    # Also scan all source files for jwt.encode patterns
    for py_file in _SRC.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        content = py_file.read_text()
        if "jwt" in content.lower() or "encode" in content:
            jwt_files.append(py_file)

    # Remove duplicates while preserving order
    seen: set[Path] = set()
    jwt_files = [p for p in jwt_files if not (p in seen or seen.add(p))]

    for path in jwt_files:
        try:
            tree = _parse(path)
        except SyntaxError:
            continue  # Skip files with syntax errors

        jwt_calls = _find_jwt_encode_calls(tree)

        for call, lineno in jwt_calls:
            if not _check_jwt_encode_has_audience(call):
                violations.append(
                    f"{_rel(path)}:{lineno}: jwt.encode() missing 'aud' claim in payload"
                )

    assert violations == [], (
        "JWT tokens must include audience claim ('aud') for security.\n"
        "Add 'aud' to the payload dict or pass audience= parameter:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #209 - JWT encode call without audience",
    strict=False,
)
def test_209_jwt_encode_payload_includes_aud_field() -> None:
    """Specific test for jwt.encode() payload containing 'aud' field.

    This test specifically checks that when jwt.encode() is called with a
    dictionary literal as the payload, that dictionary contains an 'aud' key.
    """
    violations: list[str] = []

    for py_file in _SRC.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue

        content = py_file.read_text()
        if "jwt" not in content.lower():
            continue

        try:
            tree = _parse(py_file)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not _is_jwt_encode_call(node):
                continue
            if not isinstance(node, ast.Call):
                continue

            # Check first positional argument (payload)
            if not node.args:
                violations.append(
                    f"{_rel(py_file)}:{node.lineno}: jwt.encode() has no payload argument"
                )
                continue

            payload = node.args[0]

            # Only check dict literals - variables we can't analyze statically
            if isinstance(payload, ast.Dict):
                has_aud = False
                for key in payload.keys:
                    if isinstance(key, ast.Constant) and key.value == "aud":
                        has_aud = True
                        break
                    # Python < 3.8 compatibility
                    if isinstance(key, ast.Str) and key.s == "aud":
                        has_aud = True
                        break

                if not has_aud:
                    violations.append(
                        f"{_rel(py_file)}:{node.lineno}: "
                        f"jwt.encode() payload dict missing 'aud' key"
                    )

    assert (
        violations == []
    ), "jwt.encode() payload must include 'aud' (audience) claim:\n" + "\n".join(violations)
