# tested-by: tests/unit/test_deterministic_security_guards.py
"""Deterministic security guards for secret handling at trust boundaries.

These tests intentionally encode security invariants as static checks.
They use @pytest.mark.xfail to allow the test suite to pass while
violations exist, documenting the security debt.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Set

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Trust boundary files where secrets must use SecretStr
_SECRET_BOUNDARY_FILES: tuple[Path, ...] = (
    _SRC / "core" / "config.py",
    _SRC / "agent" / "config.py",
    _SRC / "webhook" / "config.py",
    _SRC / "adapters" / "github_publisher.py",
)

# Secret-bearing field name patterns (case-insensitive)
_SECRET_FIELD_RE = re.compile(
    r"(api[_-]?key|credential|dsn|password|private[_-]?key|secret|token)",
    re.IGNORECASE,
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _annotation_text(annotation: ast.AST | None) -> str:
    """Convert annotation AST back to source text."""
    if annotation is None:
        return "<missing>"
    return ast.unparse(annotation)


def _is_plain_str(annotation: ast.AST | None) -> bool:
    """Check if annotation is a plain 'str' type (not SecretStr)."""
    if annotation is None:
        return False
    return isinstance(annotation, ast.Name) and annotation.id == "str"


def _contains_name(node: ast.AST | None, names: Set[str]) -> bool:
    """Check if AST node contains any of the given names."""
    if node is None:
        return False
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _is_secret_str_annotation(annotation: ast.AST | None) -> bool:
    """Check if annotation uses SecretStr or SecretStr | None."""
    return _contains_name(annotation, {"SecretStr"})


def _is_secret_field_name(name: str) -> bool:
    """Check if a field name matches secret-bearing patterns."""
    return bool(_SECRET_FIELD_RE.search(name))


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #261 - secret-bearing settings use plain strings at trust boundaries",
    strict=False,
)
def test_261_secret_bearing_settings_use_plain_strings_at_trust_boundaries() -> None:
    """Detect plain str usage for secrets in settings and adapter constructors.

    Issue #261 (parent #227): Secret-bearing settings and adapter constructor
    parameters at trust boundaries must use SecretStr instead of plain str to
    prevent accidental logging or exposure.

    Violations:
        - src/caliper/webhook/config.py:24 - WebhookSettings.secret: str
        - src/caliper/adapters/github_publisher.py:20 - GitHubPublisher.__init__(token: str)

    Acceptance criteria for fix:
        - All secret-bearing fields use SecretStr or SecretStr | None
        - No plain str for api_key, secret, token, password, etc. at trust boundaries
    """
    violations: list[str] = []

    for path in _SECRET_BOUNDARY_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            # Check annotated assignments (class attributes in settings)
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                field_name = node.target.id
                if _is_secret_field_name(field_name):
                    if _is_plain_str(node.annotation):
                        violations.append(
                            f"{_rel(path)}:{node.lineno}: {field_name}: " f"str should be SecretStr"
                        )
                    elif not _is_secret_str_annotation(node.annotation):
                        # Has annotation but not SecretStr and not plain str
                        # Could be other types - skip or flag based on strictness
                        pass

            # Check function parameters (especially __init__ constructors)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check all parameters
                all_args = [
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                ]
                if node.args.vararg:
                    all_args.append(node.args.vararg)
                if node.args.kwarg:
                    all_args.append(node.args.kwarg)

                for arg in all_args:
                    arg_name = arg.arg
                    if arg_name == "self":
                        continue

                    if _is_secret_field_name(arg_name):
                        if _is_plain_str(arg.annotation):
                            func_name = node.name
                            violations.append(
                                f"{_rel(path)}:{arg.lineno}: "
                                f"{func_name}({arg_name}: str) should use SecretStr"
                            )

    assert violations == [], (
        "Secret-bearing settings at trust boundaries must use SecretStr, not plain str:\n"
        + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_261_webhook_settings_secret_uses_secretstr() -> None:
    """Specific test for WebhookSettings.secret field type.

    WebhookSettings.secret is used for HMAC-SHA256 signature validation.
    Using plain str risks accidental exposure in logs.
    """
    path = _SRC / "webhook" / "config.py"
    tree = _parse(path)

    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "secret" and _is_plain_str(node.annotation):
                violations.append(
                    f"{_rel(path)}:{node.lineno}: "
                    f"WebhookSettings.secret uses plain str, should be SecretStr"
                )

    assert violations == [], "\n".join(violations)


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_261_github_publisher_token_uses_secretstr() -> None:
    """Specific test for GitHubPublisher token parameter type.

    GitHubPublisher receives a GitHub PAT for API authentication.
    Using plain str in constructor risks accidental exposure.
    """
    path = _SRC / "adapters" / "github_publisher.py"
    tree = _parse(path)

    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "__init__":
            for arg in [*node.args.args, *node.args.kwonlyargs]:
                if arg.arg == "token" and _is_plain_str(arg.annotation):
                    violations.append(
                        f"{_rel(path)}:{arg.lineno}: "
                        f"GitHubPublisher.__init__(token: str) should use SecretStr"
                    )

    assert violations == [], "\n".join(violations)
