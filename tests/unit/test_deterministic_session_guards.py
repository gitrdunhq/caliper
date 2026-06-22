# tested-by: tests/unit/test_deterministic_session_guards.py
"""Deterministic session token expiration guards (#215).

These tests use AST analysis to detect session tokens that lack expiration
binding. Session tokens without expiration create security risks:
- Tokens that never expire remain valid indefinitely if leaked
- No mechanism to force re-authentication after periods of inactivity
- Violates principle of least privilege over time

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Set

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Token-bearing field name patterns (case-insensitive)
_TOKEN_FIELD_RE = r"token|session|auth|credential|api[_-]?key|access[_-]?token|refresh[_-]?token"

# Expiration-related field patterns (case-insensitive)
_EXPIRATION_PATTERNS: Set[str] = {
    "expires_at",
    "expiry",
    "expiration",
    "expires",
    "valid_until",
    "valid_to",
    "not_after",
    "ttl",
    "lifetime",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_token_field_name(name: str) -> bool:
    """Check if a field name matches token-bearing patterns."""
    import re

    pattern = re.compile(_TOKEN_FIELD_RE, re.IGNORECASE)
    return bool(pattern.search(name))


def _is_expiration_field_name(name: str) -> bool:
    """Check if a field name indicates expiration tracking."""
    return any(exp_pattern in name.lower() for exp_pattern in _EXPIRATION_PATTERNS)


def _has_expiration_field(class_node: ast.ClassDef) -> bool:
    """Check if a class has any expiration-related fields."""
    for node in ast.walk(class_node):
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                if _is_expiration_field_name(node.target.id):
                    return True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if _is_expiration_field_name(target.id):
                        return True
    return False


def _get_token_fields(class_node: ast.ClassDef) -> list[str]:
    """Extract all token-bearing field names from a class."""
    token_fields: list[str] = []
    for node in ast.walk(class_node):
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                if _is_token_field_name(node.target.id):
                    token_fields.append(node.target.id)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if _is_token_field_name(target.id):
                        token_fields.append(target.id)
    return token_fields


def _is_session_or_token_class(class_node: ast.ClassDef) -> bool:
    """Check if a class is a session, token, or auth-related class."""
    # Check class name
    class_name_lower = class_node.name.lower()
    session_patterns = [
        "session",
        "token",
        "auth",
        "credential",
        "apikey",
        "api_key",
    ]
    if any(pattern in class_name_lower for pattern in session_patterns):
        return True

    # Check if it has token fields
    token_fields = _get_token_fields(class_node)
    return len(token_fields) > 0


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #181/#215 - session tokens missing expiration binding",
    strict=False,
)
def test_215_session_tokens_have_expiration_binding() -> None:
    """Detect session/token classes without expiration binding.

    Issue #181 (parent): Session tokens don't have expiration binding
    Issue #215: Add deterministic rule for #181

    Security risk: Session tokens without expiration remain valid indefinitely
    if leaked, creating a permanent attack vector. All tokens should have:
    - An expiration timestamp (expires_at, expiry, etc.)
    - A mechanism to validate expiration
    - Optional: refresh token flow for renewal

    Violations detected:
        - Token/Session classes with token fields but no expiration field
        - Session classes without TTL or lifetime constraints

    Acceptance criteria for fix:
        - All token-bearing classes have expiration fields
        - Expiration is enforced during token validation
        - Tests verify expiration behavior
    """
    violations: list[str] = []

    # Scan all Python files in src
    for path in sorted(_SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        if not path.exists():
            continue

        try:
            tree = _parse(path)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Check if this is a session/token class
            if not _is_session_or_token_class(node):
                continue

            # Check for token fields
            token_fields = _get_token_fields(node)
            if not token_fields:
                continue

            # Check if class has expiration fields
            if not _has_expiration_field(node):
                violations.append(
                    f"{_rel(path)}:{node.lineno}: "
                    f"class '{node.name}' has token fields {token_fields} "
                    f"but no expiration binding (missing: expires_at, expiry, "
                    f"expiration, valid_until, ttl, etc.)"
                )

    assert (
        violations == []
    ), "Session/token classes must have expiration binding (issue #181/#215):\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #181/#215 - session tokens missing expiration binding",
    strict=False,
)
def test_215_webhook_settings_has_token_expiration() -> None:
    """Specific test for WebhookSettings session token expiration.

    WebhookSettings handles GitHub tokens for webhook authentication.
    These tokens should have expiration tracking for security.
    """
    path = _SRC / "webhook" / "config.py"
    if not path.exists():
        pytest.skip("WebhookSettings not found")

    tree = _parse(path)
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if node.name == "WebhookSettings":
                token_fields = _get_token_fields(node)
                if token_fields and not _has_expiration_field(node):
                    violations.append(
                        f"{_rel(path)}:{node.lineno}: "
                        f"WebhookSettings has token fields {token_fields} "
                        f"but no expiration binding"
                    )

    assert violations == [], "\n".join(violations)


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #181/#215 - session tokens missing expiration binding",
    strict=False,
)
def test_215_github_publisher_has_token_expiration() -> None:
    """Specific test for GitHubPublisher token expiration.

    GitHubPublisher stores GitHub PAT tokens. These should have
    expiration tracking to prevent use of expired/stale tokens.
    """
    path = _SRC / "adapters" / "github_publisher.py"
    if not path.exists():
        pytest.skip("GitHubPublisher not found")

    tree = _parse(path)
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if node.name == "GitHubPublisher":
                token_fields = _get_token_fields(node)
                if token_fields and not _has_expiration_field(node):
                    violations.append(
                        f"{_rel(path)}:{node.lineno}: "
                        f"GitHubPublisher has token fields {token_fields} "
                        f"but no expiration binding"
                    )

    assert violations == [], "\n".join(violations)
