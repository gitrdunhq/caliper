# tested-by: tests/unit/test_deterministic_security_headers_guards.py
"""Deterministic detector for missing security headers in HTTP responses.

These tests intentionally encode security invariants as static AST checks.
They use @pytest.mark.xfail to allow the test suite to pass while
violations exist, documenting the security debt.

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

# File(s) containing HTTP response handling
_RESPONSE_FILES: tuple[Path, ...] = (_SRC / "webhook" / "server.py",)

# Security headers that should be present on HTTP responses
_REQUIRED_SECURITY_HEADERS: Set[str] = {
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "content-security-policy",
    "referrer-policy",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_response_call(node: ast.Call) -> bool:
    """Check if an AST Call node is a Response or JSONResponse instantiation."""
    if isinstance(node.func, ast.Name):
        return node.func.id in {"Response", "JSONResponse"}
    return False


def _extract_headers_from_call(node: ast.Call) -> dict[str, str]:
    """Extract headers dict from a Response/JSONResponse call.

    Returns a dict of header names (lowercase) to their values.
    """
    headers: dict[str, str] = {}

    for keyword in node.keywords:
        if keyword.arg == "headers":
            # Check if headers is a dict literal
            if isinstance(keyword.value, ast.Dict):
                for key, val in zip(keyword.value.keys, keyword.value.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        headers[key.value.lower()] = ast.unparse(val)
            break

    return headers


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #170 - Response headers don't include security headers",
    strict=False,
)
def test_170_webhook_responses_missing_security_headers() -> None:
    """Detect HTTP responses without security headers.

    Issue #170: HTTP responses from the webhook server should include
    standard security headers to protect against common web vulnerabilities.

    Required headers:
        - X-Content-Type-Options: nosniff
        - X-Frame-Options: DENY or SAMEORIGIN
        - X-XSS-Protection: 1; mode=block
        - Content-Security-Policy: default-src 'self' (or similar)
        - Referrer-Policy: strict-origin-when-cross-origin (or similar)

    Current violations (response lines without security headers):
        - src/caliper/webhook/server.py:125-128 - payload too large response
        - src/caliper/webhook/server.py:134 - missing signature response
        - src/caliper/webhook/server.py:138 - signature mismatch response
        - src/caliper/webhook/server.py:144-147 - invalid content type response
        - src/caliper/webhook/server.py:153 - ignored event response
        - src/caliper/webhook/server.py:160 - JSON parse error response
        - src/caliper/webhook/server.py:165 - ignored PR action response
        - src/caliper/webhook/server.py:176 - missing payload field response
        - src/caliper/webhook/server.py:231 - success response

    Acceptance criteria for fix:
        - All Response/JSONResponse calls include security headers
        - Headers can be set via middleware or per-response
    """
    violations: list[str] = []

    for path in _RESPONSE_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_response_call(node):
                headers = _extract_headers_from_call(node)

                # Check which required headers are missing
                missing_headers = _REQUIRED_SECURITY_HEADERS - set(headers.keys())

                if missing_headers:
                    response_type = (
                        "JSONResponse"
                        if isinstance(node.func, ast.Name) and node.func.id == "JSONResponse"
                        else "Response"
                    )
                    violations.append(
                        f"{_rel(path)}:{node.lineno}: {response_type} missing "
                        f"security headers: {sorted(missing_headers)}"
                    )

    assert violations == [], "HTTP responses must include security headers:\n" + "\n".join(
        violations
    )
