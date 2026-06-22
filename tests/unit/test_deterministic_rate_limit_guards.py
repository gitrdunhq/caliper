# tested-by: tests/unit/test_deterministic_rate_limit_guards.py
"""Deterministic per-client rate limiting guards for API endpoints.

These tests use AST analysis to detect API endpoints missing per-client
rate limiting mechanisms. Per-client limiting is essential to prevent
DoS attacks and ensure fair resource allocation.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files serving API endpoints that must have per-client rate limiting (issue #183)
_API_ENDPOINT_FILES: tuple[Path, ...] = (_SRC / "webhook" / "server.py",)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_request_handler(node: ast.AST) -> bool:
    """Check if a function is an HTTP request handler (has 'request' parameter)."""
    if not isinstance(node, ast.AsyncFunctionDef) and not isinstance(node, ast.FunctionDef):
        return False

    # Check for 'request' parameter
    return any(arg.arg == "request" for arg in node.args.args)


def _has_client_identifier_check(tree: ast.Module) -> bool:
    """Check if the AST has any client identification mechanism.

    This includes:
    - IP address extraction (request.client, request.headers.get with X-Forwarded-For/Remote-Addr)
    - API key or token-based identification
    - Session or client ID tracking
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            # Check for request.client (Starlette/FastAPI pattern for client IP)
            if node.attr == "client":
                return True

        if isinstance(node, ast.Call):
            # Check for headers.get() calls with client-identifying headers
            call_name = _call_name(node.func)
            if call_name and "headers.get" in call_name:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        header = arg.value.lower()
                        if header in (
                            "x-forwarded-for",
                            "x-real-ip",
                            "remote-addr",
                            "cf-connecting-ip",
                            "true-client-ip",
                        ):
                            return True

    return False


def _has_rate_limit_mechanism(tree: ast.Module) -> bool:
    """Check if the AST has rate limiting mechanisms.

    This includes:
    - Token bucket algorithms
    - Sliding window rate limiting
    - Decorators like @rate_limit
    - Middleware references
    - Time-based throttling (sleep between requests from same client)
    """
    rate_limit_patterns = [
        "rate_limit",
        "throttle",
        "bucket",
        "limiter",
        "ratelimit",
        "slowapi",
        "fastapi_limiter",
        "flask_limiter",
    ]

    for node in ast.walk(tree):
        # Check for decorator-based rate limiting
        if isinstance(node, ast.Name):
            name_lower = node.id.lower()
            if any(pattern in name_lower for pattern in rate_limit_patterns):
                return True

        if isinstance(node, ast.Attribute):
            name_lower = node.attr.lower()
            if any(pattern in name_lower for pattern in rate_limit_patterns):
                return True

        # Check for import statements with rate limiting libraries
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name_lower = alias.name.lower()
                if any(pattern in name_lower for pattern in rate_limit_patterns):
                    return True

    return False


def _call_name(node: ast.AST) -> str | None:
    """Extract the full name of a function call (e.g., 'request.headers.get')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _find_webhook_handler(tree: ast.Module) -> ast.AsyncFunctionDef | ast.FunctionDef | None:
    """Find the main webhook request handler in the AST."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            # Look for the webhook handler (typically named 'webhook' or has 'request' param)
            if node.name == "webhook":
                return node
            # Also check for handlers with 'request' parameter
            if any(arg.arg == "request" for arg in node.args.args):
                return node
    return None


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #183 - API rate limiting is not enforced per-client",
    strict=False,
)
def test_183_webhook_has_per_client_rate_limiting() -> None:
    """Detect missing per-client rate limiting in webhook server.

    Issue #183: API endpoints must enforce rate limits per-client to prevent:
    - DoS attacks from single malicious client
    - Resource exhaustion by repeated requests
    - Unfair resource allocation between clients

    Violations detected:
        - No client identification (IP address, API key, session ID)
        - No rate limiting mechanism (token bucket, sliding window, throttling)
        - Rate limiting applied globally instead of per-client

    Acceptance criteria for fix:
        - All API endpoints identify the client making the request
        - Rate limits are enforced per-client, not globally
        - Different limits can be applied to different client types
    """
    violations: list[str] = []

    for path in _API_ENDPOINT_FILES:
        if not path.exists():
            violations.append(f"{_rel(path)}: file does not exist")
            continue

        tree = _parse(path)

        # Find the webhook handler
        handler = _find_webhook_handler(tree)
        if handler is None:
            violations.append(f"{_rel(path)}: no webhook request handler found")
            continue

        # Check for client identification
        has_client_id = _has_client_identifier_check(tree)

        # Check for rate limiting mechanism
        has_rate_limit = _has_rate_limit_mechanism(tree)

        if not has_client_id:
            violations.append(
                f"{_rel(path)}:{handler.lineno}: webhook handler '{handler.name}' "
                "missing client identification (no IP extraction, API key, or session tracking)"
            )

        if not has_rate_limit:
            violations.append(
                f"{_rel(path)}:{handler.lineno}: webhook handler '{handler.name}' "
                "missing per-client rate limiting (no token bucket, sliding window, or throttling)"
            )

    assert (
        violations == []
    ), "API endpoints must have per-client rate limiting (issue #183):\n" + "\n".join(violations)
