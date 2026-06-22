# tested-by: tests/unit/test_deterministic_retry_after_guards.py
"""Deterministic Retry-After header guards for HTTP clients.

These tests use AST analysis to detect HTTP client code missing proper
handling of the Retry-After header on HTTP 429 (Too Many Requests) responses.

Issue #192: HTTP client doesn't respect Retry-After header on 429 responses

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files with HTTP client code that must handle Retry-After (issue #192)
_HTTP_CLIENT_FILES: tuple[Path, ...] = (
    _SRC / "core" / "solver.py",
    _SRC / "core" / "taskfit.py",
    _SRC / "webhook" / "server.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _get_all_function_defs(tree: ast.Module) -> list[ast.FunctionDef]:
    """Extract all function definitions from the AST."""
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]


def _get_function_body(func: ast.FunctionDef) -> list[ast.stmt]:
    """Extract the body statements of a function."""
    return func.body


def _contains_429_status_check(body: list[ast.stmt]) -> bool:
    """Check if body contains a check for HTTP 429 status code."""
    source = ast.unparse(body)
    # Look for common 429 check patterns
    check_patterns = [
        "429",
        "status_code == 429",
        "status_code != 429",
        "== 429",
        "429,",
        "(429)",
        "Too Many Requests",
    ]
    return any(pattern in source for pattern in check_patterns)


def _contains_retry_after_header_check(body: list[ast.stmt]) -> bool:
    """Check if body reads Retry-After header."""
    source = ast.unparse(body)
    # Look for Retry-After header access patterns
    retry_after_patterns = [
        "retry-after",
        "retry_after",
        "Retry-After",
        "Retry_After",
        '"retry-after"',
        "'retry-after'",
        '"Retry-After"',
        "'Retry-After'",
    ]
    return any(pattern in source for pattern in retry_after_patterns)


def _contains_httpx_post_call(body: list[ast.stmt]) -> bool:
    """Check if body contains an httpx POST request call."""
    for stmt in body:
        for child in ast.walk(stmt):
            if isinstance(child, ast.Call):
                # Check for .post() call on httpx client
                if isinstance(child.func, ast.Attribute) and child.func.attr == "post":
                    return True
                # Check for direct httpx.post() or client.post()
                if isinstance(child.func, ast.Name) and child.func.id == "post":
                    return True
    return False


def _is_http_request_function(func: ast.FunctionDef) -> bool:
    """Determine if a function makes HTTP requests."""
    body = _get_function_body(func)
    # Check for httpx imports or client usage in the function
    source = ast.unparse(body).lower()
    http_indicators = [
        "httpx",
        ".post(",
        ".get(",
        ".request(",
        "asyncclient",
        "client.post",
    ]
    return any(indicator in source for indicator in http_indicators)


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #192 - HTTP clients don't respect Retry-After header on 429 responses",
    strict=False,
)
def test_192_http_clients_respect_retry_after_header() -> None:
    """Detect HTTP client code missing Retry-After header handling on 429 responses.

    Issue #192: HTTP client doesn't respect Retry-After header on 429 responses.

    When an HTTP client receives a 429 (Too Many Requests) response, it MUST:
    1. Check if the response status code is 429
    2. Read the Retry-After header from the response
    3. Use that value to determine how long to wait before retrying

    Violations:
        - Any HTTP request handling that doesn't check for 429 status
        - Any 429 handling that doesn't read Retry-After header
        - Using only fixed backoff without considering Retry-After

    Acceptance criteria for fix:
        - All HTTP clients check for 429 status code
        - All 429 responses trigger reading of Retry-After header
        - The Retry-After value is used for backoff timing
    """
    violations: list[str] = []

    for path in _HTTP_CLIENT_FILES:
        if not path.exists():
            violations.append(f"{path}: file does not exist")
            continue

        tree = _parse(path)
        functions = _get_all_function_defs(tree)

        for func in functions:
            body = _get_function_body(func)

            # Skip functions that don't make HTTP requests
            if not _is_http_request_function(func):
                continue

            # Check if this function handles 429 responses
            has_429_check = _contains_429_status_check(body)
            has_retry_after = _contains_retry_after_header_check(body)

            # If there's HTTP request code, it should handle 429 with Retry-After
            if _contains_httpx_post_call(body):
                if not has_429_check:
                    violations.append(
                        f"{_rel(path)}:{func.lineno}: {func.name}() makes HTTP POST "
                        "requests but does not check for 429 status code"
                    )
                elif not has_retry_after:
                    violations.append(
                        f"{_rel(path)}:{func.lineno}: {func.name}() handles 429 "
                        "but does not read Retry-After header"
                    )

    assert violations == [], (
        "HTTP clients must respect Retry-After header on 429 responses:\n"
        "1. Check for HTTP 429 status code in responses\n"
        "2. Read Retry-After header when 429 is received\n"
        "3. Use the header value for backoff timing\n\n" + "\n".join(violations)
    )
