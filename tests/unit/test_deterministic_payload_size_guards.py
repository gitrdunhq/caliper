# tested-by: tests/unit/test_deterministic_payload_size_guards.py
"""Deterministic payload size guards for request handlers.

These tests use AST analysis to detect HTTP request handlers that process
request bodies without first checking payload size limits. Missing size
limits can lead to DoS attacks via oversized payloads.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files with HTTP request handlers that must have payload size limits (issue #171)
_PAYLOAD_SIZE_CHECK_FILES: tuple[Path, ...] = (_SRC / "webhook" / "server.py",)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_request_handler(node: ast.AST) -> bool:
    """Check if a function is an HTTP request handler.

    Detects patterns like:
        async def handler(request: Request) -> Response
        def handler(request: Request)
    """
    if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
        return False

    # Check for 'request' parameter with Request type annotation
    args = node.args
    if not args.args:
        return False

    for arg in args.args:
        if arg.arg == "request":
            # Check if it has a Request type annotation
            if arg.annotation is not None:
                annotation_str = ast.dump(arg.annotation)
                if "Request" in annotation_str:
                    return True
            # Also accept if the function name suggests it's a handler
            if node.name in ("webhook", "handler", "handle"):
                return True

    return False


def _has_body_access(node: ast.AST) -> bool:
    """Check if the function accesses request.body() or request.json()."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func_str = ast.dump(child.func)
            if "request.body" in func_str or "request.json" in func_str:
                return True
    return False


def _has_size_check(node: ast.AST) -> bool:
    """Check if the function has a payload size limit check.

    Looks for patterns like:
        - if len(body) > MAX_SIZE
        - if len(body) > _MAX_PAYLOAD_SIZE_BYTES
        - body length comparisons
    """
    for child in ast.walk(node):
        if isinstance(child, ast.If):
            # Check if condition involves len() comparison
            condition_str = ast.dump(child.test)

            # Look for len(body) or len(body) > comparison
            if "len" in condition_str and (
                "body" in condition_str or "_MAX" in condition_str or "MAX" in condition_str
            ):
                # Check if it's a comparison with > or >= (size check)
                if any(op in condition_str for op in ["Gt", "GtE"]):
                    return True

        # Also check for direct size attribute access
        if isinstance(child, ast.Attribute):
            attr_str = ast.dump(child)
            if any(pattern in attr_str for pattern in ["_MAX_PAYLOAD", "MAX_PAYLOAD", "MAX_SIZE"]):
                return True

    return False


def _find_handler_violations(tree: ast.Module, path: Path) -> list[str]:
    """Find all request handlers in the AST that lack size checks."""
    violations: list[str] = []

    for node in ast.walk(tree):
        if _is_request_handler(node):
            # Check if this handler accesses request body
            if _has_body_access(node):
                # Check if it has size protection
                if not _has_size_check(node):
                    line_no = getattr(node, "lineno", 0)
                    violations.append(
                        f"{_rel(path)}:{line_no}: {node.name}() accesses request body without size limit check"
                    )

    return violations


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #171 - Request payload size is not limited",
    strict=False,
)
def test_171_webhook_handlers_have_payload_size_limits() -> None:
    """Detect webhook request handlers without payload size limits.

    Issue #171 (epic #146): HTTP request handlers that process request bodies
    must validate payload size before processing to prevent DoS attacks from
    oversized payloads.

    Violations:
        - Any request handler that calls request.body() or request.json()
          without first checking the body size against a maximum limit
        - Missing _MAX_PAYLOAD_SIZE_BYTES or similar size limit constant
        - Missing size check: if len(body) > MAX_SIZE before processing

    Acceptance criteria for fix:
        - All request handlers that access request.body() or request.json()
          must first check the payload size
        - Size limit should reject payloads exceeding a reasonable threshold
          (e.g., 1 MB for webhooks)
        - Violations must return HTTP 413 (Payload Too Large)
    """
    violations: list[str] = []

    for path in _PAYLOAD_SIZE_CHECK_FILES:
        if not path.exists():
            violations.append(f"{path}: file does not exist")
            continue

        tree = _parse(path)
        file_violations = _find_handler_violations(tree, path)
        violations.extend(file_violations)

        # Also check for the presence of size limit constant in the file
        source = path.read_text()
        has_max_size_constant = any(
            pattern in source
            for pattern in ["_MAX_PAYLOAD_SIZE", "MAX_PAYLOAD_SIZE", "MAX_SIZE_BYTES"]
        )

        if not has_max_size_constant and not file_violations:
            # File has handlers but no visible size constant
            # This is a warning, not necessarily a violation if checks are done differently
            pass

    assert violations == [], (
        "Request handlers must have payload size limits to prevent DoS attacks:\n"
        + "\n".join(violations)
        + "\n\nFix: Add size check before processing request body:\n"
        + "    if len(body) > _MAX_PAYLOAD_SIZE_BYTES:\n"
        + "        return JSONResponse({'error': 'Payload too large'}, status_code=413)"
    )
