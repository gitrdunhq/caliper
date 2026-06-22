"""Deterministic API versioning guards — tests that detect missing version prefixes in URL paths.

# tested-by: tests/unit/test_deterministic_api_version_guards.py

These tests use AST analysis to detect API routes that lack version prefixes in their
URL paths. API versioning is essential for backward compatibility and clear contract
management. Marked with xfail to track until fixed.

Issue #173: API versioning is not enforced in URL paths.
Issue #207: Deterministic detector for missing API versioning.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# API version pattern: /v{N} or /api/v{N} where N is a positive integer
_API_VERSION_RE = re.compile(r"^/(api/)?v\d+/", re.IGNORECASE)

# Files known to contain API route definitions
_API_ROUTE_FILES: tuple[Path, ...] = (_SRC / "webhook" / "server.py",)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_route_call(node: ast.Call) -> bool:
    """Check if an AST Call node is a Route constructor call."""
    # Route("/path", handler, methods=[...]) or similar patterns
    if isinstance(node.func, ast.Name) and node.func.id == "Route":
        return True
    # Also handle starlette.routing.Route
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "Route"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "routing"
    )


def _extract_path_from_route(node: ast.Call) -> str | None:
    """Extract the path string from a Route() call's first positional argument."""
    if not node.args:
        return None
    first_arg = node.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return first_arg.value
    return None


def _has_version_prefix(path: str) -> bool:
    """Check if a URL path has an API version prefix.

    Valid patterns:
        - /v1/... (e.g., /v1/webhook)
        - /api/v1/... (e.g., /api/v1/webhook)
        - /v2/... etc.

    Invalid patterns (no version):
        - /webhook
        - /api/webhook (missing version number)
        - /webhook/v1 (version after resource)
    """
    # Root path is exempt (typically not versioned)
    if path == "/":
        return True

    # Check for version prefix at the start
    return bool(_API_VERSION_RE.match(path))


def _find_route_violations(tree: ast.Module, source_path: Path) -> list[str]:
    """Find all Route definitions in AST that lack version prefixes."""
    violations: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not _is_route_call(node):
            continue

        path = _extract_path_from_route(node)
        if path is None:
            continue

        if not _has_version_prefix(path):
            violations.append(
                f"{_rel(source_path)}:{node.lineno}: Route({path!r}) lacks API version prefix"
            )

    return violations


def _find_all_route_violations() -> list[str]:
    """Scan all known API route files for missing version prefixes."""
    all_violations: list[str] = []

    for path in _API_ROUTE_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        violations = _find_route_violations(tree, path)
        all_violations.extend(violations)

    return all_violations


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #173 - API versioning is not enforced in URL paths",
    strict=False,
)
def test_173_api_routes_must_have_version_prefix() -> None:
    """Detect API routes that lack version prefixes in URL paths.

    Issue #173: API versioning is not enforced in URL paths.
    Parent #146: Epic for API contract and versioning issues.

    Violations:
        - src/caliper/webhook/server.py:233 - Route("/webhook", ...) should be Route("/v1/webhook", ...)

    Best practices for API versioning:
        - URL path versioning: /v1/resource, /v2/resource
        - Major version in path indicates breaking changes
        - Allows gradual migration of clients
        - Clear contract boundaries for documentation

    Acceptance criteria for fix:
        - All API routes have version prefix (e.g., /v1/)
        - Version is a positive integer (v1, v2, etc.)
        - Documentation updated to reflect versioned paths
        - Backward compatibility considered for existing integrations
    """
    violations = _find_all_route_violations()

    assert violations == [], (
        "API routes must include version prefix in URL path:\n"
        + "\n".join(violations)
        + "\n\nExpected format: /v{N}/resource or /api/v{N}/resource\n"
        + 'Example: Route("/v1/webhook", ...) instead of Route("/webhook", ...)'
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #173 - webhook endpoint lacks version",
    strict=False,
)
def test_173_webhook_endpoint_has_version_prefix() -> None:
    """Specific test for webhook endpoint versioning.

    The webhook endpoint at /webhook is the primary API surface for GitHub
    webhook integration. Without versioning, any breaking change to the
    webhook contract requires coordinated updates across all GitHub App
    installations.

    Current state:
        - Route("/webhook", webhook, methods=["POST"])

    Expected state:
        - Route("/v1/webhook", webhook, methods=["POST"])
        - Allows future /v2/webhook for breaking changes
        - GitHub webhook URLs can be versioned per installation
    """
    path = _SRC / "webhook" / "server.py"
    if not path.exists():
        pytest.skip("webhook/server.py not found")

    tree = _parse(path)
    violations: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not _is_route_call(node):
            continue

        path_str = _extract_path_from_route(node)
        if path_str is None:
            continue

        # Check specifically for webhook route
        if path_str == "/webhook":
            violations.append(
                f"{_rel(path)}:{node.lineno}: "
                f'Route("/webhook", ...) lacks version — use "/v1/webhook"'
            )

    assert violations == [], "\n".join(violations)


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #173 - all endpoints need versioning",
    strict=False,
)
def test_173_starlette_routes_list_has_versioned_paths() -> None:
    """Verify that Starlette routes list contains only versioned paths.

    This test specifically targets the routes list construction in
    build_app() to catch the exact pattern used in webhook/server.py.

    Target pattern to detect:
        return Starlette(routes=[Route("/webhook", webhook, methods=["POST"])])

    The test examines the routes list construction and validates each path.
    """
    path = _SRC / "webhook" / "server.py"
    if not path.exists():
        pytest.skip("webhook/server.py not found")

    tree = _parse(path)
    violations: list[str] = []

    # Look for Starlette constructor with routes parameter
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check if this is a Starlette() call
        is_starlette = (isinstance(node.func, ast.Name) and node.func.id == "Starlette") or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "Starlette"
        )

        if not is_starlette:
            continue

        # Find the routes keyword argument
        for keyword in node.keywords:
            if keyword.arg != "routes":
                continue

            # routes should be a list containing Route() calls
            if not isinstance(keyword.value, ast.List):
                continue

            for element in keyword.value.elts:
                if not isinstance(element, ast.Call):
                    continue

                if not _is_route_call(element):
                    continue

                path_str = _extract_path_from_route(element)
                if path_str is None:
                    continue

                if not _has_version_prefix(path_str):
                    violations.append(
                        f"{_rel(path)}:{element.lineno}: "
                        f"Starlette routes contain unversioned path: {path_str!r}"
                    )

    assert (
        violations == []
    ), "All routes in Starlette application must have versioned paths:\n" + "\n".join(violations)
