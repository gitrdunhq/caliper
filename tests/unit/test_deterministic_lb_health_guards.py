"""Deterministic detector for LB health checks missing app state verification (#197).

# tested-by: tests/unit/test_deterministic_lb_health_guards.py

Bug: #163 — Load balancer health checks don't verify application state
Parent: #163
Epic: #146

Health checks that only verify binary existence (shutil.which) don't actually
check if the application is ready to serve traffic. A load balancer needs to
know if the plugin registry is functional, scanners are ready, and the app can
process requests—not just that binaries exist on disk.
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

# File(s) containing health check implementations
_HEALTHCHECK_FILES: tuple[Path, ...] = (_SRC / "cli" / "inspect_cmds.py",)

# Application state checks that indicate actual readiness verification
# These go beyond just checking binary existence
_APP_STATE_CHECKS: Set[str] = {
    # Registry/plugin state verification
    "get_default_registry",
    "registry.list",
    "registry.get",
    "plugin.is_ready",
    "plugin.health",
    # Functional checks (actually invoking the binary)
    "subprocess.run",
    "subprocess.check_output",
    "subprocess.call",
    # Application-specific state checks
    "context.is_ready",
    "app.state",
    "db.ping",
    "db.execute",  # Actually running a test query
    "connection.test",
}

# Binary-only checks that DON'T verify application state
_BINARY_ONLY_CHECKS: Set[str] = {
    "shutil.which",
    "which",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_shutil_which_call(node: ast.Call) -> bool:
    """Check if an AST Call node is shutil.which() or similar binary-only check."""
    if isinstance(node.func, ast.Attribute):
        # shutil.which, os.path.exists, etc.
        if node.func.attr in {"which", "exists"}:
            return True
    elif isinstance(node.func, ast.Name):
        if node.func.id in {"which", "exists"}:
            return True
    return False


def _is_registry_or_plugin_call(node: ast.Call) -> bool:
    """Check if an AST Call node verifies registry/plugin state."""
    if isinstance(node.func, ast.Attribute):
        # registry.list(), plugin.is_ready(), etc.
        if node.func.attr in {"list", "get", "is_ready", "health", "ping", "test"}:
            return True
    elif isinstance(node.func, ast.Name):
        if node.func.id in {"get_default_registry"}:
            return True
    return False


def _is_functional_subprocess_call(node: ast.Call) -> bool:
    """Check if an AST Call node actually runs a binary (not just checks existence)."""
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in {"run", "check_output", "call", "check_call"}:
            return True
    elif isinstance(node.func, ast.Name):
        if node.func.id in {"run", "check_output", "call", "check_call"}:
            return True
    return False


def _get_function_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Get the name of a function definition."""
    return node.name


def _analyze_healthcheck_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    """Analyze a health check function for app state verification.

    Returns a dict with:
        - name: function name
        - has_binary_check: True if function checks binary existence
        - has_app_state_check: True if function verifies actual app state
        - violations: list of specific violations found
    """
    result = {
        "name": node.name,
        "has_binary_check": False,
        "has_app_state_check": False,
        "violations": [],
    }

    # Walk through all nodes in the function
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            # Check for binary-only checks (shutil.which, etc.)
            if _is_shutil_which_call(child):
                result["has_binary_check"] = True

            # Check for app state verification
            if _is_registry_or_plugin_call(child):
                result["has_app_state_check"] = True

            if _is_functional_subprocess_call(child):
                result["has_app_state_check"] = True

    # If function has binary checks but no app state checks, it's a violation
    if result["has_binary_check"] and not result["has_app_state_check"]:
        result["violations"].append(
            f"Function '{node.name}' only checks binary existence (shutil.which) "
            f"without verifying application state (registry, plugins, or functional checks)"
        )

    return result


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #163 - LB health checks don't verify application state",
    strict=False,
)
def test_163_healthchecks_missing_app_state_verification() -> None:
    """Detect health check functions that only verify binary existence.

    Issue #163: Load balancer health checks should verify the application is
    actually ready to serve traffic, not just that binaries exist on disk.

    Current violations:
        - src/caliper/cli/inspect_cmds.py:healthcheck() - Only uses shutil.which()
          to check binary existence, doesn't verify registry is functional
        - src/caliper/cli/inspect_cmds.py:check_health() - Only uses shutil.which()
          and basic DB connect, doesn't verify application readiness

    A proper health check should verify:
        - Plugin registry is initialized and functional
        - Scanners can actually execute (not just exist)
        - Database is ready for queries (not just connectable)
        - Application context is properly loaded

    Acceptance criteria for fix:
        - Health check functions call get_default_registry() and verify plugins
        - At least one functional check (actually invoke a scanner binary)
        - Or registry.list() / registry.get() to verify state
    """
    violations: list[str] = []

    for path in _HEALTHCHECK_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        # Find all function definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if this is a health check function
                if node.name in {"healthcheck", "check_health"}:
                    analysis = _analyze_healthcheck_function(node)

                    if analysis["violations"]:
                        for violation in analysis["violations"]:
                            violations.append(f"{_rel(path)}:{node.lineno}: {violation}")

    assert violations == [], (
        "Health check functions must verify application state, not just binary existence:\n"
        + "\n".join(violations)
        + "\n\nExpected: health checks should call registry methods or perform functional checks"
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #163 - healthcheck() lacks registry verification",
    strict=False,
)
def test_163_healthcheck_function_lacks_registry_checks() -> None:
    """Specific check: healthcheck() should verify registry is functional.

    The healthcheck() function calls get_default_registry() but doesn't
    actually verify the registry is functional (e.g., by calling registry.list()).

    This is a specific instance of the broader #163 issue.
    """
    violations: list[str] = []

    for path in _HEALTHCHECK_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == "healthcheck":
                    # Check if this function actually uses the registry
                    has_registry_list = False
                    has_functional_check = False

                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            # Look for registry.list() or similar
                            if isinstance(child.func, ast.Attribute):
                                if child.func.attr == "list":
                                    has_registry_list = True

                            # Look for functional subprocess calls
                            if _is_functional_subprocess_call(child):
                                has_functional_check = True

                    if not has_registry_list and not has_functional_check:
                        violations.append(
                            f"{_rel(path)}:{node.lineno}: healthcheck() gets registry "
                            f"but doesn't call registry.list() or perform functional checks"
                        )

    assert violations == [], (
        "healthcheck() must verify registry functionality:\n"
        + "\n".join(violations)
        + "\n\nAdd: for p in registry.list(): ... or subprocess.run([tool, '--version'])"
    )
