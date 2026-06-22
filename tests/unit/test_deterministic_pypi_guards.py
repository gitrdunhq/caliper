# tested-by: tests/unit/test_deterministic_pypi_guards.py
"""Deterministic guards for PyPI client lifecycle management (#255).

Detects when PyPIClient instances are created without proper cleanup,
caching, or context manager support. HTTP clients must be explicitly
closed or used as context managers to prevent connection leaks.

Parent bug: #221
Epic: #146
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #255 - PyPI client not closed or cached per pipeline run",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files where PyPIClient lifecycle issues should be detected
_PYPI_CLIENT_FILES: tuple[Path, ...] = (
    _SRC / "core" / "pipeline.py",
    _SRC / "data" / "pypi.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _find_pypi_client_instantiations(tree: ast.Module) -> list[tuple[int, str]]:
    """Find all PyPIClient instantiations in AST.

    Returns list of (lineno, context) tuples where context describes the usage.
    """
    instantiations: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check for PyPIClient(...) or d["PyPIClient"](...)
        call_name = _extract_call_name(node.func)

        if call_name and ("PyPIClient" in call_name or call_name == 'd["PyPIClient"]'):
            context = _get_instantiation_context(node, tree)
            instantiations.append((node.lineno, context))

    return instantiations


def _extract_call_name(node: ast.expr) -> str | None:
    """Extract the full name of a function call."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _extract_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Subscript):
        # Handle d["PyPIClient"] pattern
        if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant):
            return f'{node.value.id}["{node.slice.value}"]'
    return None


def _get_instantiation_context(call_node: ast.Call, tree: ast.Module) -> str:
    """Get the context where PyPIClient is instantiated (function name, etc.)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            # Check if the call is within this function
            for child in ast.walk(node):
                if child is call_node:
                    return f"function:{node.name}"
        if isinstance(node, ast.ClassDef):
            for child in ast.walk(node):
                if child is call_node:
                    return f"class:{node.name}"
    return "module"


def _find_close_calls(tree: ast.Module, var_name: str) -> list[int]:
    """Find all calls to close() on a variable."""
    closes: list[int] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check for var_name.close() pattern
        if isinstance(node.func, ast.Attribute) and node.func.attr == "close":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == var_name:
                closes.append(node.lineno)

    return closes


def _find_context_manager_usage(tree: ast.Module, var_name: str) -> list[int]:
    """Find if a variable is used in a with statement (context manager)."""
    usages: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Name) and item.context_expr.id == var_name:
                    usages.append(node.lineno)
                # Also check for 'with d["PyPIClient"](...) as x:' pattern
                if isinstance(item.context_expr, ast.Call):
                    call_name = _extract_call_name(item.context_expr.func)
                    if call_name and "PyPIClient" in call_name:
                        if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                            if item.optional_vars.id == var_name:
                                usages.append(node.lineno)

    return usages


def _has_context_manager_support(tree: ast.Module) -> bool:
    """Check if PyPIClient class has __enter__ and __exit__ methods."""
    has_enter = False
    has_exit = False

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PyPIClient":
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    if item.name == "__enter__":
                        has_enter = True
                    if item.name == "__exit__":
                        has_exit = True

    return has_enter and has_exit


def _find_pypi_client_variable_assignments(tree: ast.Module) -> dict[str, list[int]]:
    """Find variable names assigned to PyPIClient instantiations.

    Returns dict mapping variable name to list of line numbers where assigned.
    """
    assignments: dict[str, list[int]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if isinstance(node.value, ast.Call):
                        call_name = _extract_call_name(node.value.func)
                        if call_name and "PyPIClient" in call_name:
                            var_name = target.id
                            if var_name not in assignments:
                                assignments[var_name] = []
                            assignments[var_name].append(node.lineno)

    return assignments


@pytest.mark.xfail(
    reason="deterministic bug detector for #255 - PyPI client not closed or cached per pipeline run",
    strict=False,
)
def test_255_pypi_client_has_context_manager_support() -> None:
    """#255: PyPIClient must support context manager protocol for proper cleanup.

        Without __enter__/__exit__, callers cannot use 'with' statements to ensure
    the underlying httpx.Client is properly closed.
    """
    pypi_path = _SRC / "data" / "pypi.py"
    if not pypi_path.exists():
        pytest.skip("PyPI client file not found")

    tree = _parse(pypi_path)
    has_cm = _has_context_manager_support(tree)

    assert has_cm, (
        "PyPIClient must implement __enter__ and __exit__ for context manager support. "
        "This ensures the underlying httpx.Client is properly closed. "
        "See #255 for details on proper HTTP client lifecycle management."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector for #255 - PyPI client not closed or cached per pipeline run",
    strict=False,
)
def test_255_pipeline_closes_pypi_client() -> None:
    """#255: Pipeline must close PyPIClient after use or use context manager.

        The pipeline creates PyPIClient instances but never closes them,
    leading to connection leaks. Each instantiation should have a corresponding
        close() call, or use context manager (with statement).

        Parent bug: #221
    """
    pipeline_path = _SRC / "core" / "pipeline.py"
    if not pipeline_path.exists():
        pytest.skip("Pipeline file not found")

    tree = _parse(pipeline_path)
    content = pipeline_path.read_text()

    violations: list[str] = []

    # Find all PyPIClient instantiations
    instantiations = _find_pypi_client_instantiations(tree)

    for lineno, context in instantiations:
        # Find what variable name the client is assigned to
        # We need to parse the surrounding code
        lines = content.splitlines()
        line_content = lines[lineno - 1] if lineno <= len(lines) else ""

        # Extract variable name from assignment patterns like:
        # pypi_client = d["PyPIClient"](timeout=config.pypi_timeout)
        var_name = None
        if "=" in line_content:
            var_part = line_content.split("=")[0].strip()
            if var_part:
                var_name = var_part

        if var_name:
            # Check if this variable is ever closed
            closes = _find_close_calls(tree, var_name)
            cm_usages = _find_context_manager_usage(tree, var_name)

            if not closes and not cm_usages:
                violations.append(
                    f"{_rel(pipeline_path)}:{lineno}: PyPIClient assigned to '{var_name}' "
                    f"in {context} but never closed (no .close() call or context manager usage)"
                )
        else:
            # Direct instantiation without assignment - definitely leaked
            violations.append(
                f"{_rel(pipeline_path)}:{lineno}: PyPIClient instantiated without "
                f"assignment in {context} - cannot be closed"
            )

    assert violations == [], (
        "PyPIClient instances must be closed after use to prevent connection leaks.\n"
        "Either call .close() in a finally block, use context manager (with statement), "
        "or cache and reuse the client per pipeline run.\n"
        "See #255 and parent bug #221.\n\n" + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector for #255 - PyPI client not cached per pipeline run",
    strict=False,
)
def test_255_pypi_client_cached_per_pipeline_run() -> None:
    """#255: PyPIClient should be cached/reused per pipeline run, not recreated per package.

    Creating a new HTTP client for each package creates unnecessary connection
    overhead. The client should be created once per pipeline run and reused.

    Epic: #146
    """
    pipeline_path = _SRC / "core" / "pipeline.py"
    if not pipeline_path.exists():
        pytest.skip("Pipeline file not found")

    tree = _parse(pipeline_path)

    # Count PyPIClient instantiations in each method
    instantiations_by_method: dict[str, int] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            count = 0
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = _extract_call_name(child.func)
                    if call_name and "PyPIClient" in call_name:
                        count += 1
            if count > 0:
                instantiations_by_method[node.name] = count

    violations: list[str] = []

    for method_name, count in instantiations_by_method.items():
        if count > 1:
            violations.append(
                f"{_rel(pipeline_path)}: method '{method_name}' creates "
                f"{count} PyPIClient instances - should create once and reuse"
            )

    assert violations == [], (
        "PyPIClient should be created once per pipeline run and reused for all packages.\n"
        "Creating multiple clients creates unnecessary connection overhead.\n"
        "See #255 (Epic #146) for caching strategy.\n\n" + "\n".join(violations)
    )
