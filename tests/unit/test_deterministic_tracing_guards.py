# tested-by: tests/unit/test_deterministic_tracing_guards.py
"""Deterministic guards for distributed tracing context propagation.

These tests detect missing context propagation in distributed tracing code.
When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.

Issue #199: Add deterministic rule for #165: Distributed tracing doesn't propagate context
Parent bug: #165
Epic: #146
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

# Patterns that indicate tracing-related code
_TRACING_FUNCTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"start_span|start.*span", re.IGNORECASE),
    re.compile(r"tracer|trace\.(?:start|span|trace)", re.IGNORECASE),
    re.compile(r"opentelemetry|otel|jaeger|zipkin", re.IGNORECASE),
    re.compile(r"with_span|@traced", re.IGNORECASE),
)

# Context propagation patterns that should be present
_CONTEXT_PROPAGATION_PATTERNS: Set[str] = {
    "context",
    "parent",
    "span_context",
    "traceparent",
    "tracestate",
    "propagator",
    "extract",
    "inject",
    "carrier",
    "links",
}

# Function names that typically need context propagation
_TRACING_FUNCTION_NAMES: Set[str] = {
    "start_span",
    "start_as_current_span",
    "trace",
    "traced",
    "create_span",
    "get_tracer",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module | None:
    """Parse a Python file into an AST."""
    try:
        return ast.parse(path.read_text(), filename=str(path))
    except SyntaxError:
        return None


def _is_tracing_function(node: ast.AST) -> bool:
    """Check if a node represents a tracing function call."""
    if isinstance(node, ast.Call):
        func = node.func
        # Direct function call: start_span(...)
        if isinstance(func, ast.Name):
            return func.id in _TRACING_FUNCTION_NAMES
        # Method call: tracer.start_span(...)
        if isinstance(func, ast.Attribute):
            return func.attr in _TRACING_FUNCTION_NAMES
    return False


def _get_call_keywords(node: ast.Call) -> dict[str, ast.expr]:
    """Extract keyword arguments from a call node."""
    keywords: dict[str, ast.expr] = {}
    for kw in node.keywords:
        if kw.arg is not None:
            keywords[kw.arg] = kw.value
    return keywords


def _has_context_propagation(node: ast.Call) -> bool:
    """Check if a tracing call includes context propagation keywords."""
    keywords = _get_call_keywords(node)
    keyword_names = set(keywords.keys())

    # Check for context-related keywords
    context_keywords = {
        "context",
        "parent",
        "links",
        "parent_span",
        "span_context",
    }

    if keyword_names & context_keywords:
        return True

    # Check if any keyword value references context
    for value in keywords.values():
        for child in ast.walk(value):
            if isinstance(child, ast.Name):
                if child.id.lower() in _CONTEXT_PROPAGATION_PATTERNS:
                    return True
            if isinstance(child, ast.Attribute):
                if child.attr.lower() in _CONTEXT_PROPAGATION_PATTERNS:
                    return True

    return False


def _find_tracing_violations(tree: ast.Module, path: Path) -> list[str]:
    """Find tracing calls without context propagation in an AST."""
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            # Check with statements that might be tracing context managers
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    call = item.context_expr
                    if _is_tracing_function(call):
                        if not _has_context_propagation(call):
                            line_num = getattr(call, "lineno", 0)
                            func_name = (
                                call.func.attr
                                if isinstance(call.func, ast.Attribute)
                                else call.func.id if isinstance(call.func, ast.Name) else "unknown"
                            )
                            violations.append(
                                f"{_rel(path)}:{line_num}: "
                                f"{func_name}() missing context propagation"
                            )

        elif isinstance(node, ast.Call):
            # Check direct tracing calls
            if _is_tracing_function(node):
                if not _has_context_propagation(node):
                    line_num = getattr(node, "lineno", 0)
                    func_name = (
                        node.func.attr
                        if isinstance(node.func, ast.Attribute)
                        else node.func.id if isinstance(node.func, ast.Name) else "unknown"
                    )
                    violations.append(
                        f"{_rel(path)}:{line_num}: " f"{func_name}() missing context propagation"
                    )

    return violations


def _find_async_context_issues(tree: ast.Module, path: Path) -> list[str]:
    """Find async functions that start spans but don't propagate context properly."""
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            # Check if function contains tracing calls
            has_tracing = False
            has_context_param = False

            # Check for context parameter
            for arg in node.args.args:
                if arg.arg.lower() in {"context", "ctx", "trace_context"}:
                    has_context_param = True

            for kwarg in node.args.kwonlyargs:
                if kwarg.arg.lower() in {"context", "ctx", "trace_context"}:
                    has_context_param = True

            # Walk function body for tracing calls
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and _is_tracing_function(child):
                    has_tracing = True
                    if not _has_context_propagation(child):
                        line_num = getattr(child, "lineno", 0)
                        func_name = (
                            child.func.attr
                            if isinstance(child.func, ast.Attribute)
                            else child.func.id if isinstance(child.func, ast.Name) else "unknown"
                        )
                        violations.append(
                            f"{_rel(path)}:{line_num}: "
                            f"async {node.name}() calls {func_name}() without context propagation"
                        )

            # If function has tracing but no context parameter, flag it
            if has_tracing and not has_context_param:
                # Only flag if it doesn't already have violations logged
                line_num = getattr(node, "lineno", 0)
                violations.append(
                    f"{_rel(path)}:{line_num}: "
                    f"async {node.name}() uses tracing but lacks context parameter"
                )

    return violations


def _find_propagator_usage(tree: ast.Module, path: Path) -> list[dict[str, object]]:
    """Find and analyze propagator usage patterns."""
    findings: list[dict[str, object]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            func_name = None

            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id

            if func_name and func_name.lower() in {"extract", "inject", "propagate"}:
                line_num = getattr(node, "lineno", 0)
                findings.append(
                    {
                        "path": _rel(path),
                        "line": line_num,
                        "func": func_name,
                        "has_carrier": bool(_get_call_keywords(node).get("carrier")),
                    }
                )

    return findings


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #165 - distributed tracing doesn't propagate context",
    strict=False,
)
def test_165_tracing_calls_must_propagate_context() -> None:
    """Detect tracing function calls missing context propagation.

    Issue #165 (epic #146): Distributed tracing requires context propagation
    to maintain trace continuity across service boundaries. Tracing calls
    without context create orphaned spans that break distributed traces.

    Violations:
        - start_span() without parent context
        - start_as_current_span() without links or context
        - Tracing in async functions without context parameter

    Acceptance criteria for fix:
        - All tracing calls include context, parent, or links parameter
        - Async functions using tracing accept context parameter
        - Context propagator extract/inject used at service boundaries
    """
    violations: list[str] = []

    # Scan all Python files in src
    for path in sorted(_SRC.rglob("*.py")):
        if not path.is_file() or path.name.startswith("__"):
            continue

        tree = _parse(path)
        if tree is None:
            continue

        # Check for tracing violations
        violations.extend(_find_tracing_violations(tree, path))
        violations.extend(_find_async_context_issues(tree, path))

    # The test expects to find violations (xfail)
    # When fixed, this assertion will pass and trigger XPASS
    assert violations == [], (
        "Tracing calls must propagate context to maintain distributed trace continuity:\n"
        + "\n".join(violations)
        if violations
        else "No violations found - context propagation is correct"
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #165 - missing context propagator at boundaries",
    strict=False,
)
def test_165_service_boundaries_must_use_context_propagators() -> None:
    """Detect missing context propagator usage at service boundaries.

    Issue #165: Service entry/exit points must extract incoming trace context
    and inject outgoing trace context using W3C TraceContext propagator.

    This test looks for HTTP handlers, message consumers, and external
    callers that should be using propagator.extract() and propagator.inject().
    """
    violations: list[str] = []

    # Files that represent service boundaries
    boundary_patterns = [
        _SRC / "webhook",
        _SRC / "cli",
        _SRC / "agent",
    ]

    for pattern in boundary_patterns:
        if not pattern.exists():
            continue

        for path in sorted(pattern.rglob("*.py")):
            if not path.is_file() or path.name.startswith("__"):
                continue

            tree = _parse(path)
            if tree is None:
                continue

            # Check for propagator usage
            findings = _find_propagator_usage(tree, path)

            # If file has HTTP handlers or external calls but no propagator, flag it
            has_http_handlers = False
            for node in ast.walk(tree):
                if isinstance(node, ast.AsyncFunctionDef):
                    # Check if function looks like an HTTP handler
                    if any(
                        decorator in node.name.lower()
                        for decorator in ["route", "get", "post", "put", "delete", "handler"]
                    ):
                        has_http_handlers = True

                # Check for HTTP client calls
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute):
                        if func.attr in {"get", "post", "put", "delete", "request", "send"}:
                            has_http_handlers = True

            if has_http_handlers and not findings:
                violations.append(
                    f"{_rel(path)}: service boundary file missing context propagator usage"
                )

    assert violations == [], (
        "Service boundaries must use context propagators for distributed tracing:\n"
        + "\n".join(violations)
        if violations
        else "No violations found - propagator usage is correct"
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #165 - tracing module lacks context support",
    strict=False,
)
def test_165_tracing_module_must_exist_with_context_support() -> None:
    """Verify that a tracing module exists with proper context propagation support.

    Issue #165: The codebase should have a centralized tracing module that
    properly handles context propagation for distributed tracing.
    """
    tracing_module = _SRC / "core" / "tracing.py"

    if not tracing_module.exists():
        pytest.fail(
            "tracing.py module does not exist at src/caliper/core/tracing.py. "
            "Distributed tracing requires a centralized tracing module with "
            "context propagation support."
        )

    tree = _parse(tracing_module)
    if tree is None:
        pytest.fail(f"Could not parse {tracing_module}")

    # Check for context propagation in the tracing module
    has_context_support = False
    context_patterns = {
        "context",
        "parent",
        "span_context",
        "traceparent",
        "propagator",
        "extract",
        "inject",
        "carrier",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id.lower() in context_patterns:
                has_context_support = True
        if isinstance(node, ast.Attribute):
            if node.attr.lower() in context_patterns:
                has_context_support = True

    assert has_context_support, (
        f"{tracing_module} exists but lacks context propagation support. "
        "Distributed tracing requires context propagation functionality."
    )
