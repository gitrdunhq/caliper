# tested-by: tests/unit/test_deterministic_cors_guards.py
"""Deterministic CORS configuration guards for issue #177.

Detects when CORS configuration allows wildcard origins in production code.
These tests intentionally encode security invariants.
They use @pytest.mark.xfail to allow the test suite to pass while
violations exist, documenting the security debt.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.

Parent bug: #177
Epic: #146
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

# Files that may contain CORS configuration (webhook server, middleware)
_CORS_RELEVANT_FILES: tuple[Path, ...] = (
    _SRC / "webhook" / "server.py",
    _SRC / "webhook" / "config.py",
    _SRC / "webhook" / "__init__.py",
    (
        _SRC / "webhook" / "middleware.py"
        if (_SRC / "webhook" / "middleware.py").exists()
        else _SRC / "webhook" / "server.py"
    ),
)

# CORS-related attribute/keyword patterns
_CORS_PATTERN_ATTRS: Set[str] = {"allow_origins", "allow_origin", "allow_origin_regex"}
_CORS_MIDDLEWARE_NAMES: Set[str] = {"CORSMiddleware", "CORS"}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


class CORSWildcardVisitor(ast.NodeVisitor):
    """AST visitor that detects CORS wildcard configuration."""

    def __init__(self) -> None:
        self.violations: list[tuple[int, str]] = []

    def _contains_wildcard(self, node: ast.expr) -> bool:
        """Check if an AST node contains a wildcard string '*'."""
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and child.value == "*":
                return True
        return False

    def _is_cors_middleware_call(self, node: ast.Call) -> bool:
        """Check if a call is to CORSMiddleware or similar."""
        if isinstance(node.func, ast.Name):
            return node.func.id in _CORS_MIDDLEWARE_NAMES
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in _CORS_MIDDLEWARE_NAMES
        return False

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function/class calls to detect CORS middleware."""
        # Check for CORSMiddleware instantiation
        if self._is_cors_middleware_call(node):
            # Check keywords like allow_origins=["*"]
            for keyword in node.keywords:
                if keyword.arg in _CORS_PATTERN_ATTRS:
                    if self._contains_wildcard(keyword.value):
                        self.violations.append(
                            (node.lineno, f"CORSMiddleware with {keyword.arg} containing '*'")
                        )

        # Check for any function call with CORS-related keywords containing wildcards
        for keyword in node.keywords:
            if keyword.arg in _CORS_PATTERN_ATTRS:
                if self._contains_wildcard(keyword.value):
                    self.violations.append(
                        (node.lineno, f"CORS config {keyword.arg}='*' allows all origins")
                    )

        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        """Visit dict literals to detect CORS config dicts."""
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and key.value in _CORS_PATTERN_ATTRS:
                if self._contains_wildcard(value):
                    self.violations.append((node.lineno, f"CORS config dict with {key.value}='*'"))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to detect CORS config variables."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id in _CORS_PATTERN_ATTRS:
                    if self._contains_wildcard(node.value):
                        self.violations.append((node.lineno, f"{target.id} assigned wildcard '*'"))
            if isinstance(target, ast.Attribute):
                if target.attr in _CORS_PATTERN_ATTRS:
                    if self._contains_wildcard(node.value):
                        self.violations.append(
                            (node.lineno, f"{target.attr} assigned wildcard '*'")
                        )
        self.generic_visit(node)


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #177 - CORS configuration allows wildcard in production",
    strict=False,
)
def test_177_cors_no_wildcard_origins() -> None:
    """Detect CORS configurations that allow wildcard origins in production.

    Issue #177 (epic #146): CORS configuration in production must not allow
    wildcard origins ('*') as this permits any website to make cross-origin
    requests to the API, creating security vulnerabilities.

    Violations detected:
        - CORSMiddleware(allow_origins=["*"])
        - CORSMiddleware(allow_origin="*")
        - allow_origins = ["*"] or "*"
        - allow_origin_regex with overly permissive patterns

    Acceptance criteria for compliance:
        - CORS origins must be explicitly specified (no wildcards)
        - Production deployments use specific origin lists
        - Wildcards only allowed in explicit dev/test configurations
    """
    violations: list[str] = []

    for path in _CORS_RELEVANT_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        visitor = CORSWildcardVisitor()
        visitor.visit(tree)

        for lineno, message in visitor.violations:
            violations.append(f"{_rel(path)}:{lineno}: {message}")

    assert violations == [], (
        "CORS configuration must not allow wildcard origins ('*') in production.\n"
        "Use explicit origin lists instead of wildcards:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_177_cors_middleware_no_wildcard() -> None:
    """Specific test for CORSMiddleware instantiation with wildcards.

    CORSMiddleware is commonly used in Starlette/FastAPI applications.
    Wildcard origins permit any website to access the API.
    """
    violations: list[str] = []

    for path in _CORS_RELEVANT_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for CORSMiddleware or similar
                is_cors = False
                if isinstance(node.func, ast.Name) and node.func.id in _CORS_MIDDLEWARE_NAMES:
                    is_cors = True
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in _CORS_MIDDLEWARE_NAMES
                ):
                    is_cors = True

                if is_cors:
                    for keyword in node.keywords:
                        if keyword.arg in _CORS_PATTERN_ATTRS:
                            for child in ast.walk(keyword.value):
                                if isinstance(child, ast.Constant) and child.value == "*":
                                    violations.append(
                                        f"{_rel(path)}:{node.lineno}: "
                                        f"CORSMiddleware({keyword.arg}='*') - use explicit origins"
                                    )
                                # Check for list with wildcard
                                if isinstance(child, ast.List):
                                    for elt in child.elts:
                                        if isinstance(elt, ast.Constant) and elt.value == "*":
                                            violations.append(
                                                f"{_rel(path)}:{node.lineno}: "
                                                f"CORSMiddleware({keyword.arg}=['*']) - use explicit origins"
                                            )

    assert violations == [], "CORSMiddleware must not use wildcard origins:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_177_webhook_server_cors_origins_explicit() -> None:
    """Specific test for webhook server CORS origin configuration.

    The webhook server handles GitHub webhook events and must ensure
    CORS origins are explicitly controlled.
    """
    path = _SRC / "webhook" / "server.py"
    if not path.exists():
        pytest.skip("webhook/server.py does not exist")

    tree = _parse(path)
    visitor = CORSWildcardVisitor()
    visitor.visit(tree)

    violations: list[str] = []
    for lineno, message in visitor.violations:
        violations.append(f"{_rel(path)}:{lineno}: {message}")

    assert (
        violations == []
    ), "Webhook server CORS configuration must use explicit origins:\n" + "\n".join(violations)
