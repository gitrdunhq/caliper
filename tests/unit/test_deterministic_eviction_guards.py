# tested-by: tests/unit/test_deterministic_eviction_guards.py
"""Deterministic cache eviction policy guards for issue #174.

Detects when memory caches lack proper eviction policies, which can lead
to unbounded memory growth and potential OOM crashes.

These tests intentionally encode reliability invariants.
They use @pytest.mark.xfail to allow the test suite to pass while
violations exist, documenting the technical debt.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.

Parent bug: #174
Epic: #146
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files that may contain cache implementations without eviction policies
_CACHE_RELEVANT_FILES: tuple[Path, ...] = (
    _SRC / "webhook" / "server.py",
    _SRC / "agent" / "tool_helpers.py",
    _SRC / "core" / "registry.py",
    _SRC / "data" / "catalog.py",
    _SRC / "core" / "solver.py",
)

# Cache-related function/class patterns that need eviction policies
_UNBOUNDED_CACHE_PATTERNS: tuple[str, ...] = (
    "functools.cache",
    "cache",
    "dict",
    "{}",
)

# Eviction policy keywords to look for
_EVICTION_KEYWORDS: frozenset[str] = frozenset(
    {
        "maxsize",
        "ttl",
        "max_len",
        "max_entries",
        "capacity",
        "limit",
        "eviction",
        "expire",
        "timeout",
    }
)


class CacheEvictionVisitor(ast.NodeVisitor):
    """AST visitor that detects caches without eviction policies."""

    def __init__(self) -> None:
        self.violations: list[tuple[int, str]] = []

    def _is_cache_decorator(self, node: ast.expr) -> bool:
        """Check if a decorator is a cache decorator without eviction."""
        decorator_name: str | None = None

        if isinstance(node, ast.Name):
            decorator_name = node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                decorator_name = f"{node.value.id}.{node.attr}"
            else:
                decorator_name = node.attr
        elif isinstance(node, ast.Call):
            # Handle @cache() or @functools.cache() or @lru_cache()
            return self._is_cache_decorator(node.func)

        return decorator_name in ("cache", "lru_cache", "functools.cache", "functools.lru_cache")

    def _has_eviction_keyword(self, node: ast.Call) -> bool:
        """Check if a cache call has eviction-related keywords."""
        return any(keyword.arg in _EVICTION_KEYWORDS for keyword in node.keywords)

    def _is_unbounded_cache_call(self, node: ast.Call) -> bool:
        """Check if a call creates a cache without eviction policy."""
        call_name: str | None = None

        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                call_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                call_name = node.func.attr

        # Check for unbounded cache patterns
        if call_name in ("cache", "lru_cache"):
            # If it's @cache() or @lru_cache() without maxsize, it's unbounded
            return not self._has_eviction_keyword(node)

        if call_name == "dict":
            # dict() without size limit is unbounded
            return True

        # Check for cachetools caches
        if call_name and "Cache" in call_name:
            # cachetools caches should have maxsize or ttl
            return not self._has_eviction_keyword(node)

        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions to check for cache decorators."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                # Handle @cache(maxsize=...) or @lru_cache(maxsize=...)
                if self._is_cache_decorator(decorator.func):
                    if not self._has_eviction_keyword(decorator):
                        self.violations.append(
                            (
                                node.lineno,
                                f"Function '{node.name}' uses cache decorator without eviction policy",
                            )
                        )
            elif isinstance(decorator, ast.Name):
                # Handle @cache without parentheses (functools.cache)
                if decorator.id == "cache":
                    self.violations.append(
                        (
                            node.lineno,
                            f"Function '{node.name}' uses @cache without eviction policy - use @lru_cache(maxsize=...) or add TTL",
                        )
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to detect dict-based caches without eviction."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                # Check if variable name suggests it's a cache
                if "cache" in var_name or "memo" in var_name:
                    # Check if assigned value is a dict or empty dict
                    if isinstance(node.value, ast.Dict):
                        # {} or dict() assignment to cache variable
                        self.violations.append(
                            (
                                node.lineno,
                                f"Variable '{target.id}' is a dict-based cache without eviction policy",
                            )
                        )
                    elif isinstance(node.value, ast.Call):
                        if isinstance(node.value.func, ast.Name):
                            if node.value.func.id == "dict":
                                self.violations.append(
                                    (
                                        node.lineno,
                                        f"Variable '{target.id}' is a dict-based cache without eviction policy",
                                    )
                                )

        self.generic_visit(node)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _find_cache_violations(tree: ast.Module) -> list[tuple[int, str]]:
    """Find all cache violations in an AST."""
    visitor = CacheEvictionVisitor()
    visitor.visit(tree)
    return visitor.violations


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_174_memory_cache_has_eviction_policy() -> None:
    """#174: Memory caches must have eviction policies to prevent OOM.

    Unbounded memory caches (functools.cache, dict-based caches) without
    eviction policies can grow indefinitely, causing memory exhaustion.

    Caches should use:
    - maxsize parameter (for lru_cache)
    - TTL/time-based expiration
    - Size-based eviction (LRU, LFU)
    - Or be documented as bounded by design

    Acceptance criteria:
    - All cache decorators have maxsize or TTL
    - Dict-based caches used for caching have eviction logic
    - Module-level cache variables have documented bounds

    Epic: #146
    """
    all_violations: list[str] = []

    for file_path in _CACHE_RELEVANT_FILES:
        if not file_path.exists():
            continue

        tree = _parse(file_path)
        violations = _find_cache_violations(tree)

        for lineno, message in violations:
            all_violations.append(f"{_rel(file_path)}:{lineno}: {message}")

    assert all_violations == [], (
        "Memory caches without eviction policies detected.\n"
        "Caches must have eviction policies (maxsize, TTL) to prevent OOM.\n"
        "Use @lru_cache(maxsize=...) instead of @cache, or add TTL-based eviction.\n"
        "See #174 and parent bug #174.\n\n" + "\n".join(all_violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector for #208 - webhook cache without eviction",
    strict=False,
)
def test_208_webhook_app_cache_has_eviction() -> None:
    """#208: Webhook server app cache must have size/time bounds.

    The _app_instance cache in webhook/server.py should have an eviction
    policy to prevent unbounded memory growth during long-running processes.

    Parent bug: #174
    Epic: #146
    """
    webhook_path = _SRC / "webhook" / "server.py"
    if not webhook_path.exists():
        pytest.skip("Webhook server file not found")

    tree = _parse(webhook_path)

    # Find module-level cache variables
    cache_vars: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if "app" in target.id.lower() and "instance" in target.id.lower():
                        # This is likely _app_instance
                        cache_vars.append((node.lineno, target.id))

    # The violation is that _app_instance is stored indefinitely without eviction
    # For a long-running webhook server, this should have a TTL or be refreshed
    violations: list[str] = []

    for lineno, var_name in cache_vars:
        # Check if there's any TTL or eviction logic for this variable
        has_eviction = False

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Look for any function that might implement eviction
                func_body = ast.dump(node)
                if var_name in func_body and (
                    "ttl" in func_body.lower() or "expire" in func_body.lower()
                ):
                    has_eviction = True
                    break

        if not has_eviction:
            violations.append(
                f"{_rel(webhook_path)}:{lineno}: "
                f"Variable '{var_name}' has no eviction policy - "
                f"consider adding TTL or periodic refresh"
            )

    assert violations == [], (
        "Webhook app cache lacks eviction policy.\n"
        "Module-level app instance should have TTL-based eviction for long-running processes.\n"
        "Consider using cachetools.TTLCache or periodic refresh logic.\n"
        "See #208 and parent bug #174.\n\n" + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector for #208 - agent settings cache without eviction",
    strict=False,
)
def test_208_agent_settings_cache_has_eviction() -> None:
    """#208: Agent settings cache must have TTL or size bounds.

    The get_agent_settings() function in agent/tool_helpers.py uses
    @functools.cache without an eviction policy. Settings should be
    refreshed periodically to pick up configuration changes.

    Parent bug: #174
    Epic: #146
    """
    tool_helpers_path = _SRC / "agent" / "tool_helpers.py"
    if not tool_helpers_path.exists():
        pytest.skip("Tool helpers file not found")

    tree = _parse(tool_helpers_path)

    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.name == "get_agent_settings":
                # Check decorators
                for decorator in node.decorator_list:
                    decorator_str = ast.dump(decorator)

                    # Check for @functools.cache or @cache without maxsize
                    if "cache" in decorator_str.lower():
                        if "maxsize" not in decorator_str and "ttl" not in decorator_str:
                            violations.append(
                                f"{_rel(tool_helpers_path)}:{node.lineno}: "
                                f"Function 'get_agent_settings' uses cache without eviction policy\n"
                                f"  Decorator: {ast.unparse(decorator) if hasattr(ast, 'unparse') else decorator_str}"
                            )

    assert violations == [], (
        "Agent settings cache lacks eviction policy.\n"
        "Settings cached with @functools.cache cannot be refreshed without process restart.\n"
        "Use @lru_cache(maxsize=1) with cache_clear() or add TTL-based caching.\n"
        "See #208 and parent bug #174.\n\n" + "\n".join(violations)
    )
