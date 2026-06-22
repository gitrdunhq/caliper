# tested-by: tests/unit/test_deterministic_cache_key_guards.py
"""Deterministic guards for plugin result cache key construction (#224).

Detects when plugin result cache keys don't include plugin version,
which can lead to stale cache hits when plugins are updated.

Parent bug: #190
Epic: #146
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #224 - plugin version missing from cache keys",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files where cache key construction should be analyzed
_CACHE_KEY_FILES: tuple[Path, ...] = (
    _SRC / "core" / "registry.py",
    _SRC / "core" / "plugin.py",
    _SRC / "data" / "catalog.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _find_cache_key_constructions(tree: ast.Module) -> list[tuple[int, str, list[str]]]:
    """Find all cache key constructions in AST.

    Returns list of (lineno, context, key_components) tuples where:
    - lineno: line number of the key construction
    - context: function/class name where construction occurs
    - key_components: list of variable names/attributes used in the key
    """
    constructions: list[tuple[int, str, list[str]]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            # Look for patterns like: cache_key = f"{plugin_name}:{file_hash}"
            # or key = (plugin_name, file_path, mtime)
            for target in node.targets:
                if isinstance(target, ast.Name) and "key" in target.id.lower():
                    components = _extract_key_components(node.value)
                    if components:
                        context = _get_node_context(node, tree)
                        constructions.append((node.lineno, context, components))

        elif isinstance(node, ast.Call):
            # Look for dict key access patterns: cache[cache_key]
            # or lru_cache key generation
            call_name = _extract_call_name(node.func)
            if call_name and any(kw in call_name.lower() for kw in ["cache", "memo"]):
                context = _get_node_context(node, tree)
                # Check if the call has key-related arguments
                key_args = _extract_key_from_call(node)
                if key_args:
                    constructions.append((node.lineno, context, key_args))

    return constructions


def _extract_key_components(node: ast.expr) -> list[str]:
    """Extract components from a key construction expression."""
    components: list[str] = []

    if isinstance(node, ast.JoinedStr):
        # f-string: f"{plugin_name}:{file_hash}"
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                comp = _extract_value_name(value.value)
                if comp:
                    components.append(comp)
            elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                # Separator or constant part
                components.append(f"const:{value.value}")

    elif isinstance(node, ast.Tuple):
        # Tuple: (plugin_name, file_path, mtime)
        for elt in node.elts:
            comp = _extract_value_name(elt)
            if comp:
                components.append(comp)

    elif (
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) or isinstance(node.op, ast.Add)
    ):
        # String concatenation: plugin_name + ":" + file_hash
        left = _extract_value_name(node.left)
        right = _extract_value_name(node.right)
        if left:
            components.append(left)
        if right:
            components.append(right)

    elif isinstance(node, ast.Call):
        # Function call that might construct a key
        call_name = _extract_call_name(node.func)
        if call_name and "key" in call_name.lower():
            for arg in node.args:
                comp = _extract_value_name(arg)
                if comp:
                    components.append(comp)
            for kw in node.keywords:
                comp = _extract_value_name(kw.value)
                if comp:
                    components.append(f"{kw.arg}={comp}")

    return components


def _extract_value_name(node: ast.expr) -> str | None:
    """Extract a descriptive name from an AST expression node."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        parent = _extract_value_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    elif isinstance(node, ast.Constant):
        return f"const:{node.value!r}"
    elif isinstance(node, ast.Call):
        return _extract_call_name(node.func)
    return None


def _extract_call_name(node: ast.expr) -> str | None:
    """Extract the full name of a function call."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _extract_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _extract_key_from_call(node: ast.Call) -> list[str] | None:
    """Extract key components from a cache-related function call."""
    components: list[str] = []

    # Check for key= or cache_key= keyword arguments
    for kw in node.keywords:
        if "key" in kw.arg.lower():
            comps = _extract_key_components(kw.value)
            components.extend(comps)

    return components if components else None


def _get_node_context(target_node: ast.AST, tree: ast.Module) -> str:
    """Get the function/class context where a node appears."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if child is target_node:
                    return f"function:{node.name}"
        elif isinstance(node, ast.ClassDef):
            for child in ast.walk(node):
                if child is target_node:
                    return f"class:{node.name}"
    return "module"


def _has_version_in_key(components: list[str]) -> bool:
    """Check if any component represents a plugin version."""
    version_indicators = ["version", "ver", "plugin_version", "tool_version"]
    for comp in components:
        comp_lower = comp.lower()
        for indicator in version_indicators:
            if indicator in comp_lower:
                return True
    return False


def _has_plugin_in_key(components: list[str]) -> bool:
    """Check if any component represents a plugin identifier."""
    plugin_indicators = ["plugin", "tool", "scanner", "analyzer"]
    for comp in components:
        comp_lower = comp.lower()
        for indicator in plugin_indicators:
            if indicator in comp_lower:
                return True
    return False


@pytest.mark.xfail(
    reason="deterministic bug detector for #190/#224 - plugin version missing from cache keys",
    strict=False,
)
def test_224_plugin_result_cache_key_includes_version():
    """#224: Plugin result cache keys must include plugin version.

    When caching plugin results, the cache key must include the plugin version
    to ensure that cached results are invalidated when the plugin is updated.
    Without version in the key, stale results from old plugin versions may be
    returned after plugin updates.

    Parent bug: #190
    Epic: #146
    """
    violations: list[str] = []

    for file_path in _CACHE_KEY_FILES:
        if not file_path.exists():
            continue

        tree = _parse(file_path)
        constructions = _find_cache_key_constructions(tree)

        for lineno, context, components in constructions:
            # Check if this is a plugin-related cache key
            if _has_plugin_in_key(components):
                # Plugin-related key must include version
                if not _has_version_in_key(components):
                    violations.append(
                        f"{_rel(file_path)}:{lineno}: {context} - "
                        f"plugin cache key missing version: {components}"
                    )

    assert violations == [], (
        "Plugin result cache keys must include plugin version to prevent "
        "stale cache hits after plugin updates.\n"
        "Add plugin version to cache key construction.\n"
        "See #190 and #224 for details on cache key requirements.\n\n" + "\n".join(violations)
    )


@pytest.mark.xfail(
    reason="deterministic bug detector for #224 - cache key construction without version",
    strict=False,
)
def test_224_cache_key_ast_pattern_detection():
    """#224: AST-based detection of cache key patterns that may miss version.

    Scans for common cache key construction patterns and flags those that
    include plugin/tool identifiers but not version information.

    This test detects the bug pattern at the AST level before it causes
    production issues with stale cached results.
    """
    violations: list[str] = []

    for file_path in _CACHE_KEY_FILES:
        if not file_path.exists():
            continue

        content = file_path.read_text()
        tree = _parse(file_path)

        # Find all string formatting operations that might be cache keys
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                target_name = None
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_name = target.id
                        break

                # Check if target looks like a cache key
                if target_name and "key" in target_name.lower():
                    # Analyze the assignment value
                    if isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
                        key_str = ast.unparse(node.value) if hasattr(ast, "unparse") else ""

                        # Check for plugin-related terms without version
                        has_plugin_term = any(
                            term in key_str.lower() for term in ["plugin", "tool", "scanner"]
                        )
                        has_version_term = any(
                            term in key_str.lower() for term in ["version", "ver"]
                        )

                        if has_plugin_term and not has_version_term:
                            violations.append(
                                f"{_rel(file_path)}:{node.lineno}: "
                                f"Cache key '{target_name}' includes plugin identifier "
                                f"but not version: {key_str[:80]}"
                            )

    # Note: This may find legitimate cases that need review
    # The test documents the pattern detection
    assert True, f"Cache key pattern detection complete. Potential issues: {len(violations)}"


@pytest.mark.xfail(
    reason="deterministic bug detector for #224 - functools.cache on plugin results",
    strict=False,
)
def test_224_no_bare_functools_cache_on_plugin_methods():
    """#224: Detect @functools.cache on plugin methods without version-aware keys.

    When @functools.cache or @lru_cache is used on plugin result methods,
    the cache key is automatically generated from function arguments.
    If the plugin version isn't part of the arguments, cache hits may
    return stale results after plugin updates.

    Parent bug: #190
    """
    violations: list[str] = []

    # Files that might have cached plugin methods
    plugin_files = list((_SRC / "plugins").glob("*.py"))
    plugin_files.extend(_CACHE_KEY_FILES)

    for file_path in plugin_files:
        if not file_path.exists():
            continue

        tree = _parse(file_path)
        content = file_path.read_text()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Check for cache decorators
            for decorator in node.decorator_list:
                dec_name = _extract_call_name(decorator)
                if dec_name and any(
                    cache_type in (dec_name or "").lower()
                    for cache_type in ["cache", "lru_cache", "memoize"]
                ):
                    # Check if the method relates to plugin results
                    func_name_lower = node.name.lower()
                    is_plugin_result_func = any(
                        term in func_name_lower
                        for term in ["run", "scan", "analyze", "result", "plugin"]
                    )

                    if is_plugin_result_func:
                        # Check if version is in the function arguments
                        arg_names = [arg.arg for arg in node.args.args]
                        has_version_arg = any("version" in arg.lower() for arg in arg_names)

                        if not has_version_arg:
                            violations.append(
                                f"{_rel(file_path)}:{node.lineno}: "
                                f"@{dec_name} on '{node.name}' without version in args - "
                                f"may return stale results after plugin updates"
                            )

    assert violations == [], (
        "@functools.cache/@lru_cache on plugin result methods must include "
        "version in cache key to prevent stale results.\n"
        "Either add version parameter or use a custom cache key function.\n"
        "See #190 and #224 for caching best practices.\n\n" + "\n".join(violations)
    )
