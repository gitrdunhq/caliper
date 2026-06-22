# tested-by: tests/unit/test_deterministic_cycle_guards.py
"""Deterministic cycle detection guards for dependency graph builder (#231).

Detects when the CodeGraph dependency graph builder lacks circular dependency
cycle detection. This is a deterministic bug detector that will fail until
cycle detection is properly implemented in the graph building methods.

Parent bug: #197
Epic: #146
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #231 — fix the source code, then this test goes green",
    strict=False,
)

import ast
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Graph builder module paths
_GRAPH_BUILDER_PATH = _SRC / "plugins" / "_runners" / "graph_builder.py"


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    """Get repo-relative path string."""
    return path.relative_to(_REPO).as_posix()


def _get_function_node(
    tree: ast.Module, func_name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find a function definition by name in the AST."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return node
    return None


def _get_method_node(
    tree: ast.Module, class_name: str, method_name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find a method definition by class and method name in the AST."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name == method_name
                ):
                    return item
    return None


def _has_cycle_detection_in_function(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """
    Check if a function has cycle detection logic.

    Cycle detection indicators:
    1. Uses a 'visited' set for tracking seen nodes
    2. Checks for node in visited before processing
    3. Has 'cycle' in variable/function names
    4. Detects circular/recursive patterns
    """
    # Get function source as string for simple pattern matching
    func_source = ast.unparse(func_node)

    # Check for visited set pattern (common cycle detection technique)
    has_visited_set = "visited" in func_source and ("set()" in func_source or "set" in func_source)

    # Check for cycle-related naming
    has_cycle_naming = "cycle" in func_source.lower() or "circular" in func_source.lower()

    # Check for recursion depth limiting (another cycle prevention technique)
    has_depth_limit = "depth" in func_source and (
        "max_depth" in func_source or "limit" in func_source
    )

    # Check for parent/ancestor tracking (detects cycles in tree/graph traversal)
    has_parent_tracking = (
        "parent" in func_source or "ancestor" in func_source or "path" in func_source
    )

    # Check for recursive call with visited check pattern
    has_recursive_guard = False
    for node in ast.walk(func_node):
        if isinstance(node, ast.If):
            # Check if condition checks for membership in visited
            condition_source = ast.unparse(node.test)
            if "in visited" in condition_source or "visited" in condition_source:
                has_recursive_guard = True
                break

    return (
        has_visited_set
        or has_cycle_naming
        or has_depth_limit
        or has_parent_tracking
        or has_recursive_guard
    )


def _function_adds_edges_without_cycle_check(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """
    Check if a function adds edges without cycle detection.

    Returns True if function adds edges but lacks cycle detection.
    """
    func_source = ast.unparse(func_node).lower()

    # Check for edge addition patterns
    adds_edges = (
        "_add_edge" in func_source
        or "edges" in func_source
        or "insert" in func_source
        and "edge" in func_source
    )

    if not adds_edges:
        return False  # Doesn't add edges, no cycle risk

    # Check if it has cycle detection
    has_cycle_detection = _has_cycle_detection_in_function(func_node)

    # Returns True if it adds edges but has no cycle detection
    return adds_edges and not has_cycle_detection


@pytest.mark.xfail(reason="deterministic bug detector for #231", strict=False)
def test_graph_builder_add_edge_has_no_cycle_detection() -> None:
    """#231: CodeGraph._add_edge() lacks circular dependency detection.

    The _add_edge method inserts edges into the graph without checking
    if the edge would create a circular dependency. This could lead to
    infinite loops during traversal and incorrect graph topology.

    Expected fix: Add cycle detection before edge insertion or in the
    indexing methods that call _add_edge.
    """
    if not _GRAPH_BUILDER_PATH.exists():
        pytest.skip("Graph builder not found")

    tree = _parse(_GRAPH_BUILDER_PATH)

    # Find _add_edge method
    add_edge_method = _get_method_node(tree, "CodeGraph", "_add_edge")

    if add_edge_method is None:
        # Method might be renamed or refactored - check for any edge-adding function
        add_edge_func = _get_function_node(tree, "_add_edge")
        if add_edge_func is None:
            pytest.skip("_add_edge method not found - may have been renamed")
        add_edge_method = add_edge_func

    # Check if _add_edge has cycle detection
    has_cycle_detection = _has_cycle_detection_in_function(add_edge_method)

    violations: list[str] = []
    if not has_cycle_detection:
        violations.append(
            f"{_rel(_GRAPH_BUILDER_PATH)}:{add_edge_method.lineno}: "
            "_add_edge() adds edges without circular dependency detection. "
            "Missing: visited set check, cycle detection, or parent tracking."
        )

    assert violations == [], (
        "Graph builder _add_edge() must detect circular dependencies before adding edges.\n"
        "Add cycle detection to prevent infinite loops and invalid graph topology:\n"
        + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #231", strict=False)
def test_graph_builder_index_python_has_no_cycle_detection() -> None:
    """#231: CodeGraph._index_python() builds graph without cycle detection.

    The _index_python method processes Python AST and adds edges for
    function calls, imports, and inheritance without checking for cycles.
    This can create circular dependencies in the graph during indexing.

    Expected fix: Add cycle detection when adding edges in _index_python
    or in the _add_edge method it calls.
    """
    if not _GRAPH_BUILDER_PATH.exists():
        pytest.skip("Graph builder not found")

    tree = _parse(_GRAPH_BUILDER_PATH)

    # Find _index_python method
    index_python_method = _get_method_node(tree, "CodeGraph", "_index_python")

    if index_python_method is None:
        pytest.skip("_index_python method not found")

    # Check if _index_python adds edges without cycle detection
    adds_edges_without_check = _function_adds_edges_without_cycle_check(index_python_method)

    violations: list[str] = []
    if adds_edges_without_check:
        violations.append(
            f"{_rel(_GRAPH_BUILDER_PATH)}:{index_python_method.lineno}: "
            "_index_python() adds edges (via _add_edge) without cycle detection. "
            "Graph can contain circular dependencies after indexing."
        )

    assert violations == [], (
        "Graph builder _index_python() must prevent circular dependencies.\n"
        "Add cycle detection during graph construction:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #231", strict=False)
def test_graph_builder_index_javascript_has_no_cycle_detection() -> None:
    """#231: CodeGraph._index_javascript() builds graph without cycle detection.

    The _index_javascript method processes JavaScript/TypeScript source and
    adds edges without checking for circular dependencies. Like _index_python,
    this can create cycles in the dependency graph.

    Expected fix: Add cycle detection when adding edges in _index_javascript
    or in the _add_edge method it calls.
    """
    if not _GRAPH_BUILDER_PATH.exists():
        pytest.skip("Graph builder not found")

    tree = _parse(_GRAPH_BUILDER_PATH)

    # Find _index_javascript method
    index_js_method = _get_method_node(tree, "CodeGraph", "_index_javascript")

    if index_js_method is None:
        pytest.skip("_index_javascript method not found")

    # Check if _index_javascript adds edges without cycle detection
    adds_edges_without_check = _function_adds_edges_without_cycle_check(index_js_method)

    violations: list[str] = []
    if adds_edges_without_check:
        violations.append(
            f"{_rel(_GRAPH_BUILDER_PATH)}:{index_js_method.lineno}: "
            "_index_javascript() adds edges (via _add_edge) without cycle detection. "
            "Graph can contain circular dependencies after indexing."
        )

    assert violations == [], (
        "Graph builder _index_javascript() must prevent circular dependencies.\n"
        "Add cycle detection during graph construction:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #231", strict=False)
def test_graph_builder_add_import_edge_has_no_cycle_detection() -> None:
    """#231: CodeGraph._add_import_edge() lacks circular dependency detection.

    The _add_import_edge method adds import edges between modules without
    checking if this creates a circular import dependency. Module import cycles
    are common and should be detected and flagged.

    Expected fix: Add cycle detection before adding import edges.
    """
    if not _GRAPH_BUILDER_PATH.exists():
        pytest.skip("Graph builder not found")

    tree = _parse(_GRAPH_BUILDER_PATH)

    # Find _add_import_edge method
    add_import_method = _get_method_node(tree, "CodeGraph", "_add_import_edge")

    if add_import_method is None:
        pytest.skip("_add_import_edge method not found")

    # Check if _add_import_edge has cycle detection
    has_cycle_detection = _has_cycle_detection_in_function(add_import_method)

    violations: list[str] = []
    if not has_cycle_detection:
        violations.append(
            f"{_rel(_GRAPH_BUILDER_PATH)}:{add_import_method.lineno}: "
            "_add_import_edge() adds import edges without circular dependency detection. "
            "Missing: visited set check, cycle detection, or parent tracking."
        )

    assert violations == [], (
        "Graph builder _add_import_edge() must detect circular import dependencies.\n"
        "Add cycle detection to prevent circular import cycles:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #231", strict=False)
def test_graph_builder_index_file_has_no_cycle_detection() -> None:
    """#231: CodeGraph.index_file() calls edge addition without cycle detection.

    The index_file method is the public entry point for adding files to the
    graph. It delegates to _index_python and _index_javascript which both add
    edges without cycle detection. This is the root cause of #197.

    Expected fix: Add cycle detection at the entry point (index_file) or in
    the underlying _add_edge method.
    """
    if not _GRAPH_BUILDER_PATH.exists():
        pytest.skip("Graph builder not found")

    tree = _parse(_GRAPH_BUILDER_PATH)

    # Find index_file method
    index_file_method = _get_method_node(tree, "CodeGraph", "index_file")

    if index_file_method is None:
        pytest.skip("index_file method not found")

    # Check source for calls to indexing methods that add edges
    func_source = ast.unparse(index_file_method)

    # index_file calls _index_python or _index_javascript which add edges
    calls_indexers = "_index_python" in func_source or "_index_javascript" in func_source

    # Check if index_file itself has cycle detection
    has_cycle_detection = _has_cycle_detection_in_function(index_file_method)

    violations: list[str] = []
    if calls_indexers and not has_cycle_detection:
        violations.append(
            f"{_rel(_GRAPH_BUILDER_PATH)}:{index_file_method.lineno}: "
            "index_file() calls _index_python/_index_javascript which add edges "
            "without cycle detection. Entry point lacks circular dependency guards."
        )

    assert violations == [], (
        "Graph builder index_file() entry point must prevent circular dependencies.\n"
        "Add cycle detection at the public API boundary:\n" + "\n".join(violations)
    )
