"""Structural isolation: the deterministic tiers cannot reach the LLM path.

# tested-by: tests/unit/test_inspect_isolation.py

Invariant: Screen (gauges) and Adjudicate (the adjudicator) must be structurally
unable to import the LLM path — the concrete backends (``plugins/_inspect_llm.py``),
the Review runner (``core/inspect_runner.py``), and the port (``core/llm_port.py``).
This mirrors how the PARTING registry is isolated from the auto pipeline.

We assert it **transitively**: a direct-import check would miss a leak smuggled in
one hop away (Adjudicate imports an innocent helper that imports the runner). So we
walk the full ``caliper.*`` import graph from each deterministic module and assert no
forbidden module is reachable.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

# The forbidden LLM-path modules (where a model is actually invoked or wired).
_FORBIDDEN = {
    "caliper.plugins._inspect_llm",
    "caliper.core.inspect_runner",
    "caliper.core.llm_port",
}


def _module_file(name: str) -> Path | None:
    """Resolve a ``caliper.*`` module name to its source file, or None."""
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ModuleNotFoundError, ValueError):
        return None
    if spec is None or not spec.origin or spec.origin == "built-in":
        return None
    return Path(spec.origin)


def _direct_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _transitive_caliper_imports(start: str) -> set[str]:
    """All ``caliper.*`` modules reachable from *start* via the import graph."""
    seen: set[str] = set()
    stack = [start]
    while stack:
        name = stack.pop()
        if name in seen or not name.startswith("caliper."):
            continue
        seen.add(name)
        path = _module_file(name)
        if path is None:
            continue
        for imported in _direct_imports(path):
            if imported.startswith("caliper.") and imported not in seen:
                stack.append(imported)
    return seen


def test_adjudicator_does_not_transitively_import_llm_path() -> None:
    reachable = _transitive_caliper_imports("caliper.core.inspect")
    leaked = reachable & _FORBIDDEN
    assert not leaked, f"Adjudicate reaches the LLM path (transitively): {leaked}"


def test_screen_gauges_do_not_transitively_import_llm_path() -> None:
    reachable = _transitive_caliper_imports("caliper.core.inspect_gauges")
    leaked = reachable & _FORBIDDEN
    assert not leaked, f"Screen gauges reach the LLM path (transitively): {leaked}"
