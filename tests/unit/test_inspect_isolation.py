"""Structural isolation: the deterministic tiers cannot reach the LLM path.

# tested-by: tests/unit/test_inspect_isolation.py

Invariant 3: Tier 0 (gauges) and Tier 2 (adjudicator) must be structurally unable
to import the LLM path — the concrete backends (``plugins/_inspect_llm.py``) and the
Tier 1 runner (``core/inspect_runner.py``). This mirrors how the PARTING registry is
isolated from the auto pipeline. We assert it by parsing the modules' imports (a
real import would otherwise let the deterministic path smuggle in a model call).
"""

from __future__ import annotations

import ast
from pathlib import Path

import caliper.core.inspect as tier2_mod
import caliper.core.inspect_gauges as tier0_mod

# The forbidden LLM-path modules (where a model is actually invoked).
_FORBIDDEN = {
    "caliper.plugins._inspect_llm",
    "caliper.core.inspect_runner",
    "caliper.core.llm_port",
}


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_tier2_adjudicator_does_not_import_llm_path() -> None:
    imports = _imported_modules(Path(tier2_mod.__file__))
    leaked = imports & _FORBIDDEN
    assert not leaked, f"Tier 2 adjudicator imports the LLM path: {leaked}"


def test_tier0_gauges_do_not_import_llm_path() -> None:
    imports = _imported_modules(Path(tier0_mod.__file__))
    leaked = imports & _FORBIDDEN
    assert not leaked, f"Tier 0 gauges import the LLM path: {leaked}"
