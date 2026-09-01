# tested-by: tests/unit/test_deterministic_architecture_guards.py
"""Enforced tier-boundary guard (#404 Phase 6, closes #231).

A single AST walk over every ``src/caliper`` module checks that imports only
cross tier boundaries in the allowed direction. This is the mechanically
enforced invariant that locks in the ports-&-adapters refactor — it is **not**
``xfail``: a new upward/skip-tier import fails CI.

Tier map (mirrors datum-ax ``tests/test_architecture.py``); the resolution
logic itself lives in ``caliper.core.tier_map`` (shared with the CAL-022
tier-boundary detector):

* presentation (``cli`` / ``webhook`` / ``composition``) — may
  import anything; this is where concrete adapters are wired.
* ``core`` — may import only core + the shared kernel. Never presentation,
  never data/adapters/plugins/detectors.
* ``data`` / ``adapters`` / ``plugins`` / ``detectors`` — may import core
  (where the ports/contracts live), the shared kernel, and themselves. Never
  presentation, never a sibling outer tier.
* kernel (``caliper._base`` / ``caliper.adapter_registry``) — importable everywhere,
  depends on nothing in ``caliper``.

Relative imports are resolved to their absolute ``caliper.*`` form (not
skipped) — a two-level-up relative import can cross a tier boundary just as
easily as an absolute one.

The test is import-light (pure AST + the pure ``tier_map`` module, no runtime
wiring), so it is container-safe.
"""

from __future__ import annotations

import ast
from pathlib import Path

from caliper.core.tier_map import DEFAULT_ALLOWED as _ALLOWED
from caliper.core.tier_map import DEFAULT_SKIP_DIRS as _SKIP_DIRS
from caliper.core.tier_map import DEFAULT_TIER_BY_DIR as _TIER_BY_DIR
from caliper.core.tier_map import imported_caliper_modules as _resolve_imports
from caliper.core.tier_map import kernel_modules
from caliper.core.tier_map import source_tier as _resolve_source_tier
from caliper.core.tier_map import target_tier as _resolve_target_tier

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_KERNEL_MODULES = kernel_modules(_SRC)


def _python_files() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _source_tier(path: Path) -> str | None:
    return _resolve_source_tier(path, _SRC, _TIER_BY_DIR, _SKIP_DIRS)


def _target_tier(module: str) -> str:
    return _resolve_target_tier(module, _TIER_BY_DIR, _KERNEL_MODULES, _SKIP_DIRS)


def _imported_caliper_modules(tree: ast.Module, source_file: Path) -> list[tuple[str, int]]:
    return _resolve_imports(tree, source_file, _SRC)


def test_no_unknown_top_level_packages() -> None:
    """Guard the tier map itself: every src/caliper dir is mapped or explicitly skipped."""
    dirs = {p.name for p in _SRC.iterdir() if p.is_dir() and p.name != "__pycache__"}
    known = set(_TIER_BY_DIR) | set(_SKIP_DIRS)
    unmapped = dirs - known
    assert unmapped == set(), (
        f"Unmapped top-level package(s): {unmapped}. Add them to _TIER_BY_DIR "
        "(with the correct tier) or _SKIP_DIRS so the boundary stays enforced."
    )


def test_unmapped_target_is_a_violation_not_kernel() -> None:
    """An import of an unmapped caliper package fails the check (not silently kernel)."""
    assert _target_tier("caliper.bogus.thing") == "unknown"
    assert "unknown" not in _ALLOWED["core"]
    # Real tiers + the shared kernel still resolve correctly.
    assert _target_tier("caliper.data.scanners") == "data"
    assert _target_tier("caliper.adapter_registry") == "kernel"
    assert _target_tier("caliper._base") == "kernel"


def test_relative_upward_import_is_flagged() -> None:
    """A relative import that crosses a tier boundary is resolved, not silently skipped.

    ``from ..data.parquet_writer import append_decisions`` written inside a
    core-tier module resolves to ``caliper.data.parquet_writer`` — outside
    core's allow-set — and must be visible to the boundary check exactly like
    the absolute-import equivalent.
    """
    source_file = _SRC / "core" / "pipeline.py"
    tree = ast.parse("from ..data.parquet_writer import append_decisions\n")

    modules = _imported_caliper_modules(tree, source_file)

    assert modules == [("caliper.data.parquet_writer", 1)]
    module, _lineno = modules[0]
    assert _target_tier(module) == "data"
    assert _target_tier(module) not in _ALLOWED["core"]


def test_tier_boundaries_are_not_crossed() -> None:
    """No module imports another tier in a disallowed direction."""
    violations: list[str] = []

    for path in _python_files():
        src_tier = _source_tier(path)
        if src_tier is None:
            continue
        allowed = _ALLOWED[src_tier]
        tree = ast.parse(path.read_text(), filename=str(path))
        for module, lineno in _imported_caliper_modules(tree, path):
            tgt_tier = _target_tier(module)
            if tgt_tier not in allowed:
                rel = path.relative_to(_REPO).as_posix()
                violations.append(f"{rel}:{lineno}: {src_tier} -> {tgt_tier} (import {module})")

    assert (
        violations == []
    ), "Tier boundary violations (a module imported a tier it must not depend on):\n" + "\n".join(
        violations
    )


# Third-party/stdlib modules that perform real I/O (network, DB, sockets).
# core/ must stay functional-core/imperative-shell (DPS-101): these belong in
# data/adapters, wired in via a port, never imported directly by core.
_FORBIDDEN_IO_MODULES = ("httpx", "psycopg", "socket")


def _imports_forbidden_io(tree: ast.Module) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _FORBIDDEN_IO_MODULES:
                    hits.append((root, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root in _FORBIDDEN_IO_MODULES:
                    hits.append((root, node.lineno))
    return hits


def test_core_has_no_direct_io_imports() -> None:
    """core/ never imports httpx/psycopg/socket directly (DPS-101).

    Side-effecting transport belongs in data/adapters behind a port
    (see core/llm_port.py); core stays a pure functional core.
    """
    violations: list[str] = []
    core_dir = _SRC / "core"

    for path in sorted(core_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for module, lineno in _imports_forbidden_io(tree):
            rel = path.relative_to(_REPO).as_posix()
            violations.append(f"{rel}:{lineno}: core imports {module!r} directly")

    assert violations == [], (
        "core/ must not import I/O modules directly — route through a port "
        "(data/adapters), wired in composition/bootstrap.py:\n" + "\n".join(violations)
    )
