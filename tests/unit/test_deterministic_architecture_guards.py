# tested-by: tests/unit/test_deterministic_architecture_guards.py
"""Enforced tier-boundary guard (#404 Phase 6, closes #231).

A single AST walk over every ``src/caliper`` module checks that imports only
cross tier boundaries in the allowed direction. This is the mechanically
enforced invariant that locks in the ports-&-adapters refactor — it is **not**
``xfail``: a new upward/skip-tier import fails CI.

Tier map (mirrors datum-ax ``tests/test_architecture.py``):

* presentation (``cli`` / ``agent`` / ``webhook`` / ``composition``) — may
  import anything; this is where concrete adapters are wired.
* ``core`` — may import only core + the shared kernel. Never presentation,
  never data/adapters/plugins/detectors.
* ``data`` / ``adapters`` / ``plugins`` / ``detectors`` — may import core
  (where the ports/contracts live), the shared kernel, and themselves. Never
  presentation, never a sibling outer tier.
* kernel (``caliper._base`` / ``caliper.registry``) — importable everywhere,
  depends on nothing in ``caliper``.

The test is import-free (pure AST), so it is container-safe.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Top-level directory under src/caliper -> tier name.
_TIER_BY_DIR = {
    "cli": "presentation",
    "agent": "presentation",
    "webhook": "presentation",
    "composition": "presentation",
    "core": "core",
    "data": "data",
    "adapters": "adapters",
    "plugins": "plugins",
    "detectors": "detectors",
}

# Directories that contain no importable cross-tier code (templates are Jinja).
_SKIP_DIRS = {"templates"}

# Root-level modules form the shared kernel (importable everywhere); derived from
# src/caliper/*.py so a future kernel module is picked up automatically.
_KERNEL_MODULES = {p.stem for p in _SRC.glob("*.py") if p.stem != "__init__"}

_ANY = {"presentation", "core", "data", "adapters", "plugins", "detectors", "kernel"}

# source tier -> set of target tiers it is allowed to import.
_ALLOWED: dict[str, set[str]] = {
    "presentation": _ANY,
    "core": {"core", "kernel"},
    "data": {"data", "core", "kernel"},
    "adapters": {"adapters", "core", "kernel"},
    "plugins": {"plugins", "core", "kernel"},
    "detectors": {"detectors", "core", "kernel"},
    "kernel": {"kernel"},
}


def _python_files() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _source_tier(path: Path) -> str | None:
    """Tier of a source file, or None when it should be skipped."""
    rel = path.relative_to(_SRC).parts
    if len(rel) == 1:  # src/caliper/<file>.py
        # The package-root __init__ is the public-API facade (may re-export from
        # any tier); _base/registry are the strict shared kernel.
        return "presentation" if rel[0] == "__init__.py" else "kernel"
    top = rel[0]
    if top in _SKIP_DIRS:
        return None
    return _TIER_BY_DIR.get(top)


def _target_tier(module: str) -> str:
    """Tier an imported ``caliper.*`` module belongs to.

    Unmapped packages resolve to ``"unknown"`` (in no tier's allow-set) so a
    typo'd or future top-level package fails the boundary check instead of
    silently passing as kernel.
    """
    parts = module.split(".")
    if len(parts) < 2:  # bare ``caliper``
        return "kernel"
    second = parts[1]
    if second in _TIER_BY_DIR:
        return _TIER_BY_DIR[second]
    if second in _KERNEL_MODULES or second in _SKIP_DIRS:
        return "kernel"
    return "unknown"


def _imported_caliper_modules(tree: ast.Module) -> list[tuple[str, int]]:
    """Every ``caliper.*`` module imported anywhere in the file (incl. lazy)."""
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("caliper"):
                    out.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            # Relative imports stay within the same package/tier — skip them.
            if node.level == 0 and node.module and node.module.startswith("caliper"):
                out.append((node.module, node.lineno))
    return out


def test_no_unknown_top_level_packages() -> None:
    """Guard the tier map itself: every src/caliper dir is mapped or explicitly skipped."""
    dirs = {p.name for p in _SRC.iterdir() if p.is_dir() and p.name != "__pycache__"}
    known = set(_TIER_BY_DIR) | _SKIP_DIRS
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
    assert _target_tier("caliper.registry") == "kernel"
    assert _target_tier("caliper._base") == "kernel"


def test_tier_boundaries_are_not_crossed() -> None:
    """No module imports another tier in a disallowed direction."""
    violations: list[str] = []

    for path in _python_files():
        src_tier = _source_tier(path)
        if src_tier is None:
            continue
        allowed = _ALLOWED[src_tier]
        tree = ast.parse(path.read_text(), filename=str(path))
        for module, lineno in _imported_caliper_modules(tree):
            tgt_tier = _target_tier(module)
            if tgt_tier not in allowed:
                rel = path.relative_to(_REPO).as_posix()
                violations.append(f"{rel}:{lineno}: {src_tier} -> {tgt_tier} (import {module})")

    assert (
        violations == []
    ), "Tier boundary violations (a module imported a tier it must not depend on):\n" + "\n".join(
        violations
    )
