# tested-by: tests/unit/test_deterministic_architecture_guards.py
"""Pure tier-boundary resolution shared by the architecture guard test and the
CAL-022 tier-boundary detector.

Mirrors the ports-&-adapters layering (#404 Phase 6, closes #231):

* presentation (``cli`` / ``agent`` / ``webhook`` / ``composition``) — may
  import anything; this is where concrete adapters are wired.
* ``core`` — may import only core + the shared kernel. Never presentation,
  never data/adapters/plugins/detectors.
* ``data`` / ``adapters`` / ``plugins`` / ``detectors`` — may import core
  (where the ports/contracts live), the shared kernel, and themselves. Never
  presentation, never a sibling outer tier.
* kernel (root-level ``src/caliper/*.py`` modules, e.g. ``_base`` /
  ``adapter_registry``) — importable everywhere, depends on nothing in ``caliper``.

Every function here is pure (no I/O beyond reading paths already handed to
it), so it is safe to reuse from both a container-free test and a scanner
detector.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Top-level directory under src/caliper -> tier name.
DEFAULT_TIER_BY_DIR: dict[str, str] = {
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
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({"templates"})

ANY_TIER: frozenset[str] = frozenset(
    {"presentation", "core", "data", "adapters", "plugins", "detectors", "kernel"}
)

# source tier -> set of target tiers it is allowed to import.
DEFAULT_ALLOWED: dict[str, frozenset[str]] = {
    "presentation": ANY_TIER,
    "core": frozenset({"core", "kernel"}),
    "data": frozenset({"data", "core", "kernel"}),
    "adapters": frozenset({"adapters", "core", "kernel"}),
    "plugins": frozenset({"plugins", "core", "kernel"}),
    "detectors": frozenset({"detectors", "core", "kernel"}),
    "kernel": frozenset({"kernel"}),
}


def kernel_modules(src_root: Path) -> frozenset[str]:
    """Root-level modules that form the shared kernel (importable everywhere).

    Derived from ``<src_root>/*.py`` so a future kernel module is picked up
    automatically.
    """
    return frozenset(p.stem for p in src_root.glob("*.py") if p.stem != "__init__")


def source_tier(
    path: Path,
    src_root: Path,
    tier_by_dir: dict[str, str] = DEFAULT_TIER_BY_DIR,
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
) -> str | None:
    """Tier of a source file under ``src_root``, or None when it should be skipped."""
    rel = path.relative_to(src_root).parts
    if len(rel) == 1:  # <src_root>/<file>.py
        # The package-root __init__ is the public-API facade (may re-export from
        # any tier); other root modules are the strict shared kernel.
        return "presentation" if rel[0] == "__init__.py" else "kernel"
    top = rel[0]
    if top in skip_dirs:
        return None
    return tier_by_dir.get(top)


def target_tier(
    module: str,
    tier_by_dir: dict[str, str] = DEFAULT_TIER_BY_DIR,
    kernel_mods: frozenset[str] | None = None,
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
    package_name: str = "caliper",
) -> str:
    """Tier an imported ``<package_name>.*`` module belongs to.

    Unmapped packages resolve to ``"unknown"`` (in no tier's allow-set) so a
    typo'd or future top-level package fails the boundary check instead of
    silently passing as kernel.
    """
    parts = module.split(".")
    if len(parts) < 2:  # bare ``caliper``
        return "kernel"
    second = parts[1]
    if second in tier_by_dir:
        return tier_by_dir[second]
    if second in skip_dirs:
        return "kernel"
    if kernel_mods is not None and second in kernel_mods:
        return "kernel"
    return "unknown"


def resolve_relative_import(
    module: str | None,
    level: int,
    source_file: Path,
    src_root: Path,
    package_name: str = "caliper",
) -> str | None:
    """Resolve a relative import (``from . import x`` / ``from ..data import y``)
    to an absolute ``<package_name>.*`` dotted module path.

    ``level`` is the AST ``ImportFrom.level`` (number of leading dots). The
    package containing ``source_file`` is derived by dropping its filename —
    this is correct uniformly for both plain modules and ``__init__.py``,
    since Python's own ``__package__`` resolution works the same way.

    Returns ``None`` when the import climbs above ``src_root`` (it cannot be
    a ``<package_name>.*`` module in that case).
    """
    pkg_parts = list(source_file.relative_to(src_root).parts[:-1])
    climb = level - 1
    if climb > len(pkg_parts):
        return None
    if climb:
        pkg_parts = pkg_parts[: len(pkg_parts) - climb]
    parts = [package_name, *pkg_parts]
    if module:
        parts.extend(module.split("."))
    return ".".join(parts)


def imported_caliper_modules(
    tree: ast.Module,
    source_file: Path,
    src_root: Path,
    package_name: str = "caliper",
) -> list[tuple[str, int]]:
    """Every ``<package_name>.*`` module imported anywhere in the file.

    Includes lazy (function-local) imports and relative imports — a relative
    import is resolved to its absolute form via ``resolve_relative_import``
    rather than being assumed to stay within the same tier (#see-something:
    a two-level-up relative import can silently cross a tier boundary).
    """
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(package_name):
                    out.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module and node.module.startswith(package_name):
                    out.append((node.module, node.lineno))
            else:
                resolved = resolve_relative_import(
                    node.module, node.level, source_file, src_root, package_name
                )
                if resolved and resolved.startswith(package_name):
                    out.append((resolved, node.lineno))
    return out
