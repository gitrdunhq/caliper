# tested-by: tests/unit/test_manifest_discovery.py
"""Monorepo manifest discovery — finds all package manifests and pairs them with lockfiles.

Usage::

    from eedom.core.manifest_discovery import discover_packages, PackageUnit

    units = discover_packages(Path("/path/to/repo"))
    for unit in units:
        print(unit.root, unit.ecosystem, unit.lockfile)
"""

from __future__ import annotations

from pathlib import Path

import structlog
from pydantic import BaseModel, ConfigDict

from eedom.core.file_source import _ALWAYS_SKIP_DIRS
from eedom.core.ignore import load_ignore_patterns, should_ignore

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Maps
# ---------------------------------------------------------------------------

MANIFEST_MAP: dict[str, str] = {
    "package.json": "npm",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "Cargo.toml": "rust",
    "go.mod": "go",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "gradle",
}

# Maps lockfile names → the manifest name they are paired with.
LOCKFILE_MAP: dict[str, str] = {
    "package-lock.json": "package.json",
    "yarn.lock": "package.json",
    "pnpm-lock.yaml": "package.json",
    "uv.lock": "pyproject.toml",
    "poetry.lock": "pyproject.toml",
    "Pipfile.lock": "Pipfile",
    "Cargo.lock": "Cargo.toml",
    "go.sum": "go.mod",
}

# Manifest → set of lockfile names that can pair with it.
# Built once at import time from LOCKFILE_MAP.
_MANIFEST_TO_LOCKFILES: dict[str, list[str]] = {}
for _lf, _mf in LOCKFILE_MAP.items():
    _MANIFEST_TO_LOCKFILES.setdefault(_mf, []).append(_lf)

# Directories that are always skipped regardless of ignore patterns.
# Single source of truth lives in core.file_source so the walk source and
# manifest discovery never drift apart.
_ALWAYS_SKIP: frozenset[str] = _ALWAYS_SKIP_DIRS


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class PackageUnit(BaseModel):
    """A single package manifest, optionally paired with its lockfile."""

    model_config = ConfigDict(frozen=True)

    root: Path
    manifest: Path
    lockfile: Path | None = None
    ecosystem: str
    name: str | None = None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _is_valid_ecosystem(ecosystem: str) -> bool:
    """Return True if ecosystem is non-empty and contains only safe characters."""
    if not ecosystem:
        return False
    return all(c.isalnum() or c in ("-", "_") for c in ecosystem)


def _is_within_repo(path: Path, repo_path: Path) -> bool:
    """Return True if *path* resolves to a location inside *repo_path*.

    Resolves symlinks so that a symlink pointing outside the repo root is
    correctly rejected.
    """
    try:
        path.resolve().relative_to(repo_path.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_packages(
    repo_path: Path,
    ignore_patterns: list[str] | None = None,
) -> list[PackageUnit]:
    """Walk *repo_path* and return one :class:`PackageUnit` per manifest found.

    Args:
        repo_path: Absolute path to the repository root.
        ignore_patterns: Additional fnmatch-compatible patterns to skip.
            These are merged with the defaults loaded from :func:`load_ignore_patterns`.

    Returns:
        List of :class:`PackageUnit` objects sorted by ``root`` path.
    """
    base_patterns = load_ignore_patterns(repo_path)
    if ignore_patterns:
        merged: list[str] = list(base_patterns) + list(ignore_patterns)
    else:
        merged = base_patterns

    units: list[PackageUnit] = []

    for dirpath, dirnames, filenames in _walk(repo_path):
        # Prune dirnames in-place so os.walk / our recursive walk skips them.
        rel_dir = dirpath.relative_to(repo_path)

        # Build the list of subdirs to keep (modify in-place so walk respects it).
        kept: list[str] = []
        for d in dirnames:
            if d in _ALWAYS_SKIP:
                continue
            child_rel = str(rel_dir / d) if str(rel_dir) != "." else d
            if should_ignore(child_rel + "/", merged):
                continue
            kept.append(d)
        dirnames[:] = kept

        sibling_set = set(filenames)

        for filename in filenames:
            if filename not in MANIFEST_MAP:
                continue

            ecosystem = MANIFEST_MAP[filename]

            if not _is_valid_ecosystem(ecosystem):
                logger.warning(
                    "manifest_skipped_malformed_ecosystem",
                    manifest=str(dirpath / filename),
                    ecosystem=ecosystem,
                )
                continue

            manifest_path = dirpath / filename

            # Reject manifests that resolve outside repo_path (e.g. symlinks).
            if not _is_within_repo(manifest_path, repo_path):
                logger.warning(
                    "manifest_skipped_outside_repo",
                    manifest=str(manifest_path),
                )
                continue

            # Find the first matching lockfile in the same directory.
            lockfile_path: Path | None = None
            for lf_name in _MANIFEST_TO_LOCKFILES.get(filename, []):
                if lf_name in sibling_set:
                    candidate = dirpath / lf_name
                    if _is_within_repo(candidate, repo_path):
                        lockfile_path = candidate
                    break

            units.append(
                PackageUnit(
                    root=dirpath,
                    manifest=manifest_path,
                    lockfile=lockfile_path,
                    ecosystem=ecosystem,
                )
            )
            logger.debug(
                "manifest_discovered",
                manifest=str(manifest_path),
                ecosystem=ecosystem,
                lockfile=str(lockfile_path) if lockfile_path else None,
            )

    units.sort(key=lambda u: str(u.root))
    return units


# ---------------------------------------------------------------------------
# Walk helper (wraps Path.walk for Python 3.12+)
# ---------------------------------------------------------------------------


def _walk(root: Path):  # type: ignore[return]
    """Yield (dirpath, dirnames, filenames) tuples, modifiable in-place."""
    import os

    for dirpath_str, dirnames, filenames in os.walk(root):
        yield Path(dirpath_str), dirnames, filenames
