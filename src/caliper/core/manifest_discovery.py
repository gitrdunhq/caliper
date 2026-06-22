# tested-by: tests/unit/test_manifest_discovery.py
"""Monorepo manifest discovery — finds all package manifests and pairs them with lockfiles.

Usage::

    from caliper.core.manifest_discovery import discover_packages, PackageUnit

    units = discover_packages(Path("/path/to/repo"))
    for unit in units:
        print(unit.root, unit.ecosystem, unit.lockfile)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import structlog
from pydantic import BaseModel, ConfigDict

from caliper.core.file_source import select_file_source
from caliper.core.ignore import load_ignore_patterns, should_ignore

if TYPE_CHECKING:
    from caliper.core.ports import FileSourcePort

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
    file_source: FileSourcePort | None = None,
) -> list[PackageUnit]:
    """Return one :class:`PackageUnit` per manifest found under *repo_path*.

    Enumeration goes through the shared :class:`FileSourcePort` (git ls-files
    when *repo_path* is a usable repo, else an ignore-aware walk) — the same
    seam the CLI, scanner, and supply-chain plugin use — so manifest discovery
    can no longer drift from the rest of caliper's file handling.

    Args:
        repo_path: Absolute path to the repository root.
        ignore_patterns: Additional fnmatch-compatible patterns to skip,
            merged with the defaults from :func:`load_ignore_patterns`.
        file_source: Override the resolved source (mainly for tests).

    Returns:
        List of :class:`PackageUnit` objects sorted by ``root`` path.
    """
    base_patterns = load_ignore_patterns(repo_path)
    merged: list[str] = list(base_patterns) + list(ignore_patterns or [])

    source = file_source or select_file_source(repo_path)
    repo_resolved = repo_path.resolve()

    # Group enumerated files by parent directory so each manifest can find a
    # sibling lockfile. The source already drops escaping symlinks and the base
    # ignore set; re-applying ``merged`` adds the caller's extra patterns.
    by_dir: dict[Path, set[str]] = {}
    for file_path in source.list_files(repo_path):
        try:
            rel = file_path.relative_to(repo_path).as_posix()
        except ValueError:
            rel = file_path.name
        if should_ignore(rel, merged):
            continue
        by_dir.setdefault(file_path.parent, set()).add(file_path.name)

    units: list[PackageUnit] = []

    for dirpath in sorted(by_dir):
        sibling_set = by_dir[dirpath]
        for filename in sorted(sibling_set):
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
            if not _is_within_repo(manifest_path, repo_resolved):
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
                    if _is_within_repo(candidate, repo_resolved):
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
