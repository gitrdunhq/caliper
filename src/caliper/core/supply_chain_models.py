"""Value objects for supply-chain version-bump analysis.
# tested-by: tests/unit/test_pkgsrc.py

The boundary contracts shared by the package-source fetcher (``data/pkgsrc.py``),
the deterministic signal analyzer (``core/supply_chain_diff.py``), and the advisory
narrative scribe (``plugins/scribes/supply_chain_threat.py``).

``VersionDiff`` is the deterministic, JSON-safe description of *what changed in the
code* between two published versions of a dependency. It is the single artifact the
deterministic gate scores and the LLM narrates over — the LLM never sees anything the
diff does not already contain (ADR-006).

``FetchedPackage`` is the transient result of downloading+extracting one version; it
holds a filesystem path and so is a plain frozen dataclass rather than a Contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from caliper._base import Contract


class FileChange(StrEnum):
    added = "added"
    removed = "removed"
    modified = "modified"


class FileDelta(Contract):
    """One changed file between two package versions (diff text capped upstream)."""

    path: str
    change: FileChange
    added_lines: int = 0
    removed_lines: int = 0
    diff_excerpt: str = ""


class VersionDiff(Contract):
    """Deterministic description of the source delta between two package versions.

    ``available=False`` means a fetch/extract step failed (fail-open): the analyzer
    still emits an informational finding, but no code-level signals are derived.
    """

    package: str
    ecosystem: str
    old_version: str
    new_version: str
    available: bool = True
    error: str = ""
    files: tuple[FileDelta, ...] = ()
    added_paths: tuple[str, ...] = ()
    removed_paths: tuple[str, ...] = ()
    # Install-time hooks (npm pre/install/postinstall etc.); "hook: command" strings.
    old_install_scripts: tuple[str, ...] = ()
    new_install_scripts: tuple[str, ...] = ()
    old_maintainer: str = ""
    new_maintainer: str = ""
    old_size_bytes: int = 0
    new_size_bytes: int = 0


@dataclass(frozen=True)
class FetchedPackage:
    """One downloaded+extracted package version (transient; holds a temp path)."""

    available: bool
    root: Path | None = None
    install_scripts: tuple[str, ...] = ()
    maintainer: str = ""
    size_bytes: int = 0
    error: str = ""
    # Files that could not be read as text are recorded by relative path so the
    # analyzer can still flag added binaries without holding their bytes.
    binary_paths: tuple[str, ...] = field(default_factory=tuple)
