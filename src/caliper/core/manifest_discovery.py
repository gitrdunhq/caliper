# tested-by: tests/unit/test_manifest_discovery.py
"""Monorepo manifest discovery — finds all package manifests and pairs them with lockfiles.

Usage::

    from caliper.core.manifest_discovery import discover_packages, PackageUnit

    units = discover_packages(Path("/path/to/repo"))
    for unit in units:
        print(unit.root, unit.ecosystem, unit.lockfile)
"""

from __future__ import annotations

import functools
import json
import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from xml.etree import ElementTree

import structlog
from pydantic import BaseModel, ConfigDict

from caliper.core.file_source import select_file_source
from caliper.core.ignore import load_ignore_patterns, should_ignore

if TYPE_CHECKING:
    from caliper.core.ports import FileSourcePort

DependencyKind = Literal["direct", "transitive", "unknown"]

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


# ---------------------------------------------------------------------------
# Dependency kind classification (direct / transitive / unknown)
# ---------------------------------------------------------------------------


def _normalize_dep_name(name: str) -> str:
    """Normalize a package name for cross-ecosystem, case-insensitive matching."""
    return name.strip().lower().replace("_", "-")


def _pep508_name(spec: str) -> str:
    """Extract the bare package name from a PEP 508 requirement spec."""
    match = re.match(r"[A-Za-z0-9_.\-]+", spec.strip())
    return match.group(0) if match else spec.strip()


def _direct_deps_pyproject_toml(text: str) -> set[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return set()

    deps: set[str] = set()
    project = data.get("project", {})
    if isinstance(project, dict):
        for spec in project.get("dependencies", []) or []:
            if isinstance(spec, str):
                deps.add(_pep508_name(spec))

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        for name in poetry.get("dependencies", {}) or {}:
            if isinstance(name, str) and name.lower() != "python":
                deps.add(name)
    return deps


def _direct_deps_requirements_txt(text: str) -> set[str]:
    deps: set[str] = set()
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        deps.add(_pep508_name(stripped))
    return deps


def _direct_deps_package_json(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()

    deps: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.update(name for name in section if isinstance(name, str))
    return deps


def _direct_deps_pom_xml(text: str) -> set[str]:
    deps: set[str] = set()
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return deps

    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag != "dependency":
            continue
        for child in element:
            child_tag = child.tag.rsplit("}", 1)[-1]
            if child_tag == "artifactId" and child.text:
                deps.add(child.text.strip())
    return deps


def _direct_deps_go_mod(text: str) -> set[str]:
    deps: set[str] = set()
    in_block = False
    for line in text.splitlines():
        stripped = line.split("//", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith("require (") or stripped == "require (":
            in_block = True
            continue
        if in_block:
            if stripped == ")":
                in_block = False
                continue
            parts = stripped.split()
            if parts:
                deps.add(parts[0])
            continue
        if stripped.startswith("require "):
            parts = stripped[len("require ") :].split()
            if parts:
                deps.add(parts[0])
    return deps


def _direct_deps_cargo_toml(text: str) -> set[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return set()

    deps: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = data.get(section)
        if isinstance(table, dict):
            deps.update(name for name in table if isinstance(name, str))
    return deps


_DIRECT_DEP_PARSERS: dict[str, Callable[[str], set[str]]] = {
    "pyproject.toml": _direct_deps_pyproject_toml,
    "package.json": _direct_deps_package_json,
    "pom.xml": _direct_deps_pom_xml,
    "go.mod": _direct_deps_go_mod,
    "Cargo.toml": _direct_deps_cargo_toml,
}


def _resolve_direct_parser(filename: str) -> Callable[[str], set[str]] | None:
    parser = _DIRECT_DEP_PARSERS.get(filename)
    if parser is not None:
        return parser
    if filename.startswith("requirements") and filename.endswith(".txt"):
        return _direct_deps_requirements_txt
    return None


@functools.lru_cache(maxsize=4096)
def _lockfile_pattern(package_name: str) -> re.Pattern[str]:
    """Compile (once per package name) the standalone-token regex for a lockfile."""
    return re.compile(r"(?<![\w.\-])" + re.escape(package_name) + r"(?![\w.\-])")


def _appears_in_lockfile(package_name: str, text: str) -> bool:
    """Return True if *package_name* appears as a standalone token in *text*.

    Both sides are normalized (:func:`_normalize_dep_name`) so ``Foo_Bar``
    matches ``foo-bar`` and vice versa — the same rule the direct lookup uses.
    Callers holding a :class:`ManifestCache` should pass the pre-normalized
    text from :meth:`ManifestCache.lockfile_text` to avoid re-normalizing.
    """
    return bool(
        _lockfile_pattern(_normalize_dep_name(package_name)).search(_normalize_dep_name(text))
    )


def _read_text(path: Path) -> str:
    """Default :class:`ManifestCache` reader — the one disk touch in this module."""
    return path.read_text()


class ManifestCache:
    """Per-scan, read-once cache of manifest and lockfile contents.

    Plugins create one per run and thread it through every
    :func:`classify_dependency_kind` call, so a 50-package result reads each
    manifest/lockfile exactly once instead of once per package (PERF-001/002).
    A missing or unreadable file is remembered as ``None`` so it is probed once,
    not once per package. *reader* is injectable for tests (a counting fake).
    """

    def __init__(self, reader: Callable[[Path], str] | None = None) -> None:
        self._reader = reader if reader is not None else _read_text
        self._texts: dict[Path, str | None] = {}
        self._direct: dict[Path, set[str]] = {}
        self._lock_norm: dict[Path, str | None] = {}

    def text(self, path: Path) -> str | None:
        """Return the file's text, or ``None`` if it is missing/unreadable."""
        if path not in self._texts:
            try:
                self._texts[path] = self._reader(path)
            except OSError:
                self._texts[path] = None
        return self._texts[path]

    def lockfile_text(self, path: Path) -> str | None:
        """Return the lockfile's *normalized* text (see :func:`_normalize_dep_name`)."""
        if path not in self._lock_norm:
            text = self.text(path)
            self._lock_norm[path] = _normalize_dep_name(text) if text is not None else None
        return self._lock_norm[path]

    def direct_deps(self, manifest_path: Path) -> set[str]:
        """Return the normalized direct-dependency names declared in *manifest_path*."""
        if manifest_path not in self._direct:
            parser = _resolve_direct_parser(manifest_path.name)
            text = self.text(manifest_path)
            names = parser(text) if parser and text is not None else set()
            self._direct[manifest_path] = {_normalize_dep_name(n) for n in names}
        return self._direct[manifest_path]


def _resolve_manifest_path(path: Path, cache: ManifestCache) -> Path | None:
    """Map a lockfile path to its sibling manifest; manifests pass through.

    Returns ``None`` when *path* is a known lockfile whose owning manifest is
    absent — the deterministic "no evidence" case.
    """
    manifest_name = LOCKFILE_MAP.get(path.name)
    if manifest_name is None:
        return path
    sibling = path.parent / manifest_name
    return sibling if cache.text(sibling) is not None else None


def classify_dependency_kind(
    repo_path: Path,  # noqa: ARG001 - kept for a stable, discoverable call signature
    package_name: str,
    manifest_path: Path,
    cache: ManifestCache | None = None,
) -> DependencyKind:
    """Classify *package_name* as ``"direct"``, ``"transitive"``, or ``"unknown"``.

    ``"direct"``: the package is declared as a top-level dependency in
    *manifest_path*.

    ``"transitive"``: the package is not declared directly in *manifest_path*
    but appears in a lockfile paired with it (e.g. ``uv.lock`` next to
    ``pyproject.toml``).

    ``"unknown"``: no manifest or lockfile evidence exists for the package.

    Supports pyproject.toml, requirements*.txt, package.json, pom.xml,
    go.mod, and Cargo.toml manifests. Malformed manifests/lockfiles are
    treated as empty (fail-open) rather than raising.

    *manifest_path* may also be a known lockfile (trivy reports lockfiles as
    its ``Target``): it is resolved to the sibling manifest via
    :data:`LOCKFILE_MAP` and classified against that. A lockfile with no
    sibling manifest yields ``"unknown"`` — there is no evidence to tell a
    direct dependency from a transitive one.

    *cache* is the per-scan :class:`ManifestCache`; callers classifying many
    packages against the same files should share one. ``None`` uses a
    throwaway cache (one read per file for this call only).
    """
    if cache is None:
        cache = ManifestCache()

    manifest_path = _resolve_manifest_path(manifest_path, cache)
    if manifest_path is None:
        return "unknown"

    normalized_target = _normalize_dep_name(package_name)
    if normalized_target in cache.direct_deps(manifest_path):
        return "direct"

    for lockfile_name in _MANIFEST_TO_LOCKFILES.get(manifest_path.name, []):
        lockfile_text = cache.lockfile_text(manifest_path.parent / lockfile_name)
        if lockfile_text is None:
            continue
        if _lockfile_pattern(normalized_target).search(lockfile_text):
            return "transitive"

    return "unknown"
