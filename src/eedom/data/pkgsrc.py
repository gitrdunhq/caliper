"""Package-source fetcher + version differ (PyPI / npm).
# tested-by: tests/unit/test_pkgsrc.py

Downloads two published versions of a dependency, extracts them safely, and
computes a deterministic :class:`VersionDiff` describing *what code changed*.
This is the missing primitive behind supply-chain version-bump threat analysis:
eedom already knows a version changed, but until now never looked at the diff.

Trust boundary — archives are untrusted. ``safe_extract`` refuses absolute
member paths, ``..`` traversal (zip-slip / tar path escape), and symlinks/links
escaping the destination, and enforces hard caps (total bytes, file count,
single-file bytes) against zip-bombs. Every network/IO failure is absorbed and
surfaced as ``FetchedPackage(available=False, ...)`` / ``VersionDiff(available=
False, ...)`` — this module never raises on a remote or archive problem.
"""

from __future__ import annotations

import difflib
import io
import tarfile
import zipfile
from pathlib import Path

import httpx
import structlog

from eedom.core.registries import PACKAGE_SOURCES
from eedom.core.supply_chain_models import (
    FetchedPackage,
    FileChange,
    FileDelta,
    VersionDiff,
)

logger = structlog.get_logger(__name__)

# Conservative defaults — overridable by the caller (EedomSettings in the pipeline).
_DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MiB uncompressed
_DEFAULT_MAX_FILES = 5000
_DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024  # 4 MiB per member
_DEFAULT_TIMEOUT = 20
_MAX_EXCERPT_BYTES = 4000  # per-file unified-diff excerpt cap
_MAX_DIFF_FILES = 200  # cap files recorded in a VersionDiff
_TEXT_READ_CAP = 512 * 1024  # bytes read per file when diffing

# npm lifecycle hooks that run code at install time.
_NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "preuninstall")


class ExtractionError(Exception):
    """Raised internally when an archive member violates the safety policy."""


def _is_within(base: Path, target: Path) -> bool:
    """True iff *target* resolves to a path inside *base*."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_extract(
    archive_bytes: bytes,
    dest: Path,
    *,
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
    max_files: int = _DEFAULT_MAX_FILES,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> None:
    """Extract a tar(.gz/.tgz) or zip archive into *dest*, safely and bounded.

    Raises :class:`ExtractionError` on any traversal/symlink/cap violation so the
    caller can fail-open. Regular files and directories only — links are rejected.
    """
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(io.BytesIO(archive_bytes)):
        _extract_zip(archive_bytes, dest, max_total_bytes, max_files, max_file_bytes)
        return
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
            _extract_tar(tf, dest, max_total_bytes, max_files, max_file_bytes)
    except tarfile.TarError as exc:
        raise ExtractionError(f"unrecognized archive: {exc}") from exc


def _extract_tar(
    tf: tarfile.TarFile,
    dest: Path,
    max_total_bytes: int,
    max_files: int,
    max_file_bytes: int,
) -> None:
    total = 0
    count = 0
    for member in tf.getmembers():
        if member.islnk() or member.issym():
            raise ExtractionError(f"link member rejected: {member.name}")
        if not (member.isfile() or member.isdir()):
            continue  # skip devices/fifos
        target = dest / member.name
        if not _is_within(dest, target):
            raise ExtractionError(f"path escape rejected: {member.name}")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if member.size > max_file_bytes:
            raise ExtractionError(f"member too large: {member.name} ({member.size} bytes)")
        total += member.size
        count += 1
        if total > max_total_bytes:
            raise ExtractionError("archive exceeds total size cap")
        if count > max_files:
            raise ExtractionError("archive exceeds file count cap")
        src = tf.extractfile(member)
        if src is None:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with src, target.open("wb") as out:
            out.write(src.read(max_file_bytes + 1))


def _extract_zip(
    archive_bytes: bytes,
    dest: Path,
    max_total_bytes: int,
    max_files: int,
    max_file_bytes: int,
) -> None:
    total = 0
    count = 0
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith("/"):
                target = dest / name
                if not _is_within(dest, target):
                    raise ExtractionError(f"path escape rejected: {name}")
                target.mkdir(parents=True, exist_ok=True)
                continue
            target = dest / name
            if not _is_within(dest, target):
                raise ExtractionError(f"path escape rejected: {name}")
            if info.file_size > max_file_bytes:
                raise ExtractionError(f"member too large: {name} ({info.file_size} bytes)")
            total += info.file_size
            count += 1
            if total > max_total_bytes:
                raise ExtractionError("archive exceeds total size cap")
            if count > max_files:
                raise ExtractionError("archive exceeds file count cap")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                out.write(src.read(max_file_bytes + 1))


def _single_top_dir(root: Path) -> Path:
    """sdists/npm tarballs nest under one top dir; descend into it when present."""
    entries = [p for p in root.iterdir()] if root.is_dir() else []
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def _read_text(path: Path) -> str | None:
    """Read up to the cap as UTF-8 text; None if the file looks binary."""
    try:
        raw = path.read_bytes()[:_TEXT_READ_CAP]
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _collect(root: Path) -> tuple[dict[str, str], list[str]]:
    """Map relative path -> text for all text files under *root* (sorted, deterministic).

    Returns ``(text_files, binary_paths)``.
    """
    texts: dict[str, str] = {}
    binaries: list[str] = []
    if root is None or not root.is_dir():
        return texts, binaries
    for path in sorted(root.rglob("*"), key=lambda p: str(p)):
        if not path.is_file() or path.is_symlink():
            continue
        rel = str(path.relative_to(root))
        content = _read_text(path)
        if content is None:
            binaries.append(rel)
        else:
            texts[rel] = content
    return texts, binaries


def _unified(old_text: str, new_text: str, path: str) -> tuple[str, int, int]:
    """Capped unified diff plus (added_lines, removed_lines) counts."""
    diff_lines = list(
        difflib.unified_diff(
            old_text.splitlines(),
            new_text.splitlines(),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="",
        )
    )
    added = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
    excerpt = "\n".join(diff_lines)[:_MAX_EXCERPT_BYTES]
    return excerpt, added, removed


def diff_versions(
    old: FetchedPackage,
    new: FetchedPackage,
    *,
    package: str,
    ecosystem: str,
    old_version: str,
    new_version: str,
) -> VersionDiff:
    """Pure, deterministic diff of two fetched versions into a :class:`VersionDiff`."""
    if not old.available or not new.available:
        return VersionDiff(
            package=package,
            ecosystem=ecosystem,
            old_version=old_version,
            new_version=new_version,
            available=False,
            error=(old.error or new.error or "source unavailable"),
        )

    old_texts, old_bin = _collect(old.root) if old.root else ({}, [])
    new_texts, new_bin = _collect(new.root) if new.root else ({}, [])

    old_paths = set(old_texts) | set(old_bin)
    new_paths = set(new_texts) | set(new_bin)

    added_paths = tuple(sorted(new_paths - old_paths))
    removed_paths = tuple(sorted(old_paths - new_paths))

    deltas: list[FileDelta] = []
    for rel in sorted(new_paths - old_paths):  # added
        new_t = new_texts.get(rel)
        if new_t is None:
            deltas.append(FileDelta(path=rel, change=FileChange.added))
            continue
        excerpt, added, removed = _unified("", new_t, rel)
        deltas.append(
            FileDelta(
                path=rel,
                change=FileChange.added,
                added_lines=added,
                removed_lines=removed,
                diff_excerpt=excerpt,
            )
        )
    for rel in sorted(old_paths & new_paths):  # modified
        old_t, new_t = old_texts.get(rel), new_texts.get(rel)
        if old_t is None or new_t is None or old_t == new_t:
            continue
        excerpt, added, removed = _unified(old_t, new_t, rel)
        deltas.append(
            FileDelta(
                path=rel,
                change=FileChange.modified,
                added_lines=added,
                removed_lines=removed,
                diff_excerpt=excerpt,
            )
        )
    for rel in sorted(old_paths - new_paths):  # removed
        deltas.append(FileDelta(path=rel, change=FileChange.removed))

    return VersionDiff(
        package=package,
        ecosystem=ecosystem,
        old_version=old_version,
        new_version=new_version,
        available=True,
        files=tuple(deltas[:_MAX_DIFF_FILES]),
        added_paths=added_paths,
        removed_paths=removed_paths,
        old_install_scripts=old.install_scripts,
        new_install_scripts=new.install_scripts,
        old_maintainer=old.maintainer,
        new_maintainer=new.maintainer,
        old_size_bytes=old.size_bytes,
        new_size_bytes=new.size_bytes,
    )


def _unavailable(error: str) -> FetchedPackage:
    return FetchedPackage(available=False, error=error)


class PyPISource:
    """Fetch + extract a PyPI sdist for a single version (fail-open)."""

    name = "pypi"

    def __init__(self, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout, follow_redirects=True)

    def close(self) -> None:
        self._client.close()

    def fetch_version(self, package: str, version: str, dest: Path) -> FetchedPackage:
        url = f"https://pypi.org/pypi/{package}/{version}/json"
        try:
            resp = self._client.get(url)
        except httpx.HTTPError as exc:
            logger.warning("pkgsrc.pypi.http_error", package=package, error=str(exc))
            return _unavailable(f"pypi request failed: {exc}")
        if resp.status_code != 200:
            return _unavailable(f"pypi returned {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            return _unavailable(f"pypi parse error: {exc}")

        info = data.get("info") or {}
        maintainer = str(info.get("author") or info.get("author_email") or "")
        sdist = next(
            (u for u in (data.get("urls") or []) if u.get("packagetype") == "sdist"),
            None,
        )
        if sdist is None:
            return _unavailable("no sdist for version")
        return self._download_and_extract(sdist.get("url", ""), dest, maintainer)

    def _download_and_extract(self, url: str, dest: Path, maintainer: str) -> FetchedPackage:
        if not url:
            return _unavailable("missing sdist url")
        try:
            blob = self._client.get(url)
        except httpx.HTTPError as exc:
            return _unavailable(f"sdist download failed: {exc}")
        if blob.status_code != 200:
            return _unavailable(f"sdist download returned {blob.status_code}")
        content = blob.content
        try:
            safe_extract(content, dest)
        except ExtractionError as exc:
            logger.warning("pkgsrc.pypi.extract_rejected", error=str(exc))
            return _unavailable(f"unsafe sdist archive: {exc}")
        return FetchedPackage(
            available=True,
            root=_single_top_dir(dest),
            maintainer=maintainer,
            size_bytes=len(content),
        )


class NpmSource:
    """Fetch + extract an npm tarball for a single version (fail-open)."""

    name = "npm"

    def __init__(self, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout, follow_redirects=True)

    def close(self) -> None:
        self._client.close()

    def fetch_version(self, package: str, version: str, dest: Path) -> FetchedPackage:
        url = f"https://registry.npmjs.org/{package}/{version}"
        try:
            resp = self._client.get(url)
        except httpx.HTTPError as exc:
            logger.warning("pkgsrc.npm.http_error", package=package, error=str(exc))
            return _unavailable(f"npm request failed: {exc}")
        if resp.status_code != 200:
            return _unavailable(f"npm returned {resp.status_code}")
        try:
            manifest = resp.json()
        except ValueError as exc:
            return _unavailable(f"npm parse error: {exc}")

        scripts = manifest.get("scripts") or {}
        install_scripts = tuple(
            f"{hook}: {scripts[hook]}" for hook in _NPM_INSTALL_HOOKS if hook in scripts
        )
        npm_user = manifest.get("_npmUser") or {}
        maintainer = str(npm_user.get("name") or "")
        if not maintainer:
            maints = manifest.get("maintainers") or []
            if maints and isinstance(maints[0], dict):
                maintainer = str(maints[0].get("name") or "")

        tarball = ((manifest.get("dist") or {}).get("tarball")) or ""
        return self._download_and_extract(tarball, dest, install_scripts, maintainer)

    def _download_and_extract(
        self, url: str, dest: Path, install_scripts: tuple[str, ...], maintainer: str
    ) -> FetchedPackage:
        if not url:
            return _unavailable("missing tarball url")
        try:
            blob = self._client.get(url)
        except httpx.HTTPError as exc:
            return _unavailable(f"tarball download failed: {exc}")
        if blob.status_code != 200:
            return _unavailable(f"tarball download returned {blob.status_code}")
        content = blob.content
        try:
            safe_extract(content, dest)
        except ExtractionError as exc:
            logger.warning("pkgsrc.npm.extract_rejected", error=str(exc))
            return _unavailable(f"unsafe tarball: {exc}")
        return FetchedPackage(
            available=True,
            root=_single_top_dir(dest),
            install_scripts=install_scripts,
            maintainer=maintainer,
            size_bytes=len(content),
        )


@PACKAGE_SOURCES.register("pypi")
def build_pypi_source(*, timeout: int = _DEFAULT_TIMEOUT) -> PyPISource:
    """Construct the PyPI package-source adapter."""
    return PyPISource(timeout=timeout)


@PACKAGE_SOURCES.register("npm")
def build_npm_source(*, timeout: int = _DEFAULT_TIMEOUT) -> NpmSource:
    """Construct the npm package-source adapter."""
    return NpmSource(timeout=timeout)
