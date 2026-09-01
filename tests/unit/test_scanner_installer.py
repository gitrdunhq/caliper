"""The imperative shell: download, verify, extract, place atomically.
# tested-by: tests/unit/test_scanner_installer.py
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest

from caliper.core.scanner_install import InstallItem
from caliper.core.scanner_pins import Asset
from caliper.data.scanner_installer import HttpScannerInstaller


def _tar_with(member: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=member)
        info.size = len(payload)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _zip_with(member: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, payload)
    return buf.getvalue()


def _installer_serving(body: bytes) -> HttpScannerInstaller:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    return HttpScannerInstaller(transport=httpx.MockTransport(handler), timeout=5)


def _item(kind: str, body: bytes, member: str | None = None, sha: str | None = None) -> InstallItem:
    asset = Asset(
        url="https://example.invalid/x",
        sha256=sha or hashlib.sha256(body).hexdigest(),
        kind=kind,
        member=member,
    )
    return InstallItem(name="tool", version="1.0.0", asset=asset)


class TestInstall:
    def test_binary_asset_is_written_executable(self, tmp_path: Path) -> None:
        body = b"#!/bin/sh\necho hi\n"
        dest = _installer_serving(body).install(_item("binary", body), tmp_path)
        assert dest == tmp_path / "tool"
        assert dest.read_bytes() == body
        assert os.stat(dest).st_mode & 0o111

    def test_tar_member_is_extracted(self, tmp_path: Path) -> None:
        payload = b"ELF-ish"
        body = _tar_with("tool", payload)
        dest = _installer_serving(body).install(_item("tar.gz", body, member="tool"), tmp_path)
        assert dest.read_bytes() == payload

    def test_nested_tar_member_path(self, tmp_path: Path) -> None:
        payload = b"bin"
        body = _tar_with("./tool", payload)
        dest = _installer_serving(body).install(_item("tar.gz", body, member="tool"), tmp_path)
        assert dest.read_bytes() == payload

    def test_zip_member_is_extracted(self, tmp_path: Path) -> None:
        payload = b"zipped"
        body = _zip_with("tool_linux", payload)
        dest = _installer_serving(body).install(_item("zip", body, member="tool_linux"), tmp_path)
        assert dest.read_bytes() == payload

    def test_checksum_mismatch_writes_nothing(self, tmp_path: Path) -> None:
        body = b"real"
        with pytest.raises(RuntimeError, match="checksum"):
            _installer_serving(body).install(_item("binary", body, sha="0" * 64), tmp_path)
        assert list(tmp_path.iterdir()) == []

    def test_http_error_is_a_runtime_error(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        inst = HttpScannerInstaller(transport=httpx.MockTransport(handler), timeout=5)
        with pytest.raises(RuntimeError, match="404"):
            inst.install(_item("binary", b"x"), tmp_path)

    def test_missing_archive_member_is_a_runtime_error(self, tmp_path: Path) -> None:
        body = _tar_with("other", b"x")
        with pytest.raises(RuntimeError, match="member"):
            _installer_serving(body).install(_item("tar.gz", body, member="tool"), tmp_path)

    def test_existing_file_is_replaced_atomically(self, tmp_path: Path) -> None:
        (tmp_path / "tool").write_bytes(b"old")
        body = b"new"
        _installer_serving(body).install(_item("binary", body), tmp_path)
        assert (tmp_path / "tool").read_bytes() == b"new"
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".tool")]
