"""Download, verify, extract, and place pinned scanner binaries (imperative shell).
# tested-by: tests/unit/test_scanner_installer.py

Every download is sha256-verified against the pin before anything touches the
filesystem; the executable is written to a temp file beside its destination and
moved into place atomically. Failures are ``RuntimeError`` with a specific
message — installing is not fail-open.
"""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path

import httpx

from caliper.core.scanner_install import InstallItem, verify_sha256

_DEFAULT_TIMEOUT = 120


class HttpScannerInstaller:
    def __init__(
        self, *, transport: httpx.BaseTransport | None = None, timeout: int = _DEFAULT_TIMEOUT
    ) -> None:
        self._transport = transport
        self._timeout = timeout

    def _download(self, url: str) -> bytes:
        with httpx.Client(
            transport=self._transport, timeout=self._timeout, follow_redirects=True
        ) as client:
            resp = client.get(url)
        if resp.status_code != 200:
            raise RuntimeError(f"download failed: HTTP {resp.status_code} for {url}")
        return resp.content

    @staticmethod
    def _extract(item: InstallItem, body: bytes) -> bytes:
        asset = item.asset
        if asset.kind == "binary":
            return body
        want = (asset.member or item.name).lstrip("./")
        if asset.kind == "tar.gz":
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and m.name.lstrip("./") == want:
                        f = tf.extractfile(m)
                        if f is not None:
                            return f.read()
        elif asset.kind == "zip":
            with zipfile.ZipFile(io.BytesIO(body)) as zf:
                for n in zf.namelist():
                    if n.lstrip("./") == want:
                        return zf.read(n)
        raise RuntimeError(f"archive member {want!r} not found in {asset.url}")

    def install(self, item: InstallItem, bin_dir: Path) -> Path:
        body = self._download(item.asset.url)
        if not verify_sha256(body, item.asset.sha256):
            raise RuntimeError(
                f"checksum mismatch for {item.name} {item.version}; refusing to install"
            )
        payload = self._extract(item, body)
        bin_dir.mkdir(parents=True, exist_ok=True)
        dest = bin_dir / item.name
        fd, tmp = tempfile.mkstemp(prefix=f".{item.name}.", dir=bin_dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
            os.chmod(tmp, 0o755)
            os.replace(tmp, dest)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return dest
