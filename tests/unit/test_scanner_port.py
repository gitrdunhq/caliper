"""Conformance tests for ScannerPort + the SCANNERS registry.
# tested-by: tests/unit/test_scanner_port.py

RED phase for issue #406 — imports symbols that do not exist yet
(`SCANNERS`, `ScannerPort`) and is expected to fail until the registry +
port are added to `eedom.data.scanners`.

Mirrors the per-area template the epic (#404) repeats: port → registry +
autodiscover → adapters + fake → parametrized factory conformance.
"""

from __future__ import annotations

import pytest

from eedom.core.models import ScanResult
from eedom.data.scanners import SCANNERS, ScannerPort

_REAL_SCANNERS = ["osv", "trivy", "syft", "scancode"]
_ALL_SCANNERS = [*_REAL_SCANNERS, "fake"]


class TestScannerRegistry:
    def test_real_scanners_registered(self):
        registered = SCANNERS.keys()
        for key in _REAL_SCANNERS:
            assert key in registered, f"{key} not registered"

    def test_fake_registered(self):
        registered = SCANNERS.keys()
        assert "fake" in registered

    @pytest.mark.parametrize("key", _ALL_SCANNERS)
    def test_create_returns_a_scanner_port(self, key: str):
        scanner = SCANNERS.create(key)
        assert isinstance(scanner, ScannerPort)
        assert isinstance(scanner.name, str)
        assert scanner.name
        assert callable(scanner.scan)

    def test_unknown_key_raises_key_error(self):
        with pytest.raises(KeyError):
            SCANNERS.create("does-not-exist")


class TestScannerPortIsProtocol:
    def test_is_runtime_checkable(self):
        # Must not raise — a non-runtime_checkable Protocol raises on isinstance.
        isinstance(object(), ScannerPort)

    def test_object_without_scan_is_not_a_scanner(self):
        class NoScan:
            name = "x"

        assert not isinstance(NoScan(), ScannerPort)


class TestFactoryThreadsConfig:
    def test_osv_factory_threads_exclude_paths(self):
        scanner = SCANNERS.create("osv", exclude_paths=["tests/e2e/fixtures"])
        assert scanner._exclude_paths == ["tests/e2e/fixtures"]

    def test_trivy_factory_defaults_to_60s_timeout(self):
        scanner = SCANNERS.create("trivy")
        assert scanner._timeout == 60


class TestFakeScanner:
    def test_scan_returns_a_scan_result(self, tmp_path):
        scanner = SCANNERS.create("fake")
        result = scanner.scan(tmp_path)
        assert isinstance(result, ScanResult)

    def test_scan_never_raises_on_missing_target(self):
        # Fail-open: even a non-existent path yields a typed result, not an error.
        scanner = SCANNERS.create("fake")
        result = scanner.scan(__import__("pathlib").Path("/nonexistent/xyz"))
        assert isinstance(result, ScanResult)

    class TestProperties:
        """Determinism (INVARIANT): same input → same output."""

        def test_fake_scan_is_deterministic(self, tmp_path):
            scanner = SCANNERS.create("fake")
            assert scanner.scan(tmp_path) == scanner.scan(tmp_path)
