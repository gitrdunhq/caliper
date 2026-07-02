"""Tests for the sqlite-backed ScanCachePort adapter and its Null fallback (ADR-010).

# tested-by: tests/unit/test_scan_cache.py
"""

from __future__ import annotations

from caliper.core.models import ScanResult, ScanResultStatus
from caliper.data.scan_cache import NullScanCache, SqliteScanCache


def _result(status: ScanResultStatus = ScanResultStatus.success) -> ScanResult:
    return ScanResult(
        tool_name="osv",
        status=status,
        findings=[],
        raw_output_path=None,
        message=None,
        duration_seconds=1.5,
    )


class TestProperties:
    def test_roundtrip_and_miss(self, tmp_path) -> None:
        cache = SqliteScanCache(tmp_path / "cache.sqlite")
        assert cache.get("key1") is None  # miss before put

        result = _result()
        cache.put("key1", result)
        assert cache.get("key1") == result  # hit returns identical payload
        assert cache.get("unknown-key") is None  # unknown key misses

    def test_put_overwrites_existing_key(self, tmp_path) -> None:
        cache = SqliteScanCache(tmp_path / "cache.sqlite")
        cache.put("key1", _result(ScanResultStatus.success))
        cache.put("key1", _result(ScanResultStatus.failed))
        assert cache.get("key1").status == ScanResultStatus.failed

    def test_new_instance_reads_persisted_rows(self, tmp_path) -> None:
        db_path = tmp_path / "cache.sqlite"
        SqliteScanCache(db_path).put("key1", _result())
        reopened = SqliteScanCache(db_path)
        assert reopened.get("key1") is not None

    def test_corrupt_row_is_treated_as_a_miss(self, tmp_path) -> None:
        import sqlite3

        db_path = tmp_path / "cache.sqlite"
        cache = SqliteScanCache(db_path)
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "INSERT INTO scan_cache (key, result_json) VALUES (?, ?)",
                ("bad-key", b"not-json"),
            )
            conn.commit()
        finally:
            conn.close()
        assert cache.get("bad-key") is None

    def test_unwritable_db_path_never_raises(self, tmp_path) -> None:
        cache = SqliteScanCache(tmp_path / "cache.sqlite")
        # Corrupt the underlying file so get/put hit sqlite errors, not Python ones.
        (tmp_path / "cache.sqlite").write_bytes(b"not-a-sqlite-db")
        assert cache.get("key1") is None  # fail-open: miss, not a raise
        cache.put("key1", _result())  # fail-open: silently discarded, not a raise


class TestNullScanCache:
    def test_get_always_misses(self) -> None:
        assert NullScanCache().get("anything") is None

    def test_put_is_discarded(self) -> None:
        cache = NullScanCache()
        cache.put("key1", _result())
        assert cache.get("key1") is None
