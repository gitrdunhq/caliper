"""Sqlite-backed ScanCachePort adapter, plus its Null fallback (ADR-010).
# tested-by: tests/unit/test_scan_cache.py

SqliteScanCache stores one row per cache key in a single-table sqlite db under the
evidence dir. A corrupt or unreadable entry is treated as a miss, never a crash — the
scanner just runs again, same as any other cache miss.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import orjson
import structlog

from caliper.core.models import ScanResult
from caliper.core.port_registries import SCAN_CACHES

logger = structlog.get_logger()

_CREATE_TABLE = (
    "CREATE TABLE IF NOT EXISTS scan_cache (key TEXT PRIMARY KEY, result_json BLOB NOT NULL)"
)


@SCAN_CACHES.register("sqlite")
class SqliteScanCache:
    """A sqlite-backed ScanResult cache keyed on an opaque string."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        try:
            conn.execute(_CREATE_TABLE)
            conn.commit()
        finally:
            conn.close()

    def get(self, key: str) -> ScanResult | None:
        try:
            conn = sqlite3.connect(str(self._db_path))
            try:
                row = conn.execute(
                    "SELECT result_json FROM scan_cache WHERE key = ?", (key,)
                ).fetchone()
            finally:
                conn.close()
            if row is None:
                return None
            return ScanResult.model_validate(orjson.loads(row[0]))
        except Exception:
            logger.debug("scan_cache.get_failed", key=key, exc_info=True)
            return None

    def put(self, key: str, result: ScanResult) -> None:
        try:
            payload = orjson.dumps(result.model_dump(mode="json"))
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO scan_cache (key, result_json) VALUES (?, ?)",
                    (key, payload),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            logger.debug("scan_cache.put_failed", key=key, exc_info=True)


@SCAN_CACHES.register("null")
class NullScanCache:
    """No-op ScanCachePort — every lookup misses, every write is discarded."""

    def get(self, key: str) -> ScanResult | None:
        return None

    def put(self, key: str, result: ScanResult) -> None:
        pass
