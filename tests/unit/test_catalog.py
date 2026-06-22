"""Tests for caliper.data.catalog — PackageCatalog and CatalogEntry.
# tested-by: tests/unit/test_catalog.py
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pool(fetchone_result=None, fetchall_result=None, rowcount=0):
    """Build a mock ConnectionPool whose cursor returns controlled results."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = fetchone_result
    mock_cursor.fetchall.return_value = fetchall_result or []
    mock_cursor.rowcount = rowcount

    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)

    mock_pool = MagicMock()
    mock_pool.connection.return_value = mock_conn

    return mock_pool, mock_cursor


def _make_entry(**overrides):
    """Build a CatalogEntry with sensible defaults for all slots."""
    from caliper.data.catalog import CatalogEntry

    defaults = {
        "catalog_id": 1,
        "ecosystem": "pypi",
        "package_name": "requests",
        "version": "2.31.0",
        "summary": "HTTP library",
        "vuln_scanned_at": None,
        "license_scanned_at": None,
        "sbom_scanned_at": None,
        "vuln_finding_count": 0,
        "vuln_max_severity": None,
        "license_findings": None,
        "latest_decision": None,
        "latest_decision_at": None,
        "policy_version": None,
        "status": "active",
    }
    defaults.update(overrides)
    return CatalogEntry(**defaults)


# ---------------------------------------------------------------------------
# CatalogEntry — freshness helpers
# ---------------------------------------------------------------------------


class TestCatalogEntryIsVulnFresh:
    """CatalogEntry.is_vuln_fresh() reflects whether the vuln scan is recent."""

    def test_returns_false_when_vuln_scanned_at_is_none(self) -> None:
        entry = _make_entry(vuln_scanned_at=None)
        assert entry.is_vuln_fresh() is False

    def test_returns_true_for_recent_scan(self) -> None:
        recent = datetime.now(UTC) - timedelta(hours=1)
        entry = _make_entry(vuln_scanned_at=recent)
        assert entry.is_vuln_fresh() is True

    def test_returns_false_for_stale_scan(self) -> None:
        old = datetime.now(UTC) - timedelta(hours=48)
        entry = _make_entry(vuln_scanned_at=old)
        assert entry.is_vuln_fresh() is False

    def test_custom_max_age_respected(self) -> None:
        two_hours_ago = datetime.now(UTC) - timedelta(hours=2)
        entry = _make_entry(vuln_scanned_at=two_hours_ago)
        assert entry.is_vuln_fresh(max_age_hours=1) is False
        assert entry.is_vuln_fresh(max_age_hours=3) is True


class TestCatalogEntryNeedsScan:
    """CatalogEntry.needs_scan() returns which scan types are stale/missing."""

    def test_all_stale_returns_all_three(self) -> None:
        entry = _make_entry(
            vuln_scanned_at=None,
            license_scanned_at=None,
            sbom_scanned_at=None,
        )
        needed = entry.needs_scan()
        assert "vuln" in needed
        assert "license" in needed
        assert "sbom" in needed

    def test_all_fresh_returns_empty_list(self) -> None:
        now = datetime.now(UTC)
        entry = _make_entry(
            vuln_scanned_at=now - timedelta(hours=1),
            license_scanned_at=now - timedelta(hours=1),
            sbom_scanned_at=now - timedelta(hours=1),
        )
        assert entry.needs_scan() == []

    def test_only_vuln_stale(self) -> None:
        now = datetime.now(UTC)
        entry = _make_entry(
            vuln_scanned_at=None,
            license_scanned_at=now - timedelta(hours=1),
            sbom_scanned_at=now - timedelta(hours=1),
        )
        needed = entry.needs_scan()
        assert needed == ["vuln"]


# ---------------------------------------------------------------------------
# PackageCatalog.lookup
# ---------------------------------------------------------------------------


class TestPackageCatalogLookup:
    """PackageCatalog.lookup() returns CatalogEntry or None."""

    def test_lookup_returns_none_when_not_found(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool, _ = _make_pool(fetchone_result=None)
        catalog = PackageCatalog(pool)
        result = catalog.lookup("pypi", "requests", "2.31.0")
        assert result is None

    def test_lookup_returns_none_when_pool_is_none(self) -> None:
        from caliper.data.catalog import PackageCatalog

        catalog = PackageCatalog(None)
        result = catalog.lookup("pypi", "requests", "2.31.0")
        assert result is None

    def test_lookup_returns_catalog_entry(self) -> None:
        from caliper.data.catalog import CatalogEntry, PackageCatalog

        row = (
            42,  # catalog_id
            "pypi",  # ecosystem
            "requests",  # package_name
            "2.31.0",  # version
            "HTTP lib",  # summary
            None,  # vuln_scanned_at
            None,  # license_scanned_at
            None,  # sbom_scanned_at
            3,  # vuln_finding_count
            "high",  # vuln_max_severity
            None,  # license_findings
            "approve",  # latest_decision
            None,  # latest_decision_at
            "1.0",  # policy_version
            "active",  # status
        )
        pool, _ = _make_pool(fetchone_result=row)
        catalog = PackageCatalog(pool)

        entry = catalog.lookup("pypi", "requests", "2.31.0")

        assert isinstance(entry, CatalogEntry)
        assert entry.package_name == "requests"
        assert entry.version == "2.31.0"
        assert entry.vuln_finding_count == 3
        assert entry.vuln_max_severity == "high"
        assert entry.latest_decision == "approve"


# ---------------------------------------------------------------------------
# PackageCatalog.upsert
# ---------------------------------------------------------------------------


class TestPackageCatalogUpsert:
    """PackageCatalog.upsert() inserts or updates a catalog entry."""

    def test_upsert_creates_new_entry(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool, cursor = _make_pool()
        catalog = PackageCatalog(pool)

        catalog.upsert("pypi", "requests", "2.31.0", summary="HTTP library")

        assert cursor.execute.call_count >= 1
        first_call_sql = cursor.execute.call_args_list[0][0][0]
        assert "INSERT INTO package_catalog" in first_call_sql

    def test_upsert_no_pool_does_not_raise(self) -> None:
        from caliper.data.catalog import PackageCatalog

        catalog = PackageCatalog(None)
        catalog.upsert("pypi", "requests", "2.31.0")  # must not raise


# ---------------------------------------------------------------------------
# PackageCatalog.search_semantic
# ---------------------------------------------------------------------------


class TestPackageCatalogSearchSemantic:
    """PackageCatalog.search_semantic() queries by vector embedding."""

    def test_search_semantic_returns_results(self) -> None:
        from caliper.data.catalog import PackageCatalog

        rows = [
            ("requests", "2.31.0", "pypi", "HTTP library", "approve", None, "active", 0.95),
            ("httpx", "0.27.0", "pypi", "Async HTTP", "approve", None, "active", 0.88),
        ]
        pool, _ = _make_pool(fetchall_result=rows)
        catalog = PackageCatalog(pool)

        results = catalog.search_semantic([0.1] * 8, limit=5)

        assert len(results) == 2
        assert results[0]["package_name"] == "requests"
        assert results[0]["similarity"] == pytest.approx(0.95)
        assert results[1]["package_name"] == "httpx"

    def test_search_semantic_returns_empty_when_pool_is_none(self) -> None:
        from caliper.data.catalog import PackageCatalog

        catalog = PackageCatalog(None)
        assert catalog.search_semantic([0.1], limit=5) == []

    def test_search_semantic_returns_empty_on_db_error(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool = MagicMock()
        pool.connection.side_effect = Exception("connection refused")
        catalog = PackageCatalog(pool)

        assert catalog.search_semantic([0.1], limit=5) == []


# ---------------------------------------------------------------------------
# PackageCatalog.get_consumers
# ---------------------------------------------------------------------------


class TestPackageCatalogGetConsumers:
    """PackageCatalog.get_consumers() returns repo names that use a package."""

    def test_get_consumers_returns_repo_names(self) -> None:
        from caliper.data.catalog import PackageCatalog

        rows = [("repo-a",), ("repo-b",)]
        pool, _ = _make_pool(fetchall_result=rows)
        catalog = PackageCatalog(pool)

        result = catalog.get_consumers("pypi", "requests", "2.31.0")

        assert result == ["repo-a", "repo-b"]

    def test_get_consumers_returns_empty_when_none(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool, _ = _make_pool(fetchall_result=[])
        catalog = PackageCatalog(pool)
        assert catalog.get_consumers("pypi", "requests", "2.31.0") == []

    def test_get_consumers_returns_empty_when_pool_is_none(self) -> None:
        from caliper.data.catalog import PackageCatalog

        catalog = PackageCatalog(None)
        assert catalog.get_consumers("pypi", "requests", "2.31.0") == []


# ---------------------------------------------------------------------------
# PackageCatalog.ingest_lockfile
# ---------------------------------------------------------------------------


class TestPackageCatalogIngestLockfile:
    """PackageCatalog.ingest_lockfile() stores repo package inventory."""

    def test_ingest_lockfile_stores_packages(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool, cursor = _make_pool()
        catalog = PackageCatalog(pool)

        packages = [
            {"name": "requests", "version": "2.31.0", "scope": "runtime"},
            {"name": "flask", "version": "3.0.0", "scope": "runtime"},
        ]
        catalog.ingest_lockfile("my-repo", "/repo/requirements.txt", packages)

        # Should have called execute multiple times:
        # upsert repo_inventory + delete repo_packages + 2x insert repo_packages + 2x insert catalog
        assert cursor.execute.call_count >= 3

    def test_ingest_lockfile_no_pool_does_not_raise(self) -> None:
        from caliper.data.catalog import PackageCatalog

        catalog = PackageCatalog(None)
        catalog.ingest_lockfile("repo", "/lockfile", [{"name": "x", "version": "1.0"}])


# ---------------------------------------------------------------------------
# PackageCatalog.queue_scan
# ---------------------------------------------------------------------------


class TestPackageCatalogQueueScan:
    """PackageCatalog.queue_scan() adds a package to the scan queue."""

    def test_queue_scan_adds_to_queue(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool, cursor = _make_pool()
        catalog = PackageCatalog(pool)

        catalog.queue_scan("pypi", "requests", "2.31.0", scan_type="vuln", priority=1)

        assert cursor.execute.call_count >= 1
        insert_sql = cursor.execute.call_args_list[0][0][0]
        assert "INSERT INTO scan_queue" in insert_sql

    def test_queue_scan_no_pool_does_not_raise(self) -> None:
        from caliper.data.catalog import PackageCatalog

        catalog = PackageCatalog(None)
        catalog.queue_scan("pypi", "requests", "2.31.0")


# ---------------------------------------------------------------------------
# PackageCatalog.mark_vuln_stale
# ---------------------------------------------------------------------------


class TestPackageCatalogMarkVulnStale:
    """PackageCatalog.mark_vuln_stale() nullifies vuln timestamps."""

    def test_mark_vuln_stale_returns_count(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool, cursor = _make_pool(rowcount=42)
        catalog = PackageCatalog(pool)

        count = catalog.mark_vuln_stale()

        assert count == 42

    def test_mark_vuln_stale_returns_zero_when_pool_is_none(self) -> None:
        from caliper.data.catalog import PackageCatalog

        catalog = PackageCatalog(None)
        assert catalog.mark_vuln_stale() == 0


# ---------------------------------------------------------------------------
# Exception absorption — all methods fail-open
# ---------------------------------------------------------------------------


class TestPackageCatalogExceptionAbsorption:
    """All PackageCatalog methods absorb DB exceptions and return gracefully."""

    def test_all_methods_absorb_exceptions(self) -> None:
        from caliper.data.catalog import PackageCatalog

        pool = MagicMock()
        pool.connection.side_effect = Exception("DB down")
        catalog = PackageCatalog(pool)

        assert catalog.lookup("pypi", "requests", "2.31.0") is None
        assert catalog.search_semantic([0.1], limit=5) == []
        assert catalog.get_consumers("pypi", "requests", "2.31.0") == []
        assert catalog.mark_vuln_stale() == 0

        # These return None / have no return value — must not raise
        catalog.upsert("pypi", "requests", "2.31.0")
        catalog.ingest_lockfile("repo", "/lockfile", [{"name": "x", "version": "1.0"}])
        catalog.queue_scan("pypi", "requests", "2.31.0")


class TestSqlInjectionPrevention:
    """Wave 1 Task 1.1: field keys in upsert must be whitelisted, not interpolated."""

    def test_malicious_field_key_rejected(self):
        """A field dict key containing SQL must never appear in the executed SQL.

        The vulnerable code interpolates field keys directly as column names.
        With whitelisting, unknown keys are silently dropped — no UPDATE executes.
        """
        from caliper.data.catalog import PackageCatalog

        pool, cursor = _make_pool()
        catalog = PackageCatalog(pool)

        # Pass malicious key as a direct kwarg — that's how **fields works
        catalog.upsert("pypi", "requests", "2.31.0", **{"x; DROP TABLE t; --": "pwned"})

        for call in cursor.execute.call_args_list:
            sql = call[0][0] if call[0] else ""
            assert "DROP TABLE" not in sql, f"SQL injection in upsert SET clause: {sql}"
            assert "x;" not in sql, f"Malicious key interpolated into SQL: {sql}"

    def test_valid_field_keys_still_work(self):
        """Whitelisted column names must still update correctly."""
        from caliper.data.catalog import PackageCatalog

        pool, cursor = _make_pool()
        catalog = PackageCatalog(pool)

        safe_fields = {"summary": "A great library", "status": "approved"}
        catalog.upsert("pypi", "requests", "2.31.0", fields=safe_fields)

        assert cursor.execute.call_count >= 1
