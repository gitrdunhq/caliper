"""Org-wide package catalog — centralized scan cache with semantic search.
# tested-by: tests/unit/test_catalog.py

Decouples scanning from PR evaluation. Packages are scanned once and the
results are shared across every repo that uses them. PR evaluation becomes
a DB lookup instead of a 3-minute scanner run.
"""

from __future__ import annotations

from datetime import UTC, datetime

import orjson
import structlog

logger = structlog.get_logger(__name__)

VULN_STALE_HOURS = 24
LICENSE_STALE_HOURS = 168  # 7 days
SBOM_STALE_HOURS = 168


class CatalogEntry:
    """In-memory representation of a package_catalog row."""

    __slots__ = (
        "catalog_id",
        "ecosystem",
        "package_name",
        "version",
        "summary",
        "vuln_scanned_at",
        "license_scanned_at",
        "sbom_scanned_at",
        "vuln_finding_count",
        "vuln_max_severity",
        "license_findings",
        "latest_decision",
        "latest_decision_at",
        "policy_version",
        "status",
    )

    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)

    def is_vuln_fresh(self, max_age_hours: int = VULN_STALE_HOURS) -> bool:
        if self.vuln_scanned_at is None:
            return False
        age = (datetime.now(UTC) - self.vuln_scanned_at).total_seconds() / 3600
        return age < max_age_hours

    def is_license_fresh(self, max_age_hours: int = LICENSE_STALE_HOURS) -> bool:
        if self.license_scanned_at is None:
            return False
        age = (datetime.now(UTC) - self.license_scanned_at).total_seconds() / 3600
        return age < max_age_hours

    def is_sbom_fresh(self, max_age_hours: int = SBOM_STALE_HOURS) -> bool:
        if self.sbom_scanned_at is None:
            return False
        age = (datetime.now(UTC) - self.sbom_scanned_at).total_seconds() / 3600
        return age < max_age_hours

    def needs_scan(self) -> list[str]:
        """Return which scan types are needed."""
        needed = []
        if not self.is_sbom_fresh():
            needed.append("sbom")
        if not self.is_vuln_fresh():
            needed.append("vuln")
        if not self.is_license_fresh():
            needed.append("license")
        return needed


_ALLOWED_UPSERT_COLUMNS: frozenset[str] = frozenset(CatalogEntry.__slots__) - frozenset(
    {"catalog_id", "ecosystem", "package_name", "version"}
)


class PackageCatalog:
    """Read/write interface to the org-wide package catalog.

    All methods absorb database errors — fail-open, same as DecisionRepository.
    """

    def __init__(self, pool: object) -> None:
        self._pool = pool

    def lookup(self, ecosystem: str, package_name: str, version: str) -> CatalogEntry | None:
        """Look up a package in the catalog. Returns None if not found."""
        if self._pool is None:
            return None
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                        SELECT catalog_id, ecosystem, package_name, version,
                               summary, vuln_scanned_at, license_scanned_at,
                               sbom_scanned_at, vuln_finding_count, vuln_max_severity,
                               license_findings, latest_decision, latest_decision_at,
                               policy_version, status
                        FROM package_catalog
                        WHERE ecosystem = %s AND package_name = %s AND version = %s
                        """,
                    (ecosystem, package_name, version),
                )
                row = cur.fetchone()
                if row is None:
                    return None

                cols = [
                    "catalog_id",
                    "ecosystem",
                    "package_name",
                    "version",
                    "summary",
                    "vuln_scanned_at",
                    "license_scanned_at",
                    "sbom_scanned_at",
                    "vuln_finding_count",
                    "vuln_max_severity",
                    "license_findings",
                    "latest_decision",
                    "latest_decision_at",
                    "policy_version",
                    "status",
                ]
                return CatalogEntry(**dict(zip(cols, row, strict=True)))
        except Exception:
            logger.error("catalog_lookup_failed", pkg=package_name, exc_info=True)
            return None

    def upsert(
        self,
        ecosystem: str,
        package_name: str,
        version: str,
        **fields: object,
    ) -> None:
        """Insert or update a catalog entry. Only provided fields are updated."""
        if self._pool is None:
            return
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO package_catalog (ecosystem, package_name, version)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (ecosystem, package_name, version) DO NOTHING
                        """,
                        (ecosystem, package_name, version),
                    )
                    if fields:
                        safe = {k: v for k, v in fields.items() if k in _ALLOWED_UPSERT_COLUMNS}
                        if not safe:
                            conn.commit()
                            return
                        set_clause = ", ".join(f"{k} = %({k})s" for k in safe)
                        safe["eco"] = ecosystem
                        safe["pkg"] = package_name
                        safe["ver"] = version
                        cur.execute(
                            f"UPDATE package_catalog SET {set_clause}, updated_at = now() "
                            "WHERE ecosystem = %(eco)s AND package_name = %(pkg)s "
                            "AND version = %(ver)s",
                            safe,
                        )
                conn.commit()
        except Exception:
            logger.error("catalog_upsert_failed", pkg=package_name, exc_info=True)

    def search_semantic(self, query_embedding: list[float], limit: int = 10) -> list[dict]:
        """Find packages by semantic similarity to a query embedding."""
        if self._pool is None:
            return []
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                        SELECT package_name, version, ecosystem, summary,
                               latest_decision, vuln_max_severity, status,
                               1 - (description_embedding <=> %s::vector) AS similarity
                        FROM package_catalog
                        WHERE description_embedding IS NOT NULL
                        ORDER BY description_embedding <=> %s::vector
                        LIMIT %s
                        """,
                    (query_embedding, query_embedding, limit),
                )
                cols = [
                    "package_name",
                    "version",
                    "ecosystem",
                    "summary",
                    "latest_decision",
                    "vuln_max_severity",
                    "status",
                    "similarity",
                ]
                return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]
        except Exception:
            logger.error("catalog_search_failed", exc_info=True)
            return []

    def get_consumers(self, ecosystem: str, package_name: str, version: str) -> list[str]:
        """Which repos use this package@version?"""
        if self._pool is None:
            return []
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                        SELECT DISTINCT repo_name FROM repo_packages
                        WHERE ecosystem = %s AND package_name = %s AND version = %s
                        """,
                    (ecosystem, package_name, version),
                )
                return [row[0] for row in cur.fetchall()]
        except Exception:
            logger.error("catalog_consumers_failed", exc_info=True)
            return []

    def ingest_lockfile(self, repo_name: str, lockfile_path: str, packages: list[dict]) -> None:
        """Update repo inventory from a parsed lockfile.

        packages: list of {"name": str, "version": str, "scope": str}
        """
        if self._pool is None:
            return
        try:
            import hashlib

            lockfile_hash = hashlib.sha256(
                orjson.dumps(sorted(packages, key=lambda p: p["name"]))
            ).hexdigest()

            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    # Upsert repo inventory
                    cur.execute(
                        """
                        INSERT INTO repo_inventory (repo_name, lockfile_path, lockfile_hash)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (repo_name, lockfile_path)
                        DO UPDATE SET lockfile_hash = EXCLUDED.lockfile_hash, updated_at = now()
                        """,
                        (repo_name, lockfile_path, lockfile_hash),
                    )

                    # Clear old package associations for this repo
                    cur.execute(
                        "DELETE FROM repo_packages WHERE repo_name = %s",
                        (repo_name,),
                    )

                    # Insert current packages
                    for pkg in packages:
                        cur.execute(
                            """
                            INSERT INTO repo_packages
                                (repo_name, ecosystem, package_name, version, scope)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                            """,
                            (
                                repo_name,
                                "pypi",
                                pkg["name"],
                                pkg["version"],
                                pkg.get("scope", "runtime"),
                            ),
                        )

                        # Ensure package exists in catalog
                        cur.execute(
                            """
                            INSERT INTO package_catalog (ecosystem, package_name, version)
                            VALUES (%s, %s, %s)
                            ON CONFLICT DO NOTHING
                            """,
                            ("pypi", pkg["name"], pkg["version"]),
                        )

                conn.commit()
            logger.info(
                "lockfile_ingested",
                repo=repo_name,
                packages=len(packages),
                lockfile=lockfile_path,
            )
        except Exception:
            logger.error("lockfile_ingest_failed", repo=repo_name, exc_info=True)

    def queue_scan(
        self,
        ecosystem: str,
        package_name: str,
        version: str,
        scan_type: str = "full",
        priority: int = 0,
        requested_by: str | None = None,
    ) -> None:
        """Add a package to the scan queue."""
        if self._pool is None:
            return
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO scan_queue
                            (ecosystem, package_name, version, scan_type, priority, requested_by)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (ecosystem, package_name, version, scan_type, priority, requested_by),
                    )
                conn.commit()
        except Exception:
            logger.error("queue_scan_failed", pkg=package_name, exc_info=True)

    def mark_vuln_stale(self) -> int:
        """Mark all vuln scans as stale (for weekly rescan trigger). Returns count."""
        if self._pool is None:
            return 0
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE package_catalog SET vuln_scanned_at = NULL "
                        "WHERE vuln_scanned_at IS NOT NULL"
                    )
                    count = cur.rowcount
                conn.commit()
            logger.info("vuln_cache_invalidated", count=count)
            return count
        except Exception:
            logger.error("vuln_stale_failed", exc_info=True)
            return 0
