"""Decision record repository -- persistence layer for review decisions.
# tested-by: tests/unit/test_db.py

Fail-open design: database failures are logged and absorbed, never raised.
The pipeline continues regardless of persistence availability.
"""

from __future__ import annotations

import re
import uuid
from typing import Protocol, runtime_checkable

import orjson
import structlog

try:
    from psycopg_pool import ConnectionPool
except ImportError:
    ConnectionPool = None  # type: ignore[assignment,misc]

from caliper.core.models import (
    BypassRecord,
    PolicyEvaluation,
    ReviewDecision,
    ReviewRequest,
    ScanResult,
)

logger = structlog.get_logger(__name__)


@runtime_checkable
class RepositoryProtocol(Protocol):
    """Structural contract for review pipeline repository implementations."""

    def save_request(self, request: ReviewRequest) -> None: ...
    def save_scan_results(self, request_id: uuid.UUID, results: list[ScanResult]) -> None: ...
    def save_policy_evaluation(
        self, request_id: uuid.UUID, evaluation: PolicyEvaluation
    ) -> None: ...
    def save_decision(self, request_id: uuid.UUID, decision: ReviewDecision) -> None: ...
    def get_decision_by_request_id(self, request_id: uuid.UUID) -> ReviewDecision | None: ...
    def save_bypass(self, record: BypassRecord) -> None: ...
    def close(self) -> None: ...
    def connect(self) -> bool: ...


_QUERY_TIMEOUT_MS_MULTIPLIER = 1000


def _ensure_connect_timeout(dsn: str, timeout: int) -> str:
    """Append connect_timeout to DSN if not already present."""
    if "connect_timeout" in dsn:
        return dsn
    sep = "&" if "?" in dsn else "?"
    return f"{dsn}{sep}connect_timeout={timeout}"


def _safe_dsn(dsn: str) -> str:
    """Return the DSN with the password replaced by '***'.

    Prevents credential leakage in log output.
    Input ``postgresql://user:secret@host/db`` → ``postgresql://user:***@host/db``.
    DSNs without a password component are returned unchanged.
    """
    return re.sub(r"://([^:]+):[^@]+@", r"://\1:***@", dsn)


class DecisionRepository:
    """Postgres-backed repository for review pipeline records.

    All methods absorb database errors -- they log the failure and return
    gracefully so the review pipeline is never blocked by storage issues.
    """

    def __init__(self, dsn: str, query_timeout: int = 10, connect_timeout: int = 5) -> None:
        self._dsn = _ensure_connect_timeout(dsn, connect_timeout)
        self._query_timeout = query_timeout
        self._pool: ConnectionPool | None = None

    def connect(self) -> bool:
        """Test connectivity and initialize the connection pool.

        Returns True if the pool was created and a connection succeeds,
        False otherwise.
        """
        if ConnectionPool is None:
            logger.error(
                "database_unavailable", reason="psycopg not installed (pip install caliper[db])"
            )
            return False
        try:
            self._pool = ConnectionPool(self._dsn, min_size=1, max_size=10, open=True)
            with self._pool.connection() as conn:
                conn.execute("SELECT 1")
            logger.info("database_connected", dsn=_safe_dsn(self._dsn))
            return True
        except Exception:
            logger.error("database_connection_failed", dsn=_safe_dsn(self._dsn), exc_info=True)
            self._pool = None
            return False

    def close(self) -> None:
        """Close the connection pool."""
        if self._pool is not None:
            try:
                self._pool.close()
            except Exception:
                logger.error("pool_close_failed", exc_info=True)
            self._pool = None

    def _timeout_sql(self) -> str:
        return (
            f"SET LOCAL statement_timeout = '{self._query_timeout * _QUERY_TIMEOUT_MS_MULTIPLIER}'"
        )

    def save_request(self, request: ReviewRequest) -> None:
        """INSERT an review request record."""
        if self._pool is None:
            logger.warning("save_request_skipped", reason="no_pool")
            return

        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(self._timeout_sql())
                    cur.execute(
                        """
                        INSERT INTO review_requests (
                            request_id, request_type, ecosystem, package_name,
                            target_version, current_version, team, scope,
                            pr_url, pr_number, repo_name, commit_sha,
                            use_case, operating_mode, created_at
                        ) VALUES (
                            %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s
                        )
                        """,
                        (
                            str(request.request_id),
                            request.request_type.value,
                            request.ecosystem,
                            request.package_name,
                            request.target_version,
                            request.current_version,
                            request.team,
                            request.scope,
                            request.pr_url,
                            request.pr_number,
                            request.repo_name,
                            request.commit_sha,
                            request.use_case,
                            request.operating_mode.value,
                            request.created_at,
                        ),
                    )
                conn.commit()
            logger.info("request_saved", request_id=str(request.request_id))
        except Exception:
            payload = request.model_dump_json()
            logger.error(
                "save_request_failed",
                request_id=str(request.request_id),
                payload=payload,
                exc_info=True,
            )

    def save_scan_results(self, request_id: uuid.UUID, results: list[ScanResult]) -> None:
        """INSERT a batch of scan result records."""
        if self._pool is None:
            logger.warning("save_scan_results_skipped", reason="no_pool")
            return

        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(self._timeout_sql())
                    for result in results:
                        cur.execute(
                            """
                            INSERT INTO scan_results (
                                request_id, tool_name, status,
                                finding_count, duration_seconds,
                                raw_output_path, message
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                str(request_id),
                                result.tool_name,
                                result.status.value,
                                len(result.findings),
                                result.duration_seconds,
                                result.raw_output_path,
                                result.message,
                            ),
                        )
                conn.commit()
            logger.info(
                "scan_results_saved",
                request_id=str(request_id),
                count=len(results),
            )
        except Exception:
            payload = orjson.dumps([r.model_dump() for r in results]).decode()
            logger.error(
                "save_scan_results_failed",
                request_id=str(request_id),
                payload=payload,
                exc_info=True,
            )

    def save_policy_evaluation(self, request_id: uuid.UUID, evaluation: PolicyEvaluation) -> None:
        """INSERT a policy evaluation record."""
        if self._pool is None:
            logger.warning("save_policy_evaluation_skipped", reason="no_pool")
            return

        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(self._timeout_sql())
                    cur.execute(
                        """
                        INSERT INTO policy_evaluations (
                            request_id, policy_version, decision,
                            triggered_rules, constraints, note
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            str(request_id),
                            evaluation.policy_bundle_version,
                            evaluation.decision.value,
                            orjson.dumps(evaluation.triggered_rules).decode(),
                            orjson.dumps(evaluation.constraints).decode(),
                            evaluation.note,
                        ),
                    )
                conn.commit()
            logger.info("policy_evaluation_saved", request_id=str(request_id))
        except Exception:
            payload = evaluation.model_dump_json()
            logger.error(
                "save_policy_evaluation_failed",
                request_id=str(request_id),
                payload=payload,
                exc_info=True,
            )

    def save_decision(self, request_id: uuid.UUID, decision: ReviewDecision) -> None:
        """INSERT a final review decision record."""
        if self._pool is None:
            logger.warning("save_decision_skipped", reason="no_pool")
            return

        try:
            findings_summary = orjson.dumps([f.model_dump() for f in decision.findings]).decode()

            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(self._timeout_sql())
                    cur.execute(
                        """
                        INSERT INTO review_decisions (
                            decision_id, request_id, decision,
                            findings_summary, evidence_bundle_path,
                            memo_text, pipeline_duration_seconds,
                            operating_mode, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            str(decision.decision_id),
                            str(request_id),
                            decision.decision.value,
                            findings_summary,
                            decision.evidence_bundle_path,
                            decision.memo_text,
                            decision.pipeline_duration_seconds,
                            decision.request.operating_mode.value,
                            decision.created_at,
                        ),
                    )
                conn.commit()
            logger.info(
                "decision_saved",
                request_id=str(request_id),
                decision_id=str(decision.decision_id),
            )
        except Exception:
            payload = decision.model_dump_json()
            logger.error(
                "save_decision_failed",
                request_id=str(request_id),
                payload=payload,
                exc_info=True,
            )

    def get_decision_by_request_id(self, request_id: uuid.UUID) -> ReviewDecision | None:
        """SELECT a decision by request_id. Returns None if not found or on error."""
        if self._pool is None:
            logger.warning("get_decision_skipped", reason="no_pool")
            return None

        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(self._timeout_sql())
                cur.execute(
                    """
                        SELECT
                            d.decision_id, d.decision, d.findings_summary,
                            d.evidence_bundle_path, d.memo_text,
                            d.pipeline_duration_seconds, d.operating_mode,
                            d.created_at,
                            r.request_id, r.request_type, r.ecosystem,
                            r.package_name, r.target_version, r.current_version,
                            r.team, r.scope, r.pr_url, r.pr_number,
                            r.repo_name, r.commit_sha, r.use_case,
                            r.operating_mode AS req_operating_mode,
                            r.created_at AS req_created_at
                        FROM review_decisions d
                        JOIN review_requests r ON r.request_id = d.request_id
                        WHERE d.request_id = %s
                        ORDER BY d.created_at DESC
                        LIMIT 1
                        """,
                    (str(request_id),),
                )
                row = cur.fetchone()

            if row is None:
                return None

            request = ReviewRequest(
                request_id=uuid.UUID(row[8]),
                request_type=row[9],
                ecosystem=row[10],
                package_name=row[11],
                target_version=row[12],
                current_version=row[13],
                team=row[14],
                scope=row[15],
                pr_url=row[16],
                pr_number=row[17],
                repo_name=row[18],
                commit_sha=row[19],
                use_case=row[20],
                operating_mode=row[21],
                created_at=row[22],
            )

            findings = orjson.loads(row[2]) if row[2] else []

            return ReviewDecision(
                decision_id=uuid.UUID(row[0]),
                request=request,
                decision=row[1],
                findings=findings,
                scan_results=[],
                policy_evaluation=PolicyEvaluation(
                    decision=row[1],
                    triggered_rules=[],
                    policy_bundle_version="unknown",
                ),
                evidence_bundle_path=row[3],
                memo_text=row[4],
                pipeline_duration_seconds=row[5],
                created_at=row[7],
            )
        except Exception:
            logger.error(
                "get_decision_failed",
                request_id=str(request_id),
                exc_info=True,
            )
            return None

    def save_bypass(self, record: BypassRecord) -> None:
        """INSERT a bypass record."""
        if self._pool is None:
            logger.warning("save_bypass_skipped", reason="no_pool")
            return

        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(self._timeout_sql())
                    cur.execute(
                        """
                        INSERT INTO bypass_records (
                            bypass_id, request_id, bypass_type,
                            invoked_by, reason, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            str(record.bypass_id),
                            str(record.request_id),
                            record.bypass_type,
                            record.invoked_by,
                            record.reason,
                            record.timestamp,
                        ),
                    )
                conn.commit()
            logger.info(
                "bypass_saved",
                bypass_id=str(record.bypass_id),
                request_id=str(record.request_id),
            )
        except Exception:
            payload = record.model_dump_json()
            logger.error(
                "save_bypass_failed",
                bypass_id=str(record.bypass_id),
                payload=payload,
                exc_info=True,
            )


class NullRepository:
    """No-op repository for when the database is unavailable or during testing.

    All methods silently succeed without doing anything.
    """

    def connect(self) -> bool:
        return True

    def close(self) -> None:
        pass

    def save_request(self, request: ReviewRequest) -> None:
        pass

    def save_scan_results(self, request_id: uuid.UUID, results: list[ScanResult]) -> None:
        pass

    def save_policy_evaluation(self, request_id: uuid.UUID, evaluation: PolicyEvaluation) -> None:
        pass

    def save_decision(self, request_id: uuid.UUID, decision: ReviewDecision) -> None:
        pass

    def get_decision_by_request_id(self, request_id: uuid.UUID) -> ReviewDecision | None:
        return None

    def save_bypass(self, record: BypassRecord) -> None:
        pass


from caliper.core.registries import DECISION_STORES  # noqa: E402  (registration wiring)


@DECISION_STORES.register("postgres")
def build_postgres_decision_store(
    *, dsn: str, query_timeout: int = 10, connect_timeout: int = 5
) -> DecisionRepository:
    """Construct the Postgres-backed decision repository (not yet connected)."""
    return DecisionRepository(dsn=dsn, query_timeout=query_timeout, connect_timeout=connect_timeout)
