"""Tests for caliper.data.db — decision record repository."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

from caliper.core.models import (
    BypassRecord,
    DecisionVerdict,
    OperatingMode,
    PolicyEvaluation,
    RequestType,
    ReviewDecision,
    ReviewRequest,
    ScanResult,
    ScanResultStatus,
)


def _make_request(
    request_id: uuid.UUID | None = None,
) -> ReviewRequest:
    return ReviewRequest(
        request_id=request_id or uuid.uuid4(),
        request_type=RequestType.new_package,
        ecosystem="pypi",
        package_name="requests",
        target_version="2.31.0",
        team="platform",
        operating_mode=OperatingMode.monitor,
    )


def _make_scan_result() -> ScanResult:
    return ScanResult(
        tool_name="osv-scanner",
        status=ScanResultStatus.success,
        findings=[],
        duration_seconds=1.5,
    )


def _make_policy_evaluation() -> PolicyEvaluation:
    return PolicyEvaluation(
        decision=DecisionVerdict.approve,
        triggered_rules=["age_check"],
        policy_bundle_version="1.0.0",
    )


def _make_decision(request: ReviewRequest) -> ReviewDecision:
    return ReviewDecision(
        request=request,
        decision=DecisionVerdict.approve,
        findings=[],
        scan_results=[],
        policy_evaluation=_make_policy_evaluation(),
        pipeline_duration_seconds=5.0,
    )


def _make_bypass(request_id: uuid.UUID) -> BypassRecord:
    return BypassRecord(
        request_id=request_id,
        bypass_type="manual",
        invoked_by="admin@example.com",
        reason="Emergency hotfix",
    )


class TestDecisionRepository:
    """Tests for the DecisionRepository class."""

    def test_save_request_executes_insert_with_correct_params(self) -> None:
        """save_request should execute INSERT with the request fields."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        mock_pool = MagicMock()
        mock_pool.connection.return_value = mock_conn
        repo._pool = mock_pool

        request = _make_request()
        repo.save_request(request)

        # cursor.execute called at least twice: SET timeout + INSERT
        assert mock_cursor.execute.call_count >= 2
        insert_call = mock_cursor.execute.call_args_list[1]
        sql_text = insert_call[0][0]
        params = insert_call[0][1]

        assert "INSERT INTO review_requests" in sql_text
        assert str(request.request_id) in params
        assert request.package_name in params
        assert request.ecosystem in params

    def test_save_request_no_pool_does_not_raise(self) -> None:
        """save_request with no pool should log warning and return silently."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        # _pool is None by default
        request = _make_request()
        # Must not raise
        repo.save_request(request)

    def test_save_request_db_error_logs_and_does_not_raise(self) -> None:
        """Database errors during save_request should be logged, never raised."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        mock_pool = MagicMock()
        mock_pool.connection.side_effect = Exception("connection refused")
        repo._pool = mock_pool

        request = _make_request()
        # Must not raise
        repo.save_request(request)

    def test_connect_failure_returns_false(self) -> None:
        """connect() should return False when the database is unreachable."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://bad-host:5432/nope")

        with patch("caliper.data.db.ConnectionPool", side_effect=Exception("refused")):
            result = repo.connect()

        assert result is False
        assert repo._pool is None

    def test_connect_success_returns_true(self) -> None:
        """connect() should return True when connection succeeds."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")

        mock_pool = MagicMock()
        mock_conn = MagicMock()
        mock_pool.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_pool.connection.return_value.__exit__ = MagicMock(return_value=False)

        with patch("caliper.data.db.ConnectionPool", return_value=mock_pool):
            result = repo.connect()

        assert result is True
        assert repo._pool is mock_pool

    def test_get_decision_by_request_id_returns_none_when_not_found(self) -> None:
        """get_decision_by_request_id returns None when no row matches."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        mock_pool = MagicMock()
        mock_pool.connection.return_value = mock_conn
        repo._pool = mock_pool

        result = repo.get_decision_by_request_id(uuid.uuid4())
        assert result is None

    def test_get_decision_db_error_returns_none(self) -> None:
        """get_decision_by_request_id returns None on database error."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        mock_pool = MagicMock()
        mock_pool.connection.side_effect = Exception("timeout")
        repo._pool = mock_pool

        result = repo.get_decision_by_request_id(uuid.uuid4())
        assert result is None

    def test_save_scan_results_db_error_does_not_raise(self) -> None:
        """save_scan_results should absorb database errors."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        mock_pool = MagicMock()
        mock_pool.connection.side_effect = Exception("disk full")
        repo._pool = mock_pool

        repo.save_scan_results(uuid.uuid4(), [_make_scan_result()])

    def test_save_policy_evaluation_db_error_does_not_raise(self) -> None:
        """save_policy_evaluation should absorb database errors."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        mock_pool = MagicMock()
        mock_pool.connection.side_effect = Exception("network error")
        repo._pool = mock_pool

        repo.save_policy_evaluation(uuid.uuid4(), _make_policy_evaluation())

    def test_save_decision_db_error_does_not_raise(self) -> None:
        """save_decision should absorb database errors."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        mock_pool = MagicMock()
        mock_pool.connection.side_effect = Exception("constraint violation")
        repo._pool = mock_pool

        request = _make_request()
        decision = _make_decision(request)
        repo.save_decision(request.request_id, decision)

    def test_save_bypass_db_error_does_not_raise(self) -> None:
        """save_bypass should absorb database errors."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        mock_pool = MagicMock()
        mock_pool.connection.side_effect = Exception("lost connection")
        repo._pool = mock_pool

        repo.save_bypass(_make_bypass(uuid.uuid4()))

    def test_close_with_pool(self) -> None:
        """close() should close the pool and set it to None."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        mock_pool = MagicMock()
        repo._pool = mock_pool

        repo.close()

        mock_pool.close.assert_called_once()
        assert repo._pool is None

    def test_close_without_pool(self) -> None:
        """close() without a pool should be a no-op."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test")
        repo.close()  # Must not raise

    def test_query_timeout_is_configurable(self) -> None:
        """The query timeout should be set from the constructor parameter."""
        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://fake:5432/test", query_timeout=30)

        timeout_sql = repo._timeout_sql()
        assert "30000" in timeout_sql

    def test_connect_log_does_not_expose_dsn_password(self) -> None:
        """F-009: database_connected log event must not contain the raw password."""
        import structlog

        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://admin:mysecretpw@host:5432/db")

        captured: list[dict] = []

        def _capture(logger, method, event_dict):  # noqa: ANN001
            captured.append(dict(event_dict))
            raise structlog.DropEvent()

        structlog.configure(processors=[_capture])

        with patch("caliper.data.db.ConnectionPool") as mock_pool:
            mock_conn = MagicMock()
            mock_pool.return_value.connection.return_value.__enter__ = MagicMock(
                return_value=mock_conn
            )
            mock_pool.return_value.connection.return_value.__exit__ = MagicMock(return_value=False)
            repo.connect()

        for evt in captured:
            assert "mysecretpw" not in str(evt), f"password leaked in log event: {evt}"

    def test_connect_failure_log_does_not_expose_dsn_password(self) -> None:
        """F-009: database_connection_failed log event must not contain the raw password."""
        import structlog

        from caliper.data.db import DecisionRepository

        repo = DecisionRepository(dsn="postgresql://admin:topsecret@host:5432/db")

        captured: list[dict] = []

        def _capture(logger, method, event_dict):  # noqa: ANN001
            captured.append(dict(event_dict))
            raise structlog.DropEvent()

        structlog.configure(processors=[_capture])

        with patch("caliper.data.db.ConnectionPool", side_effect=Exception("refused")):
            repo.connect()

        for evt in captured:
            assert "topsecret" not in str(evt), f"password leaked in log event: {evt}"


class TestNullRepository:
    """Tests for the NullRepository no-op implementation."""

    def test_connect_returns_true(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        assert repo.connect() is True

    def test_close_is_noop(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        repo.close()  # Must not raise

    def test_save_request_is_noop(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        repo.save_request(_make_request())

    def test_save_scan_results_is_noop(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        repo.save_scan_results(uuid.uuid4(), [_make_scan_result()])

    def test_save_policy_evaluation_is_noop(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        repo.save_policy_evaluation(uuid.uuid4(), _make_policy_evaluation())

    def test_save_decision_is_noop(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        request = _make_request()
        repo.save_decision(request.request_id, _make_decision(request))

    def test_get_decision_returns_none(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        assert repo.get_decision_by_request_id(uuid.uuid4()) is None

    def test_save_bypass_is_noop(self) -> None:
        from caliper.data.db import NullRepository

        repo = NullRepository()
        repo.save_bypass(_make_bypass(uuid.uuid4()))
