# tested-by: tests/unit/test_deterministic_parquet_guards.py
"""Deterministic guards for Parquet audit log append efficiency (#256).

These tests detect when the Parquet append operation inefficiently reads
and rewrites the entire audit log file instead of using true append
semantics. This is a performance issue that becomes critical as audit logs grow.

Bug: #256 — Parquet append rewrites the whole audit log
Parent: #222
Epic: #146
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)


def _make_minimal_review_decision() -> Any:
    """Create a minimal ReviewDecision-like object for testing."""
    from dataclasses import dataclass, field
    from enum import Enum
    from uuid import uuid4

    class Severity(Enum):
        critical = "critical"
        high = "high"
        medium = "medium"
        low = "low"
        info = "info"

    class Decision(Enum):
        approved = "approved"
        denied = "denied"
        flagged = "flagged"

    class RequestType(Enum):
        promote = "promote"

    class OperatingMode(Enum):
        standard = "standard"

    class ToolStatus(Enum):
        success = "success"

    @dataclass
    class Finding:
        severity: Severity
        advisory_id: str = ""

    @dataclass
    class ScanResult:
        tool_name: str = "test"
        status: ToolStatus = field(default_factory=lambda: ToolStatus.success)

    @dataclass
    class PolicyEval:
        triggered_rules: list[str] = field(default_factory=list)
        constraints: list[str] = field(default_factory=list)
        policy_bundle_version: str = "1.0.0"

    @dataclass
    class Request:
        commit_sha: str = "abc123"
        package_name: str = "test-pkg"
        target_version: str = "1.0.0"
        ecosystem: str = "pypi"
        team: str = "test-team"
        scope: str = "test-scope"
        pr_url: str = ""
        request_type: RequestType = field(default_factory=lambda: RequestType.promote)
        operating_mode: OperatingMode = field(default_factory=lambda: OperatingMode.standard)

    @dataclass
    class ReviewDecision:
        decision_id: Any = field(default_factory=uuid4)
        request: Request = field(default_factory=Request)
        findings: list[Finding] = field(default_factory=list)
        policy_evaluation: PolicyEval = field(default_factory=PolicyEval)
        scan_results: list[ScanResult] = field(default_factory=lambda: [ScanResult()])
        decision: Decision = field(default_factory=lambda: Decision.approved)
        created_at: Any = None
        pipeline_duration_seconds: float = 0.0
        memo_text: str = ""

    return ReviewDecision()


def test_256_parquet_append_does_not_read_whole_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Detect when append_decisions reads existing Parquet file (inefficient rewrite).

    Issue #256: The current implementation reads the entire Parquet file,
    concatenates new rows in memory, and writes back. This is O(n) with
    file size. True append should not read existing data.

    This test detects the bug by mocking pq.read_table and asserting
    it is NOT called during append operations.
    """
    import caliper.data.parquet_writer as parquet_writer

    class FakeTable:
        def __init__(self, num_rows: int) -> None:
            self.num_rows = num_rows

        def __len__(self) -> int:
            return self.num_rows

    class FakePa:
        class Table:
            @staticmethod
            def from_pylist(
                rows: list[dict[str, object]],
                schema: object,
            ) -> FakeTable:
                return FakeTable(len(rows))

        @staticmethod
        def schema(fields: list[object]) -> object:
            return fields

        @staticmethod
        def string() -> str:
            return "string"

        @staticmethod
        def int32() -> str:
            return "int32"

        @staticmethod
        def float64() -> str:
            return "float64"

        @staticmethod
        def timestamp(unit: str, tz: str) -> tuple[str, str, str]:
            return ("timestamp", unit, tz)

        @staticmethod
        def list_(value_type: object) -> tuple[str, object]:
            return ("list", value_type)

        @staticmethod
        def concat_tables(tables: list[FakeTable]) -> FakeTable:
            return FakeTable(sum(table.num_rows for table in tables))

    class FakePq:
        def __init__(self) -> None:
            self.read_calls = 0
            self.write_calls = 0
            self.last_write_path: Path | None = None

        def read_table(self, path: Path, schema: object) -> FakeTable:
            """Track that the inefficient read occurred."""
            self.read_calls += 1
            # Simulate existing data - this is the bug!
            return FakeTable(1000)

        def write_table(self, table: FakeTable, path: Path) -> None:
            """Track writes."""
            self.write_calls += 1
            self.last_write_path = path
            path.write_bytes(b"parquet")

    fake_pq = FakePq()
    monkeypatch.setattr(parquet_writer, "pa", FakePa())
    monkeypatch.setattr(parquet_writer, "pq", fake_pq)

    # Create existing parquet file to trigger the read path
    parquet_path = tmp_path / parquet_writer.PARQUET_FILENAME
    parquet_path.write_bytes(b"existing-parquet-data")

    # Attempt to append a decision
    decision = _make_minimal_review_decision()
    parquet_writer.append_decisions(tmp_path, [decision], run_id="test-run-256")

    # BUG DETECTOR: If read_calls > 0, the implementation is inefficiently
    # reading the entire file. True append should be O(1) with file size.
    assert fake_pq.read_calls == 0, (
        f"BUG #256: append_decisions() called pq.read_table {fake_pq.read_calls} time(s). "
        f"This means it read the entire existing audit log (O(n) operation). "
        f"Efficient append should NOT read existing data. "
        f"See issue #256: Parquet append rewrites the whole audit log."
    )


def test_256_parquet_append_uses_efficient_write_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Detect write amplification: output bytes vs input bytes ratio.

    When appending small data to a large file, the rewrite pattern writes
    (existing_size + new_size) instead of just new_size. This test measures
    the write amplification factor.
    """
    import caliper.data.parquet_writer as parquet_writer

    # Track write sizes
    write_sizes: list[int] = []

    class FakeTable:
        def __init__(self, num_rows: int) -> None:
            self.num_rows = num_rows

    class FakePa:
        class Table:
            @staticmethod
            def from_pylist(
                rows: list[dict[str, object]],
                schema: object,
            ) -> FakeTable:
                return FakeTable(len(rows))

        @staticmethod
        def schema(fields: list[object]) -> object:
            return fields

        @staticmethod
        def string() -> str:
            return "string"

        @staticmethod
        def int32() -> str:
            return "int32"

        @staticmethod
        def float64() -> str:
            return "float64"

        @staticmethod
        def timestamp(unit: str, tz: str) -> tuple[str, str, str]:
            return ("timestamp", unit, tz)

        @staticmethod
        def list_(value_type: object) -> tuple[str, object]:
            return ("list", value_type)

        @staticmethod
        def concat_tables(tables: list[FakeTable]) -> FakeTable:
            return FakeTable(sum(table.num_rows for table in tables))

    class FakePq:
        def __init__(self) -> None:
            self.read_calls = 0

        def read_table(self, path: Path, schema: object) -> FakeTable:
            self.read_calls += 1
            # Simulate 10,000 existing rows (large audit log)
            return FakeTable(10000)

        def write_table(self, table: FakeTable, path: Path) -> None:
            # In rewrite pattern, writes all existing + new rows
            # In efficient append, would only write new data
            write_sizes.append(table.num_rows)
            path.write_bytes(b"parquet" * table.num_rows)

    fake_pq = FakePq()
    monkeypatch.setattr(parquet_writer, "pa", FakePa())
    monkeypatch.setattr(parquet_writer, "pq", fake_pq)

    # Create existing large parquet file
    parquet_path = tmp_path / parquet_writer.PARQUET_FILENAME
    parquet_path.write_bytes(b"x" * 100000)  # 100KB existing file

    # Append just 1 new decision
    decision = _make_minimal_review_decision()
    parquet_writer.append_decisions(tmp_path, [decision], run_id="test-run-256")

    if fake_pq.read_calls > 0 and write_sizes:
        # Calculate write amplification
        rows_written = write_sizes[0]
        rows_appended = 1
        amplification = rows_written / rows_appended

        # If amplification > 100x, this is clearly the rewrite bug
        assert amplification < 100, (
            f"BUG #256: Write amplification is {amplification:.1f}x. "
            f"Appending {rows_appended} row(s) caused {rows_written} row(s) to be written. "
            f"This indicates full-file rewrite pattern. "
            f"See issue #256: Parquet append rewrites the whole audit log."
        )
