# tested-by: tests/unit/test_deterministic_queue_guards.py
"""Deterministic guards for background task queue dead letter handling (#182).

These tests use AST and SQL analysis to detect when the scan_queue implementation
lacks proper dead letter queue (DLQ) handling for failed tasks.

Issue #182: Background task queue doesn't have dead letter handling.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #182 — add dead letter handling to fix",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_CATALOG_FILE = _SRC / "data" / "catalog.py"
_MIGRATIONS_DIR = _REPO / "migrations"


def _rel(path: Path) -> str:
    """Return repository-relative path as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _source_contains(tree: ast.Module, pattern: str) -> bool:
    """Check if the source contains a regex pattern (case-insensitive)."""
    source = ast.unparse(tree)
    return bool(re.search(pattern, source, re.IGNORECASE))


def _has_scan_queue_insertion(tree: ast.Module) -> bool:
    """Check if the code inserts into a scan_queue table."""
    source = ast.unparse(tree)
    # Look for INSERT INTO scan_queue pattern
    return bool(re.search(r"INSERT\s+INTO\s+scan_queue", source, re.IGNORECASE))


def _has_dead_letter_table(tree: ast.Module) -> bool:
    """Check if the code references a dead letter queue table."""
    source = ast.unparse(tree)
    patterns = [
        r"dead_letter",
        r"deadletter",
        r"dlq",
        r"failed_queue",
    ]
    return any(re.search(p, source, re.IGNORECASE) for p in patterns)


def _has_retry_tracking(tree: ast.Module) -> bool:
    """Check if the code tracks retry counts or has retry logic."""
    source = ast.unparse(tree)
    patterns = [
        r"retry",
        r"attempt_count",
        r"max_retries",
        r"retry_count",
    ]
    return any(re.search(p, source, re.IGNORECASE) for p in patterns)


def _has_queue_processing_function(tree: ast.Module) -> bool:
    """Check if there's a function that processes items from the queue."""
    source = ast.unparse(tree)
    # Look for patterns that suggest queue processing (SELECT from scan_queue)
    patterns = [
        r"SELECT.*FROM\s+scan_queue",
        r"process.*queue",
        r"dequeue",
        r"poll.*queue",
    ]
    return any(re.search(p, source, re.IGNORECASE) for p in patterns)


def _sql_files_content() -> str:
    """Read all SQL migration files and return combined content."""
    if not _MIGRATIONS_DIR.exists():
        return ""
    content_parts = []
    for sql_file in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        content_parts.append(sql_file.read_text())
    return "\n".join(content_parts)


def _sql_has_dead_letter_table() -> bool:
    """Check if SQL schema defines a dead letter queue table."""
    sql = _sql_files_content()
    patterns = [
        r"CREATE\s+TABLE\s+.*dead_letter",
        r"CREATE\s+TABLE\s+.*deadletter",
        r"CREATE\s+TABLE\s+.*dlq",
        r"CREATE\s+TABLE\s+.*failed_queue",
    ]
    return any(re.search(p, sql, re.IGNORECASE) for p in patterns)


def _sql_has_retry_column() -> bool:
    """Check if scan_queue has retry count tracking column."""
    sql = _sql_files_content()
    # Look for retry_count or retry column in scan_queue definition
    return bool(
        re.search(r"scan_queue.*\b(?:retry|retry_count|attempts)\b", sql, re.IGNORECASE | re.DOTALL)
    )


def _sql_has_failed_at_column() -> bool:
    """Check if scan_queue has failed_at timestamp column."""
    sql = _sql_files_content()
    return bool(re.search(r"scan_queue.*\bfailed_at\b", sql, re.IGNORECASE | re.DOTALL))


@pytest.mark.xfail(
    reason="deterministic bug detector for #182 — background task queue lacks DLQ",
    strict=False,
)
def test_182_scan_queue_has_dead_letter_handling() -> None:
    """Detect missing dead letter queue handling in scan_queue implementation.

    Issue #182 (epic #146): Background task queue doesn't have dead letter handling.

    The scan_queue table is used for background scanning tasks, but there's
    no mechanism to handle tasks that fail repeatedly. A proper implementation
    should include:

    1. A dead letter queue table (dead_letter, dlq, or failed_queue)
    2. Retry count tracking (retry_count column in scan_queue)
    3. Failed timestamp tracking (failed_at column)
    4. Logic to move permanently failed items to the DLQ

    Violations detected:
        - scan_queue exists without corresponding DLQ table in schema
        - No retry_count column for tracking retries
        - No failed_at timestamp for failed tasks

    Acceptance criteria for fix:
        - Either a dead_letter table exists in migrations
        - Or retry_count column added to scan_queue with max_retries logic
        - Or failed_at timestamp added for tracking
    """
    violations: list[str] = []

    if not _CATALOG_FILE.exists():
        violations.append(f"{_rel(_CATALOG_FILE)}: file does not exist")
        pytest.fail("\n".join(violations))

    tree = _parse(_CATALOG_FILE)

    # First, check if this file actually implements a queue
    if not _has_scan_queue_insertion(tree):
        # No queue implementation found - this is fine, skip the test
        pytest.skip("No scan_queue implementation found in catalog.py")

    # Check SQL schema for dead letter handling
    has_dlq_table = _sql_has_dead_letter_table()
    has_retry_column = _sql_has_retry_column()
    has_failed_at_column = _sql_has_failed_at_column()
    has_dlq_python = _has_dead_letter_table(tree)
    has_retry_python = _has_retry_tracking(tree)

    # The bug: scan_queue exists but no DLQ infrastructure
    if not (has_dlq_table or has_retry_column or has_failed_at_column):
        violations.append(
            f"{_rel(_CATALOG_FILE)}: scan_queue table exists but schema lacks "
            f"dead letter handling:\n"
            f"  - No dead_letter/dlq/failed_queue table in migrations\n"
            f"  - No retry_count/attempts column in scan_queue\n"
            f"  - No failed_at timestamp column in scan_queue\n"
            f"\n"
            f"Failed tasks will accumulate in scan_queue with status='failed' "
            f"and never be cleaned up. Add at least one of:\n"
            f"  1. A dead_letter table + move_failed_to_dlq() function\n"
            f"  2. retry_count column with max_retries + retry logic\n"
            f"  3. failed_at timestamp with automatic cleanup"
        )

    # Also check that Python code doesn't reference DLQ if schema doesn't have it
    if has_dlq_python and not has_dlq_table:
        violations.append(
            f"{_rel(_CATALOG_FILE)}: Python references dead_letter but no "
            f"corresponding table exists in migrations SQL files. "
            f"Add CREATE TABLE dead_letter to migrations."
        )

    # Check for retry tracking in Python code (needed if schema has the columns)
    if has_retry_column and not has_retry_python:
        violations.append(
            f"{_rel(_CATALOG_FILE)}: scan_queue has retry_count column but "
            f"Python code doesn't implement retry logic. "
            f"Add retry tracking in queue processing code."
        )

    assert (
        not violations
    ), "Background task queue must have dead letter handling (#182).\n" "\n" + "\n".join(violations)
