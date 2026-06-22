"""Deterministic bug detector for missing migration rollback scripts (#203).

Bug #169: Database migrations don't have rollback scripts.
Parent: #169
Epic: #146

This test detects when forward migration scripts exist but their corresponding
rollback scripts are missing. Every migration should have a paired rollback
to enable safe downgrades and recovery.

# tested-by: tests/unit/test_deterministic_migration_guards.py
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector: issue #203 - migrations lack rollback scripts",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_MIGRATIONS_DIR = _REPO / "migrations"

# Common rollback file naming patterns (in order of preference)
ROLLBACK_PATTERNS = [
    "{base}_rollback.sql",  # 001_initial_schema_rollback.sql
    "{base}_down.sql",  # 001_initial_schema_down.sql
    "{base}_undo.sql",  # 001_initial_schema_undo.sql
    "{num}_rollback_{base}.sql",  # 001_rollback_initial_schema.sql
    "{num}_down_{base}.sql",  # 001_down_initial_schema.sql
]


def _extract_migration_base(filename: str) -> tuple[str, str] | None:
    """Extract (number, base_name) from migration filename.

    Examples:
        "001_initial_schema.sql" -> ("001", "initial_schema")
        "002_package_catalog.sql" -> ("002", "package_catalog")
    """
    match = re.match(r"^(\d+)_(.+)\.sql$", filename)
    if match:
        return match.group(1), match.group(2)
    return None


def _find_missing_rollbacks() -> list[tuple[str, list[str]]]:
    """Find migrations without corresponding rollback scripts.

    Returns:
        List of (migration_file, list_of_expected_rollback_patterns) tuples
    """
    if not _MIGRATIONS_DIR.exists():
        return []

    missing: list[tuple[str, list[str]]] = []

    # Get all SQL files
    sql_files = list(_MIGRATIONS_DIR.glob("*.sql"))
    filenames = {f.name for f in sql_files}

    for sql_file in sql_files:
        # Skip files that are already rollbacks
        if "rollback" in sql_file.name or "_down" in sql_file.name or "_undo" in sql_file.name:
            continue

        base_parts = _extract_migration_base(sql_file.name)
        if not base_parts:
            continue

        num, base = base_parts

        # Check if any rollback variant exists
        has_rollback = False
        expected_patterns: list[str] = []

        for pattern in ROLLBACK_PATTERNS:
            rollback_name = pattern.format(num=num, base=base)
            expected_patterns.append(rollback_name)
            if rollback_name in filenames:
                has_rollback = True
                break

        if not has_rollback:
            missing.append((sql_file.name, expected_patterns))

    return missing


def test_203_migrations_have_rollback_scripts() -> None:
    """Detect database migrations without corresponding rollback scripts.

    Issue #203 (parent #169, epic #146): Every forward migration must have
    a corresponding rollback script to enable safe database downgrades.

    Failure conditions detected:
        - Migration file exists (e.g., 001_initial_schema.sql)
        - No corresponding rollback script found

    Rollback naming conventions checked (in order):
        - {number}_{base}_rollback.sql (e.g., 001_initial_schema_rollback.sql)
        - {number}_{base}_down.sql (e.g., 001_initial_schema_down.sql)
        - {number}_{base}_undo.sql (e.g., 001_initial_schema_undo.sql)
        - {number}_rollback_{base}.sql (e.g., 001_rollback_initial_schema.sql)
        - {number}_down_{base}.sql (e.g., 001_down_initial_schema.sql)

    Fix: Create a rollback script for each missing migration using one of
    the above naming conventions. The rollback should undo all DDL changes
    made by the forward migration (DROP TABLE, DROP INDEX, etc.).
    """
    missing = _find_missing_rollbacks()

    if missing:
        messages = []
        for migration, expected in missing:
            # Build expected file path examples
            examples = [str(_MIGRATIONS_DIR / exp) for exp in expected[:3]]
            messages.append(
                f"  - {migration}: missing rollback script\n"
                f"    Expected one of:\n" + "\n".join(f"      • {e}" for e in examples)
            )

        pytest.fail(
            "Database migrations lack rollback scripts (issue #203):\n"
            "\n".join(messages) + "\n\nEvery forward migration must have a paired rollback script. "
            "Rollbacks enable safe downgrades and disaster recovery. "
            "See: https://github.com/your-org/caliper/issues/169"
        )
