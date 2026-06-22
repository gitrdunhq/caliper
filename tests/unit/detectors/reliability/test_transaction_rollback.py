"""Tests for Transaction Rollback detector.
# tested-by: tests/unit/detectors/reliability/test_transaction_rollback.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.reliability.transaction_rollback import TransactionRollbackDetector


class TestTransactionRollbackDetector:
    """Tests for TransactionRollbackDetector (CAL-010)."""

    @pytest.fixture
    def detector(self):
        return TransactionRollbackDetector()

    def test_detects_batch_insert_without_rollback(self, detector):
        """Detects batch insert without exception handling."""
        code = """
import sqlite3

def batch_insert_users(users):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    for user in users:
        cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)",
                      (user["name"], user["email"]))
    conn.commit()
    conn.close()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-010"

    def test_detects_executemany_without_rollback(self, detector):
        """Detects executemany without exception handling."""
        code = """
import psycopg2

def batch_insert(data):
    conn = psycopg2.connect(dsn)
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO logs VALUES (%s, %s)", data)
    conn.commit()
    cursor.close()
    conn.close()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_with_proper_rollback(self, detector):
        """No finding when rollback is implemented."""
        code = """
import sqlite3

def batch_insert_users(users):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        for user in users:
            cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)",
                          (user["name"], user["email"]))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_context_manager(self, detector):
        """No finding when using context manager with rollback."""
        code = """
import sqlite3

def batch_insert_users(users):
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        for user in users:
            cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)",
                          (user["name"], user["email"]))
        conn.commit()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_single_insert(self, detector):
        """No finding for single inserts."""
        code = """
import sqlite3

def insert_user(user):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)",
                  (user["name"], user["email"]))
    conn.commit()
    conn.close()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0
