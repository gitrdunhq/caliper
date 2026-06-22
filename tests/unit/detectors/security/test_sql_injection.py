"""Tests for SQL Injection detector.
# tested-by: tests/unit/detectors/security/test_sql_injection.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.security.sql_injection import SQLInjectionDetector


class TestSQLInjectionDetector:
    """Tests for SQLInjectionDetector (CAL-005)."""

    @pytest.fixture
    def detector(self):
        return SQLInjectionDetector()

    def test_detects_fstring_in_execute(self, detector):
        """Detects f-string in SQL execute."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
user_id = "123"
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-005"
        assert "f-string" in findings[0].message

    def test_detects_percent_formatting_in_execute(self, detector):
        """Detects % formatting in SQL execute."""
        code = """
import psycopg2

conn = psycopg2.connect(dsn)
cursor = conn.cursor()
user_id = "123"
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert "string formatting" in findings[0].message

    def test_detects_dot_format_in_execute(self, detector):
        """Detects .format() in SQL execute."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
table_name = "users"
cursor.execute("SELECT * FROM {}".format(table_name))
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_parameterized_query(self, detector):
        """No finding for parameterized queries."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_string_literal(self, detector):
        """No finding for string literal queries."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE active = 1")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_executemany_violation(self, detector):
        """Detects formatting in executemany."""
        code = """
import sqlite3

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
table = "logs"
cursor.executemany(f"INSERT INTO {table} VALUES (?, ?)", data)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Regression P12-7 — constant f-string must NOT be flagged
# Regression P12-8 — .format() with no args must NOT be flagged
# ---------------------------------------------------------------------------


class TestSQLInjectionFalsePositiveRegression:
    """Regression tests ensuring P12-7 and P12-8 false positives are gone.

    Before the fix, _has_dangerous_formatting flagged:
      P12-7: f-strings with no FormattedValue (constant f-strings like f"SELECT 1")
      P12-8: .format() calls with no arguments (e.g. "SELECT 1".format())
    """

    @pytest.fixture
    def detector(self):
        return SQLInjectionDetector()

    def test_constant_fstring_no_interpolation_not_flagged(self, detector):
        """A constant f-string with no FormattedValue elements must NOT be flagged
        (regression for P12-7: f'SELECT * FROM t' is identical to a plain string literal)."""
        code = """
import sqlite3
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute(f"SELECT * FROM users WHERE active = 1")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 0, (
            f"Constant f-string with no interpolation must not be flagged as SQL injection, "
            f"got findings: {findings!r}"
        )

    def test_format_with_no_args_not_flagged(self, detector):
        """A .format() call with no args is a no-op and must NOT be flagged
        (regression for P12-8: '...'.format() produces a constant string)."""
        code = """
import sqlite3
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE active = 1".format())
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 0, (
            f".format() with no args must not be flagged as SQL injection, "
            f"got findings: {findings!r}"
        )

    def test_fstring_with_interpolation_still_flagged(self, detector):
        """Sanity: an f-string WITH a FormattedValue must still be flagged."""
        code = """
import sqlite3
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
uid = "1 OR 1=1"
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert (
            len(findings) == 1
        ), "An f-string with interpolation must still be flagged as SQL injection"

    def test_format_with_args_still_flagged(self, detector):
        """Sanity: .format(arg) must still be flagged."""
        code = """
import sqlite3
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
table = "users"
cursor.execute("SELECT * FROM {}".format(table))
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 1, ".format(arg) must still be flagged as SQL injection"
