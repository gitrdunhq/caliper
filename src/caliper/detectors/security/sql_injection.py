"""Detector for SQL injection via string formatting (#176).
# tested-by: tests/unit/detectors/security/test_sql_injection.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import (
    find_function_calls,
    parse_file_safe,
)
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class SQLInjectionDetector(BugDetector):
    """Detects SQL execute() calls with f-strings, % formatting, or .format().

    Security issue: SQL queries built with string formatting are vulnerable to
    SQL injection attacks. Use parameterized queries instead.

    GitHub: #176
    """

    # SQL execution methods to check
    SQL_EXECUTE_PATTERNS = (
        "*.execute",
        "*.executemany",
        "*.executescript",
    )

    @property
    def detector_id(self) -> str:
        return "CAL-005"

    @property
    def name(self) -> str:
        return "SQL Injection via String Formatting"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.critical

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for SQL execute calls with dangerous formatting."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []
        seen_lines = set()

        # Find all SQL execute calls
        for pattern in self.SQL_EXECUTE_PATTERNS:
            for call, lineno in find_function_calls(tree, pattern):
                # Deduplicate by line number
                if lineno in seen_lines:
                    continue
                seen_lines.add(lineno)

                if self._has_dangerous_formatting(call):
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message="SQL query uses string formatting (f-string, %, or .format) - vulnerable to SQL injection",
                                issue_reference="#176",
                                fix_hint="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (value,))",
                            )
                        )

        return findings

    def _has_dangerous_formatting(self, call: ast.Call) -> bool:
        """Check if SQL call uses dangerous string formatting.

        Args:
            call: AST Call node for execute/many/script

        Returns:
            True if first argument uses f-string, %, or .format
        """
        if not call.args:
            return False

        query_arg = call.args[0]

        # Check for f-string (JoinedStr) WITH interpolation. A constant f-string
        # (no FormattedValue, e.g. f"SELECT * FROM t") is just a literal — not dangerous.
        if isinstance(query_arg, ast.JoinedStr):
            if any(isinstance(v, ast.FormattedValue) for v in query_arg.values):
                return True

        # Check for % formatting
        if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
            return True

        # Check for .format() call WITH arguments. "...".format() with no args is a
        # no-op and produces a constant string — not an injection vector.
        if isinstance(query_arg, ast.Call):
            if isinstance(query_arg.func, ast.Attribute):
                if query_arg.func.attr == "format" and (query_arg.args or query_arg.keywords):
                    return True

        return False
