"""Detector for SQL injection via string formatting (#176).
# tested-by: tests/unit/detectors/security/test_sql_injection.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.ast_utils import (
    find_function_calls,
    parse_file_safe,
)
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


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
        return "EED-005"

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

        # Check for f-string (JoinedStr)
        if isinstance(query_arg, ast.JoinedStr):
            return True

        # Check for % formatting
        if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
            return True

        # Check for .format() call
        if isinstance(query_arg, ast.Call):
            if isinstance(query_arg.func, ast.Attribute):
                if query_arg.func.attr == "format":
                    return True

        return False
