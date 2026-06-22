"""Detector for batch inserts without rollback handling (#216).
# tested-by: tests/unit/detectors/reliability/test_transaction_rollback.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.ast_utils import (
    parse_file_safe,
)
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


@register_detector
class TransactionRollbackDetector(BugDetector):
    """Detects batch database operations without rollback handling.

    Reliability issue: Batch inserts without proper exception handling and
    rollback can leave the database in an inconsistent state when errors occur.

    GitHub: #216
    """

    # SQL patterns that indicate batch operations
    BATCH_PATTERNS = ("executemany", "*executemany*")

    # Patterns indicating single-row operations
    SINGLE_ROW_PATTERNS = ("INSERT", "UPDATE", "DELETE")

    @property
    def detector_id(self) -> str:
        return "EED-010"

    @property
    def name(self) -> str:
        return "Batch Insert Without Rollback Handling"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for batch operations without rollback handling."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find all function definitions
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Check for batch operations
            batch_ops = self._find_batch_operations(node)

            for batch_op, lineno in batch_ops:
                # Check if operation is wrapped in try/except with rollback
                if not self._has_rollback_protection(node, batch_op):
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message="Batch database operation without transaction rollback handling",
                                issue_reference="#216",
                                fix_hint="Wrap batch operations in try/except with conn.rollback() on failure",
                            )
                        )

        return findings

    def _find_batch_operations(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[tuple[ast.Call, int]]:
        """Find batch database operations in function."""
        results = []

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    # Check for executemany
                    if "executemany" in call_name.lower():
                        results.append((child, getattr(child, "lineno", 1)))

                    # Check for looped inserts
                    if self._is_looped_insert(child, node):
                        results.append((child, getattr(child, "lineno", 1)))

        return results

    def _get_call_name(self, call: ast.Call) -> str | None:
        """Extract full call name."""
        if isinstance(call.func, ast.Attribute):
            if isinstance(call.func.value, ast.Name):
                return f"{call.func.value.id}.{call.func.attr}"
            return call.func.attr
        elif isinstance(call.func, ast.Name):
            return call.func.id
        return None

    def _is_looped_insert(
        self, call: ast.Call, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        """Check if call is an execute inside a loop (potential batch)."""
        # Look for patterns like: for x in y: cursor.execute(...)
        for parent in ast.walk(func):
            if isinstance(parent, (ast.For, ast.While)):
                for child in ast.walk(parent):
                    if child is call:
                        # Check if it's an execute call
                        call_name = self._get_call_name(call)
                        if call_name and "execute" in call_name.lower():
                            return True
        return False

    def _has_rollback_protection(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call
    ) -> bool:
        """Check if operation is protected by try/except with rollback or context manager."""
        # Walk up the AST to find enclosing try block or context manager
        for parent in ast.walk(func):
            # Check for try/except with rollback
            if isinstance(parent, ast.Try):
                # Check if our call is inside this try
                for child in ast.walk(parent):
                    if child is call:
                        # Check if try has rollback in handlers
                        if self._has_rollback_handler(parent):
                            return True

            # Check for context manager (with statement)
            if isinstance(parent, ast.With):
                # Check if our call is inside this with block
                for child in ast.walk(parent):
                    if child is call:
                        # Context managers typically handle rollback automatically
                        return True

        return False

    def _has_rollback_handler(self, try_node: ast.Try) -> bool:
        """Check if try block has rollback in exception handlers."""
        for handler in try_node.handlers:
            for child in ast.walk(handler):
                if isinstance(child, ast.Call):
                    call_name = self._get_call_name(child)
                    if call_name and "rollback" in call_name.lower():
                        return True
                # Check for conn.rollback or similar attribute access
                if isinstance(child, ast.Attribute):
                    if "rollback" in child.attr.lower():
                        return True
        return False
