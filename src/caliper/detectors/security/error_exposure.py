"""Detector for exception handlers exposing error details (#179, #213).
# tested-by: tests/unit/detectors/security/test_error_exposure.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import (
    find_exception_handlers,
    parse_file_safe,
)
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class ErrorExposureDetector(BugDetector):
    """Detects exception handlers that expose exception variables in output.

    Security issue: Exposing exception details (e.g., in f-strings, % formatting,
    or .format()) can leak sensitive information to attackers.

    GitHub: #179, #213
    """

    @property
    def detector_id(self) -> str:
        return "CAL-002"

    @property
    def name(self) -> str:
        return "Error Information Exposure"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for exception handlers exposing error details."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find all exception handlers
        for handler in find_exception_handlers(tree):
            if not handler.name:
                continue  # No exception variable bound

            exc_var = handler.name

            # Check if exc_var is used in a string formatting context
            if self._is_exposed_in_output(handler, exc_var):
                if self._should_report_finding(file_path, handler.lineno):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=handler.lineno,
                            message=f"Exception variable '{exc_var}' may be exposed in output (f-string, %, or .format)",
                            issue_reference="#179, #213",
                            fix_hint="Log exception details internally, return generic error message to user",
                        )
                    )

        return findings

    def _is_exposed_in_output(self, handler: ast.ExceptHandler, var_name: str) -> bool:
        """Check if exception variable is used in string formatting contexts.

        Args:
            handler: Exception handler node
            var_name: Name of the exception variable

        Returns:
            True if variable is used in output-exposing contexts
        """
        for node in ast.walk(handler):
            # Check f-string usage
            if isinstance(node, ast.JoinedStr):
                if self._has_variable_in_fstring(node, var_name):
                    return True

            # Check % formatting: "..." % var
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if self._has_variable(node.right, var_name):
                    return True

            # Check .format() usage: "...".format(var)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                    for arg in node.args:
                        if self._has_variable(arg, var_name):
                            return True
                    for kw in node.keywords:
                        if self._has_variable(kw.value, var_name):
                            return True

        return False

    def _has_variable_in_fstring(self, node: ast.JoinedStr, var_name: str) -> bool:
        """Check if variable appears in an f-string."""
        for child in ast.walk(node):
            if isinstance(child, ast.FormattedValue):
                if self._has_variable(child.value, var_name):
                    return True
            if isinstance(child, ast.Name) and child.id == var_name:
                # Check if it's in a FormattedValue context
                for parent in ast.walk(node):
                    if isinstance(parent, ast.FormattedValue):
                        if child in ast.walk(parent):
                            return True
        return False

    def _has_variable(self, node: ast.AST, var_name: str) -> bool:
        """Check if node contains reference to variable."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id == var_name:
                return True
        return False
