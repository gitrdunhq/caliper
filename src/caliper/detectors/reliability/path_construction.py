"""Detector for path string concatenation (#208, #235).
# tested-by: tests/unit/detectors/reliability/test_path_construction.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import (
    is_path_related_name,
    parse_file_safe,
)
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class PathConstructionDetector(BugDetector):
    """Detects path construction using string concatenation.

    Reliability issue: Building paths with string concatenation is error-prone
    and can lead to security issues (path traversal) and cross-platform bugs.
    Use pathlib.Path or os.path.join instead.

    GitHub: #208, #235
    """

    @property
    def detector_id(self) -> str:
        return "CAL-008"

    @property
    def name(self) -> str:
        return "Path String Concatenation"

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
        """Analyze file for path string concatenation patterns."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Walk AST to find dangerous path constructions
        for node in ast.walk(tree):
            # Check for + operator used with path-related strings
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                if self._is_path_concatenation(node):
                    lineno = getattr(node, "lineno", 1)
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message="Path constructed using string concatenation (+)",
                                issue_reference="#208, #235",
                                fix_hint="Use pathlib.Path('/base') / filename or os.path.join('/base', filename)",
                            )
                        )

            # Check for f-strings used with paths
            if isinstance(node, ast.JoinedStr):
                if self._is_path_fstring(node):
                    lineno = getattr(node, "lineno", 1)
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message="Path constructed using f-string formatting",
                                issue_reference="#208, #235",
                                fix_hint="Use pathlib.Path('/base') / filename or os.path.join('/base', filename)",
                            )
                        )

            # Check for % formatting with paths
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if self._is_path_percent_formatting(node):
                    lineno = getattr(node, "lineno", 1)
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message="Path constructed using % string formatting",
                                issue_reference="#208, #235",
                                fix_hint="Use pathlib.Path('/base') / filename or os.path.join('/base', filename)",
                            )
                        )

        return findings

    def _is_path_concatenation(self, node: ast.BinOp) -> bool:
        """Check if BinOp is a path-related string concatenation."""
        # Check if either side contains path-related strings
        left_str = self._get_string_content(node.left)
        right_str = self._get_string_content(node.right)

        if left_str and is_path_related_name(left_str):
            return True
        if right_str and is_path_related_name(right_str):
            return True

        # Check for path-like patterns in the strings
        return bool(
            (left_str and ("/" in left_str or "\\" in left_str or "." in left_str))
            or (right_str and ("/" in right_str or "\\" in right_str or "." in right_str))
        )

    def _is_path_fstring(self, node: ast.JoinedStr) -> bool:
        """Check if f-string is path-related."""
        # Get the format string content
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                content = value.value
                if "/" in content or "\\" in content or is_path_related_name(content):
                    return True
        return False

    def _is_path_percent_formatting(self, node: ast.BinOp) -> bool:
        """Check if % formatting is path-related."""
        left_str = self._get_string_content(node.left)
        if left_str:
            if "/" in left_str or "\\" in left_str or is_path_related_name(left_str):
                return True
        return False

    def _get_string_content(self, node: ast.AST) -> str | None:
        """Extract string content from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
