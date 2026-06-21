"""Detector for subprocess calls without timeout (#260).
# tested-by: tests/unit/detectors/reliability/test_subprocess_timeout.py
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
class SubprocessTimeoutDetector(BugDetector):
    """Detects subprocess calls without timeout parameter.

    Reliability issue: Subprocess calls without timeout can hang indefinitely
    if the subprocess doesn't complete, causing resource exhaustion.

    GitHub: #260
    """

    # Subprocess functions that should have timeout
    SUBPROCESS_CALLS = (
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    )

    @property
    def detector_id(self) -> str:
        return "EED-012"

    @property
    def name(self) -> str:
        return "Subprocess Call Without Timeout"

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
        """Analyze file for subprocess calls without timeout."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find all subprocess calls
        for call, lineno in find_function_calls(tree, "subprocess.*"):
            call_name = self._get_call_name(call)

            # Check if it's a call that should have timeout
            if not self._needs_timeout(call_name):
                continue

            # Check if timeout is already specified
            if self._has_timeout(call):
                continue

            # For Popen, check if communicate has timeout
            if call_name == "subprocess.Popen":
                if self._popen_has_communicate_timeout(tree, call):
                    continue

            if self._should_report_finding(file_path, lineno):
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=lineno,
                        message=f"{call_name} called without timeout - may hang indefinitely",
                        issue_reference="#260",
                        fix_hint="Add timeout=30 parameter to prevent indefinite hanging",
                    )
                )

        return findings

    def _get_call_name(self, call: ast.Call) -> str | None:
        """Extract full call name."""
        if isinstance(call.func, ast.Attribute):
            if isinstance(call.func.value, ast.Name):
                if call.func.value.id == "subprocess":
                    return f"subprocess.{call.func.attr}"
                return f"{call.func.value.id}.{call.func.attr}"
            return call.func.attr
        elif isinstance(call.func, ast.Name):
            return call.func.id
        return None

    def _needs_timeout(self, call_name: str | None) -> bool:
        """Check if call type should have timeout."""
        if not call_name:
            return False

        call_lower = call_name.lower()
        for pattern in ("run", "call", "check_call", "check_output", "popen"):
            if pattern in call_lower:
                return True
        return False

    def _has_timeout(self, call: ast.Call) -> bool:
        """Check if call already has timeout parameter."""
        for keyword in call.keywords:
            if keyword.arg == "timeout":
                return True
        return False

    def _popen_has_communicate_timeout(self, tree: ast.AST, popen_call: ast.Call) -> bool:
        """Check if Popen call is followed by communicate with timeout."""
        # This is a simplified check - we look for communicate calls
        # with timeout in the same scope as the Popen call
        for call, _ in find_function_calls(tree, "*.communicate"):
            if self._has_timeout(call):
                return True
        return False
