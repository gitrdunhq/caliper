"""Detector for circuit breakers without half-open state (#174).
# tested-by: tests/unit/detectors/reliability/test_circuit_breaker.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.ast_utils import (
    find_classes,
    find_function_calls,
    parse_file_safe,
)
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


@register_detector
class CircuitBreakerDetector(BugDetector):
    """Detects circuit breakers without half-open state handling.

    Reliability issue: Circuit breakers without a half-open state can
    remain open indefinitely even when the service has recovered.

    GitHub: #174
    """

    @property
    def detector_id(self) -> str:
        return "EED-007"

    @property
    def name(self) -> str:
        return "Circuit Breaker Missing Half-Open State"

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
        """Analyze file for circuit breakers without half-open state."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []
        breaker_vars_with_half_open = set()

        # First pass: find breaker variables that have half-open config
        breaker_vars_with_half_open = self._find_half_open_configs(tree)

        # Check for pybreaker usage
        findings.extend(self._check_pybreaker_usage(tree, file_path, breaker_vars_with_half_open))

        # Check for custom circuit breaker implementations
        findings.extend(self._check_custom_breakers(tree, file_path))

        return findings

    def _find_half_open_configs(self, tree: ast.AST) -> set[str]:
        """Find breaker variables that have half_open_* attribute assigned."""
        half_open_vars = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        if "half" in target.attr.lower():
                            if isinstance(target.value, ast.Name):
                                half_open_vars.add(target.value.id)

        return half_open_vars

    def _check_pybreaker_usage(
        self, tree: ast.AST, file_path: Path, breaker_vars_with_half_open: set[str]
    ) -> list[DetectorFinding]:
        """Check for pybreaker CircuitBreaker usage without half-open config."""
        findings = []

        # Find CircuitBreaker instantiations
        for call, lineno in find_function_calls(tree, "CircuitBreaker"):
            # Get the variable name this breaker is assigned to
            breaker_var = self._get_breaker_variable_name(tree, call)

            # Skip if this breaker has half-open config via attribute assignment
            if breaker_var and breaker_var in breaker_vars_with_half_open:
                continue

            # Check if half_open_max_calls or similar is configured in constructor
            if not self._has_half_open_config(call):
                if self._should_report_finding(file_path, lineno):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=lineno,
                            message="CircuitBreaker configured without half-open state handling",
                            issue_reference="#174",
                            fix_hint="Add half_open_max_calls or half_open_timeout configuration",
                        )
                    )

        return findings

    def _get_breaker_variable_name(self, tree: ast.AST, call: ast.Call) -> str | None:
        """Get the variable name a CircuitBreaker is assigned to."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if call in ast.walk(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            return target.id
        return None

    def _check_custom_breakers(self, tree: ast.AST, file_path: Path) -> list[DetectorFinding]:
        """Check for custom circuit breaker classes without half-open state."""
        findings = []

        for cls in find_classes(tree, "*Breaker*"):
            # Check if class has half-open related code
            if not self._has_half_open_state(cls):
                if self._should_report_finding(file_path, cls.lineno):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=cls.lineno,
                            message=f"Custom circuit breaker '{cls.name}' missing half-open state",
                            issue_reference="#174",
                            fix_hint="Add 'half_open' state and transition logic between open/closed",
                        )
                    )

        return findings

    def _has_half_open_config(self, call: ast.Call) -> bool:
        """Check if CircuitBreaker call has half-open configuration."""
        for keyword in call.keywords:
            if "half" in keyword.arg.lower():
                return True
        return False

    def _has_half_open_state(self, cls: ast.ClassDef) -> bool:
        """Check if circuit breaker class has half-open state handling."""
        for node in ast.walk(cls):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "half" in node.value.lower() or "half_open" in node.value.lower():
                    return True
            if isinstance(node, ast.Name):
                if "half" in node.id.lower():
                    return True
        return False
