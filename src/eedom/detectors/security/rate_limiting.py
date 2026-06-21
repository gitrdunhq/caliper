"""Detector for API endpoints without rate limiting (#183).
# tested-by: tests/unit/detectors/security/test_rate_limiting.py
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
class RateLimitingDetector(BugDetector):
    """Detects API endpoints without rate limiting decorators.

    Security issue: API endpoints without rate limiting are vulnerable to
    DoS attacks and brute force attempts.

    GitHub: #183
    """

    # Decorator patterns that indicate rate limiting
    RATE_LIMIT_PATTERNS = ("*limit*", "*throttle*", "*rate*")

    # Decorator patterns that indicate API endpoints
    API_ENDPOINT_PATTERNS = ("route", "get", "post", "put", "delete", "patch")

    @property
    def detector_id(self) -> str:
        return "EED-003"

    @property
    def name(self) -> str:
        return "API Endpoint Missing Rate Limiting"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for API endpoints without rate limiting."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find all function definitions
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Check if it's an API endpoint (has route decorator)
            if not self._is_api_endpoint(node):
                continue

            # Check if it has rate limiting
            if not self._has_rate_limiting(node):
                # Find the line number of the first decorator
                lineno = node.lineno
                if node.decorator_list:
                    lineno = node.decorator_list[0].lineno

                if self._should_report_finding(file_path, lineno):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=lineno,
                            message=f"API endpoint '{node.name}' missing rate limiting decorator",
                            issue_reference="#183",
                            fix_hint="Add @limiter.limit() or @throttle decorator",
                        )
                    )

        return findings

    def _is_api_endpoint(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if function is an API endpoint based on decorators."""
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name:
                dec_name_lower = dec_name.lower()
                for pattern in self.API_ENDPOINT_PATTERNS:
                    if pattern in dec_name_lower:
                        return True
        return False

    def _has_rate_limiting(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if function has rate limiting decorators."""
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name:
                for pattern in self.RATE_LIMIT_PATTERNS:
                    if self._matches_pattern(dec_name, pattern):
                        return True
        return False

    def _get_decorator_name(self, decorator: ast.expr) -> str | None:
        """Extract name from decorator node."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            node = decorator
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
                return ".".join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return None

    def _matches_pattern(self, name: str, pattern: str) -> bool:
        """Simple glob matching for patterns with *."""
        if pattern.startswith("*") and pattern.endswith("*"):
            return pattern[1:-1] in name
        elif pattern.startswith("*"):
            return name.endswith(pattern[1:])
        elif pattern.endswith("*"):
            return name.startswith(pattern[:-1])
        return name == pattern
