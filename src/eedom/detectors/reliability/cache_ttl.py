"""Detector for cache lookups without freshness checks (#201, #211).
# tested-by: tests/unit/detectors/reliability/test_cache_ttl.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.ast_utils import (
    find_function_calls,
    is_cache_related_name,
    parse_file_safe,
)
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


@register_detector
class CacheTTLDetector(BugDetector):
    """Detects cache lookups without freshness/TTL verification.

    Reliability issue: Using cached data without checking TTL can lead to
    serving stale data indefinitely when cache expiration is not properly handled.

    GitHub: #201, #211
    """

    @property
    def detector_id(self) -> str:
        return "EED-009"

    @property
    def name(self) -> str:
        return "Cache Lookup Without Freshness Check"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.low

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for cache lookups without freshness checks."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []
        checked_get_vars = set()

        # Find cache get operations with TTL checks first
        checked_get_vars = self._find_ttl_checked_vars(tree)

        # Find cache get operations
        for call, lineno in find_function_calls(tree, "*.get"):
            if self._is_cache_get(call):
                # Check if result is assigned to a variable with TTL check
                var_name = self._get_assigned_var(tree, call)
                if var_name and var_name in checked_get_vars:
                    continue

                # Check if there's a TTL check in the surrounding context
                if not self._has_ttl_check(tree, call, lineno):
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message="Cache lookup without TTL/freshness verification",
                                issue_reference="#201, #211",
                                fix_hint="Check cache TTL after retrieval or use cache with automatic expiration",
                            )
                        )

        # Check for dict-based cache patterns
        findings.extend(self._check_dict_cache_patterns(tree, file_path))

        return findings

    def _find_ttl_checked_vars(self, tree: ast.AST) -> set[str]:
        """Find variables that have TTL check after assignment."""
        checked_vars = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name and "ttl" in call_name.lower():
                    # Check if this call is on a result of a .get()
                    if isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            checked_vars.add(node.func.value.id)

        return checked_vars

    def _is_cache_get(self, call: ast.Call) -> bool:
        """Check if call is a cache get operation."""
        # Check if it's called on a cache-related object
        if isinstance(call.func, ast.Attribute):
            obj_name = self._get_object_name(call.func.value)
            if obj_name and is_cache_related_name(obj_name):
                return True
            # Also check for Redis-like patterns (r.get, redis.get, etc.)
            if isinstance(call.func.value, ast.Name):
                # Common cache client variable names
                cache_vars = ("r", "redis", "cache", "client", "conn", "connection")
                if call.func.value.id in cache_vars:
                    return True
        return False

    def _get_assigned_var(self, tree: ast.AST, call: ast.Call) -> str | None:
        """Get the variable name a call result is assigned to."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if call in ast.walk(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            return target.id
        return None

    def _get_object_name(self, node: ast.AST) -> str | None:
        """Extract object name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _has_ttl_check(self, tree: ast.AST, call: ast.Call, lineno: int) -> bool:
        """Check if there's a TTL check near the cache lookup."""
        # Look for TTL-related calls (ttl, exists, etc.) in the same function
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name and "ttl" in call_name.lower():
                    node_lineno = getattr(node, "lineno", 0)
                    # Check if it's within a few lines of the cache get
                    if abs(node_lineno - lineno) <= 5:
                        return True
        return False

    def _get_call_name(self, node: ast.Call) -> str | None:
        """Extract full call name."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def _check_dict_cache_patterns(self, tree: ast.AST, file_path: Path) -> list[DetectorFinding]:
        """Check for dict-based cache patterns without freshness checks."""
        findings = []

        # Look for patterns like: if key in cache: return cache[key]
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue

            # Check if condition is 'key in cache' or 'key in _cache'
            if isinstance(node.test, ast.Compare):
                if self._is_in_cache_check(node.test):
                    # Check if the body has freshness validation
                    if not self._has_freshness_validation(node):
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
                                    message="Dictionary cache lookup without freshness/TTL check",
                                    issue_reference="#201, #211",
                                    fix_hint="Store timestamp with cached values and check age before using",
                                )
                            )

        return findings

    def _is_in_cache_check(self, node: ast.Compare) -> bool:
        """Check if comparison is 'key in cache' pattern."""
        if isinstance(node.ops[0], ast.In):
            if isinstance(node.comparators[0], ast.Name):
                return is_cache_related_name(node.comparators[0].id)
        return False

    def _has_freshness_validation(self, node: ast.If) -> bool:
        """Check if the if block has freshness/TTL validation."""
        # Look for time-related or age checks in the body
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in ("time", "timestamp", "ttl", "age", "expires"):
                    return True
        return False
