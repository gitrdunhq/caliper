"""CacheEvictionDetector - Detects unbounded caches without eviction policy.
# tested-by: tests/unit/detectors/test_deterministic_eviction_guards.py

GitHub issues: #166, #167
"""

from __future__ import annotations

import ast
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


@register_detector
class CacheEvictionDetector(BugDetector):
    """Detects @cache or @lru_cache without maxsize/TTL.

    Reliability issue: Unbounded caches can grow indefinitely,
    causing memory exhaustion (OOM) in long-running processes.

    GitHub: #166, #167
    """

    @property
    def detector_id(self) -> str:
        return "EED-006"

    @property
    def name(self) -> str:
        return "Unbounded Cache Without Eviction"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for unbounded cache decorators."""
        content = file_path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                self._has_unbounded_cache(node)
            ):
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        message=f"@{node.name} uses cache without maxsize/TTL limit",
                        snippet=self._get_decorator_line(content, node),
                        issue_reference="#166, #167",
                        fix_hint="Add maxsize= to @lru_cache or use TTL cache",
                    )
                )

        return findings

    def _has_unbounded_cache(self, node: ast.FunctionDef) -> bool:
        """Check if function has unbounded cache decorator.

        Unbounded forms:
        - @cache (functools.cache with no args)
        - @lru_cache() with no maxsize
        """
        for decorator in node.decorator_list:
            # Check for bare @cache
            if isinstance(decorator, ast.Name) and decorator.id == "cache":
                return True

            # Check for @lru_cache() without maxsize
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "lru_cache"
            ):
                # Unbounded unless an explicit, non-None maxsize is given.
                # maxsize=None means UNBOUNDED — it was wrongly treated as bounded.
                has_explicit_bound = any(
                    kw.arg == "maxsize"
                    and not (isinstance(kw.value, ast.Constant) and kw.value.value is None)
                    for kw in decorator.keywords
                )
                return not has_explicit_bound

        return False

    def _get_decorator_line(self, content: str, node: ast.FunctionDef) -> str | None:
        """Get the decorator line for context."""
        lines = content.split("\n")
        if node.decorator_list:
            dec_lineno = node.decorator_list[0].lineno
            if 1 <= dec_lineno <= len(lines):
                return lines[dec_lineno - 1].strip()
        return None
