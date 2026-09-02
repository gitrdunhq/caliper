"""Detector for Lambda handlers that swallow exceptions (#499).
# tested-by: tests/unit/detectors/cloud/test_lambda_swallowed_exception.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class LambdaSwallowedExceptionDetector(BugDetector):
    """Detects Lambda handlers whose broad ``except`` returns instead of raising.

    Reliability issue: when a handler catches ``Exception``/``BaseException``
    (or uses a bare ``except:``) and returns, the Lambda service records the
    invocation as a success. Async retries, on-failure destinations, DLQs and
    the ``Errors`` metric never fire, so the failure is invisible.

    GitHub: #499
    """

    HANDLER_NAMES = frozenset({"lambda_handler", "handler"})
    HANDLER_SIGNATURE = ("event", "context")
    BROAD_EXCEPTION_NAMES = frozenset({"Exception", "BaseException"})

    @property
    def detector_id(self) -> str:
        return "CAL-023"

    @property
    def name(self) -> str:
        return "Lambda Handler Swallows Exceptions"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for Lambda handlers that swallow exceptions."""
        tree = self._parse_safe(file_path)
        if tree is None:
            return []

        findings: list[DetectorFinding] = []
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._is_lambda_handler(node):
                continue
            for handler in self._swallowing_handlers(node):
                if not self._should_report_finding(file_path, handler.lineno):
                    continue
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=handler.lineno,
                        message=(
                            f"Lambda handler '{node.name}' catches a broad exception and "
                            "returns without re-raising - the invocation is reported as a "
                            "success, so async retries, destinations and the Errors metric "
                            "never fire"
                        ),
                        issue_reference="#499",
                        fix_hint=(
                            "Log and re-raise, or return only after emitting a failure "
                            "signal (metric/DLQ)"
                        ),
                    )
                )
        return findings

    @staticmethod
    def _parse_safe(file_path: Path) -> ast.Module | None:
        """Parse the file, failing open on any read/decode/syntax problem."""
        try:
            return ast.parse(file_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - fail-open: never block a build
            return None

    def _is_lambda_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """A top-level def named like a handler, or with an (event, context) signature."""
        if node.name in self.HANDLER_NAMES:
            return True
        positional = [*node.args.posonlyargs, *node.args.args]
        first_two = tuple(arg.arg for arg in positional[:2])
        return first_two == self.HANDLER_SIGNATURE

    def _swallowing_handlers(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[ast.ExceptHandler]:
        """Broad except clauses anywhere in the function whose body returns but never raises."""
        offending: list[ast.ExceptHandler] = []
        for node in ast.walk(func):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not self._is_broad_except(node):
                continue
            body_nodes = [child for stmt in node.body for child in ast.walk(stmt)]
            if any(isinstance(child, ast.Raise) for child in body_nodes):
                continue
            if any(isinstance(child, ast.Return) for child in body_nodes):
                offending.append(node)
        return offending

    def _is_broad_except(self, handler: ast.ExceptHandler) -> bool:
        """Bare ``except:`` or ``except Exception``/``BaseException`` (also in a tuple)."""
        if handler.type is None:
            return True
        types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        return any(self._exception_name(t) in self.BROAD_EXCEPTION_NAMES for t in types)

    @staticmethod
    def _exception_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None
