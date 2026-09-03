"""Detector for delete/rollback paths that swallow their own failure (#499).
# tested-by: tests/unit/detectors/cloud/test_delete_path_swallows_failure.py
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import parse_file_safe
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@register_detector
class DeletePathSwallowsFailureDetector(BugDetector):
    """Detects delete/rollback functions whose broad ``except`` swallows the failure.

    Reliability issue: a cleanup, rollback, or teardown function that catches
    ``Exception`` (or bare) and then only logs, passes, or returns a benign
    value reports success to its caller. The resource is left behind and
    nothing downstream ever learns the delete did not happen.

    GitHub: #499
    """

    NAME_PREFIX = re.compile(
        r"^(delete|remove|destroy|rollback|revoke|cleanup|clean_up"
        r"|teardown|tear_down|purge|deprovision)",
        re.IGNORECASE,
    )
    NAME_INFIXES = ("_delete_", "_rollback_")
    BROAD_EXCEPTION_NAMES = frozenset({"Exception", "BaseException"})
    LOGGING_ATTRS = frozenset(
        {"debug", "info", "warning", "warn", "error", "exception", "log", "print"}
    )
    SIGNAL_TOKENS = ("fail", "abort", "mark_failed")

    @property
    def detector_id(self) -> str:
        return "CAL-029"

    @property
    def name(self) -> str:
        return "Delete Or Rollback Path Swallows Failure"

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
        """Analyze file for delete/rollback paths that swallow failures.

        Fail-open: any parse, decode, or IO failure yields no findings.
        """
        try:
            return self._detect(file_path)
        except Exception:  # noqa: BLE001 - fail-open by design
            return []

    def _detect(self, file_path: Path) -> list[DetectorFinding]:
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings: list[DetectorFinding] = []
        for node in ast.walk(tree):
            if not isinstance(node, _FunctionNode):
                continue
            if not self._is_delete_path_name(node.name):
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
                            f"`{node.name}` swallows a failure on its delete/rollback "
                            "path and reports success; the resource is left behind "
                            "and the caller never learns"
                        ),
                        issue_reference="#499",
                        fix_hint="Re-raise, or return a failure result the caller checks",
                    )
                )

        findings.sort(key=lambda f: f.line_number)
        return findings

    def _is_delete_path_name(self, name: str) -> bool:
        """True for delete/rollback-style names (prefix set or `_delete_`/`_rollback_` infix)."""
        if self.NAME_PREFIX.match(name):
            return True
        lowered = name.lower()
        return any(infix in lowered for infix in self.NAME_INFIXES)

    def _swallowing_handlers(self, func: _FunctionNode) -> list[ast.ExceptHandler]:
        """Broad except clauses in the function's own body that swallow the failure."""
        offending: list[ast.ExceptHandler] = []
        for node in self._own_body_nodes(func):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not self._is_broad_except(node):
                continue
            body_nodes = [child for stmt in node.body for child in ast.walk(stmt)]
            if any(isinstance(child, ast.Raise) for child in body_nodes):
                continue
            if any(self._is_signal_call(child) for child in body_nodes):
                continue
            if all(self._is_swallow_stmt(stmt) for stmt in node.body):
                offending.append(node)
        return offending

    @classmethod
    def _own_body_nodes(cls, func: _FunctionNode) -> Iterator[ast.AST]:
        """Yield every node in the function's own body, not descending into nested defs."""
        stack: list[ast.AST] = list(ast.iter_child_nodes(func))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            yield node
            stack.extend(ast.iter_child_nodes(node))

    def _is_broad_except(self, handler: ast.ExceptHandler) -> bool:
        """Bare ``except:`` or ``except Exception``/``BaseException`` (also in a tuple)."""
        if handler.type is None:
            return True
        types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        return any(self._callee_name(t) in self.BROAD_EXCEPTION_NAMES for t in types)

    def _is_signal_call(self, node: ast.AST) -> bool:
        """A call whose callee name mentions failing/aborting signals the failure."""
        if not isinstance(node, ast.Call):
            return False
        callee = self._callee_name(node.func)
        if callee is None:
            return False
        lowered = callee.lower()
        return any(token in lowered for token in self.SIGNAL_TOKENS)

    def _is_swallow_stmt(self, stmt: ast.stmt) -> bool:
        """``pass``, a logging call, or a return of None/True/a dict display."""
        if isinstance(stmt, ast.Pass):
            return True
        if isinstance(stmt, ast.Expr):
            return self._is_logging_call(stmt.value)
        if isinstance(stmt, ast.Return):
            return self._is_benign_return_value(stmt.value)
        return False

    def _is_logging_call(self, expr: ast.expr) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        if isinstance(expr.func, ast.Attribute):
            return expr.func.attr in self.LOGGING_ATTRS
        return isinstance(expr.func, ast.Name) and expr.func.id == "print"

    @staticmethod
    def _is_benign_return_value(value: ast.expr | None) -> bool:
        if value is None:
            return True
        if isinstance(value, ast.Dict):
            return True
        return isinstance(value, ast.Constant) and (value.value is None or value.value is True)

    @staticmethod
    def _callee_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None
