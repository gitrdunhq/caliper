"""Detector for event-field guards that omit a field passed to an AWS call (#499).
# tested-by: tests/unit/detectors/cloud/test_event_field_guard_gap.py
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import has_import, parse_file_safe
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@register_detector
class EventFieldGuardGapDetector(BugDetector):
    """Detects a required-field guard that omits a field later passed to an AWS call.

    Reliability issue: a Lambda handler reads several fields from the event
    with ``detail.get("...")``, validates *some* of them with
    ``if not all([...])``, then passes an unvalidated one to a boto3 method.
    A missing field then surfaces as a ``ParamValidationError`` deep inside
    the SDK instead of the clean invalid-event skip the guard was written for.

    Scope is one function at a time: the ``.get()`` assignments, the guard,
    and the call must all live in the same ``def``.

    GitHub: #499
    """

    # Module import gate: only boto3/botocore files are considered.
    AWS_IMPORT_PATTERNS = ("boto3", "boto3.*", "botocore", "botocore.*")

    @property
    def detector_id(self) -> str:
        return "CAL-026"

    @property
    def name(self) -> str:
        return "Event Field Guard Omits Field Passed To AWS Call"

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
        """Analyze file for guard gaps on event fields passed to AWS calls.

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

        if not self._imports_aws_sdk(tree):
            return []

        findings: list[DetectorFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._detect_in_function(file_path, node))

        findings.sort(key=lambda f: (f.line_number, f.message))
        return findings

    def _detect_in_function(self, file_path: Path, func: _FunctionNode) -> list[DetectorFinding]:
        """Report every ``.get()`` variable omitted from the guard and passed to a call."""
        nodes = list(self._iter_own_nodes(func))

        guard = self._find_guard(nodes)
        if guard is None:
            return []
        guard_line, guarded = guard

        collected = self._collect_get_assignments(nodes)
        unguarded = {var: line for var, line in collected.items() if var not in guarded}
        if not unguarded:
            return []

        gaps: dict[str, str] = {}
        for node in nodes:
            if not isinstance(node, ast.Call) or node.lineno <= guard_line:
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr == "get":
                continue
            method = node.func.attr
            for var in self._bare_name_arguments(node):
                if var in unguarded and var not in gaps:
                    gaps[var] = method

        findings: list[DetectorFinding] = []
        for var, method in gaps.items():
            lineno = unguarded[var]
            if not self._should_report_finding(file_path, lineno):
                continue
            findings.append(
                DetectorFinding(
                    detector_id=self.detector_id,
                    detector_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    file_path=str(file_path),
                    line_number=lineno,
                    message=(
                        f"`{var}` is read from the event but omitted from the "
                        f"required-field guard, then passed to `{method}`; a missing "
                        "field surfaces as a ParamValidationError instead of a clean "
                        "invalid-event skip"
                    ),
                    issue_reference="#499",
                    fix_hint=f"Add `{var}` to the all([...]) guard",
                )
            )
        return findings

    def _imports_aws_sdk(self, tree: ast.AST) -> bool:
        """True when the module imports boto3 or botocore (any form)."""
        return any(has_import(tree, pattern) for pattern in self.AWS_IMPORT_PATTERNS)

    @staticmethod
    def _iter_own_nodes(func: _FunctionNode) -> Iterator[ast.AST]:
        """Yield every node in ``func``'s body without descending into nested defs.

        Nested functions are analysed on their own by the caller's ``ast.walk``.
        """
        stack: list[ast.AST] = list(reversed(func.body))
        while stack:
            node = stack.pop()
            yield node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(node))))

    @staticmethod
    def _find_guard(nodes: list[ast.AST]) -> tuple[int, frozenset[str]] | None:
        """Return ``(line, names)`` for the first ``if not all([...])`` guard."""
        best: tuple[int, frozenset[str]] | None = None
        for node in nodes:
            if not isinstance(node, ast.If):
                continue
            test = node.test
            if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
                continue
            call = test.operand
            if not isinstance(call, ast.Call):
                continue
            if not isinstance(call.func, ast.Name) or call.func.id != "all":
                continue
            if len(call.args) != 1 or not isinstance(call.args[0], (ast.List, ast.Tuple)):
                continue
            elements = call.args[0].elts
            if not all(isinstance(elt, ast.Name) for elt in elements):
                continue
            names = frozenset(elt.id for elt in elements if isinstance(elt, ast.Name))
            if best is None or node.lineno < best[0]:
                best = (node.lineno, names)
        return best

    @staticmethod
    def _collect_get_assignments(nodes: list[ast.AST]) -> dict[str, int]:
        """Map ``name -> line`` for ``name = <expr>.get("literal", ...)`` assignments."""
        collected: dict[str, int] = {}
        for node in nodes:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            value = node.value
            if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
                continue
            if value.func.attr != "get" or not value.args:
                continue
            key = value.args[0]
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            collected.setdefault(target.id, node.lineno)
        return collected

    @staticmethod
    def _bare_name_arguments(call: ast.Call) -> Iterator[str]:
        """Yield every argument passed as a bare ``Name`` (positional or keyword)."""
        for arg in call.args:
            if isinstance(arg, ast.Name):
                yield arg.id
        for kw in call.keywords:
            if isinstance(kw.value, ast.Name):
                yield kw.value.id
