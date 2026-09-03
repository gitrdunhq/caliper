"""Detector for numeric settings passed to a call with no range guard (#499).
# tested-by: tests/unit/detectors/cloud/test_unguarded_numeric_setting.py
"""

from __future__ import annotations

import ast
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
class UnguardedNumericSettingDetector(BugDetector):
    """Detects a numeric setting that reaches a call without any range check.

    Reliability issue: ``timeout = int(os.environ.get("T", "30"))`` followed
    by ``client.fetch(timeout=timeout)`` lets a zero, negative, NaN or huge
    value flow straight into the callee. The conventional guard is a compare
    (``if timeout <= 0``), a ``math.isfinite`` check, or a ``max``/``min``
    clamp on the name somewhere in the same function.

    Scope is one function at a time (own body, nested defs excluded).

    GitHub: #499
    """

    # Case-insensitive substrings that mark a name as a numeric setting.
    SETTING_TOKENS = (
        "timeout",
        "limit",
        "max_",
        "min_",
        "size",
        "retries",
        "attempts",
        "interval",
        "ttl",
        "delay",
        "batch",
        "workers",
        "concurrency",
        "port",
    )

    # Bare-name calls whose result is treated as a numeric setting.
    NUMERIC_CASTS = frozenset({"int", "float"})

    # Bare-name calls that clamp a value into range.
    CLAMP_FUNCTIONS = frozenset({"max", "min"})

    @property
    def detector_id(self) -> str:
        return "CAL-030"

    @property
    def name(self) -> str:
        return "Numeric Setting Used Without Range Guard"

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
        """Analyze file for numeric settings used without a range guard.

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
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._detect_in_function(file_path, node))

        findings.sort(key=lambda f: (f.line_number, f.message))
        return findings

    def _detect_in_function(self, file_path: Path, func: _FunctionNode) -> list[DetectorFinding]:
        """Report every collected setting passed bare to a call with no guard."""
        nodes = list(self._iter_own_nodes(func))

        collected = self._collect_parameters(func)
        for var, line in self._collect_assignments(nodes).items():
            collected.setdefault(var, line)
        if not collected:
            return []

        guarded = self._guarded_names(nodes)
        candidates = {var: line for var, line in collected.items() if var not in guarded}
        if not candidates:
            return []

        uses: dict[str, str] = {}
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            callee = self._callee_name(node)
            if callee is None:
                continue
            for var in self._bare_name_arguments(node):
                if var in candidates and var not in uses:
                    uses[var] = callee

        findings: list[DetectorFinding] = []
        for var, callee in uses.items():
            lineno = candidates[var]
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
                        f"`{var}` is used by `{callee}` without a range check; "
                        "a zero, negative, NaN or huge value passes straight through"
                    ),
                    issue_reference="#499",
                    fix_hint=f"Validate `{var}` (finite, positive, bounded) before use",
                )
            )
        return findings

    def _is_setting_name(self, name: str) -> bool:
        """True when ``name`` contains any vocabulary token (case-insensitive)."""
        lowered = name.lower()
        return any(token in lowered for token in self.SETTING_TOKENS)

    def _collect_parameters(self, func: _FunctionNode) -> dict[str, int]:
        """Map ``name -> def line`` for vocabulary parameters with a numeric default."""
        collected: dict[str, int] = {}
        args = func.args
        positional = args.posonlyargs + args.args
        # Defaults align with the tail of the positional parameter list.
        offset = len(positional) - len(args.defaults)
        pairs = list(zip(positional[offset:], args.defaults, strict=True))
        pairs.extend(
            (arg, default)
            for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
            if default is not None
        )
        for arg, default in pairs:
            if self._is_numeric_constant(default) and self._is_setting_name(arg.arg):
                collected.setdefault(arg.arg, func.lineno)
        return collected

    def _collect_assignments(self, nodes: list[ast.AST]) -> dict[str, int]:
        """Map ``name -> line`` for numeric-setting assignments in the own body."""
        collected: dict[str, int] = {}
        for node in nodes:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name) or not self._is_setting_name(target.id):
                continue
            if self._is_numeric_source(node.value):
                collected.setdefault(target.id, node.lineno)
        return collected

    def _is_numeric_source(self, value: ast.expr) -> bool:
        """True for ``int(...)``/``float(...)`` or ``<expr>.get("...", <number>)``."""
        if not isinstance(value, ast.Call):
            return False
        func = value.func
        if isinstance(func, ast.Name):
            return func.id in self.NUMERIC_CASTS
        if isinstance(func, ast.Attribute) and func.attr == "get" and len(value.args) == 2:
            key, default = value.args
            return (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and self._is_numeric_constant(default)
            )
        return False

    @staticmethod
    def _is_numeric_constant(node: ast.expr | None) -> bool:
        """True for an ``int``/``float`` literal (``bool`` excluded)."""
        if not isinstance(node, ast.Constant):
            return False
        return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)

    def _guarded_names(self, nodes: list[ast.AST]) -> set[str]:
        """Names range-checked anywhere in the function body.

        A guard is a ``Compare`` with the name as an operand, an ``isfinite``
        call on the name, or a ``max``/``min`` clamp taking the name.
        """
        guarded: set[str] = set()
        for node in nodes:
            if isinstance(node, ast.Compare):
                for operand in (node.left, *node.comparators):
                    if isinstance(operand, ast.Name):
                        guarded.add(operand.id)
                continue
            if not isinstance(node, ast.Call):
                continue
            callee = self._callee_name(node)
            if callee == "isfinite" or callee in self.CLAMP_FUNCTIONS:
                guarded.update(self._bare_name_arguments(node))
        return guarded

    @staticmethod
    def _callee_name(call: ast.Call) -> str | None:
        """Terminal name of the callee: ``fetch_all`` or ``query`` for ``client.query``."""
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

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
    def _bare_name_arguments(call: ast.Call) -> Iterator[str]:
        """Yield every argument passed as a bare ``Name`` (positional or keyword)."""
        for arg in call.args:
            if isinstance(arg, ast.Name):
                yield arg.id
        for kw in call.keywords:
            if isinstance(kw.value, ast.Name):
                yield kw.value.id
