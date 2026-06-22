# tested-by: tests/unit/test_deterministic_port_guards.py
"""Deterministic port contract type guards for #253.

Detects when core port/interface definitions use loose types (raw dict, Any,
or str) that leak implementation details across hexagonal boundaries.
These tests intentionally encode contract invariants.

Parent bug: #219
Epic: #146
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #253 — fix the source code, then this test goes green",
    strict=False,
)

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Core port/interface definition files
_PORT_FILES = (
    _SRC / "core" / "ports.py",
    _SRC / "core" / "policy_port.py",
)


class LooseTypeVisitor(ast.NodeVisitor):
    """AST visitor that finds loose types in annotations."""

    def __init__(self) -> None:
        self.findings: list[tuple[int, str, str]] = []

    def _is_loose_type(self, node: ast.expr) -> tuple[bool, str]:
        """Check if a type annotation is a loose type (dict, Any, or str).

        Returns (is_loose, type_name) tuple.
        """
        if isinstance(node, ast.Name):
            # Raw dict, Any, str without subscripts
            if node.id in ("dict", "Dict", "Any", "str", "list", "List"):
                return True, node.id
        elif isinstance(node, ast.Subscript):
            # Check for list[Any], dict[str, Any], etc.
            if isinstance(node.value, ast.Name):
                container = node.value.id
                # list[Any], dict[str, Any], etc.
                if container in ("list", "List", "dict", "Dict"):
                    # Check the slice for Any
                    if self._contains_any(node.slice):
                        return True, f"{container}[...Any...]"
            # Check for str that could be more specific (Literal, Enum, etc.)
            if isinstance(node.value, ast.Name) and node.value.id == "str":
                # Subscripted str is unusual but might be valid
                pass
        elif isinstance(node, ast.Constant):
            # String annotations like "dict"
            if isinstance(node.value, str) and node.value in (
                "dict",
                "Dict",
                "Any",
                "list",
                "List",
            ):
                return True, node.value
        elif isinstance(node, ast.Attribute):
            # typing.Any, typing.Dict, etc.
            if isinstance(node.value, ast.Name) and node.value.id == "typing":
                if node.attr in ("Any", "Dict", "List"):
                    return True, f"typing.{node.attr}"
        return False, ""

    def _contains_any(self, node: ast.expr) -> bool:
        """Recursively check if node contains Any type."""
        if isinstance(node, ast.Name) and node.id == "Any":
            return True
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "typing":
                return node.attr == "Any"
        if isinstance(node, ast.Tuple):
            return any(self._contains_any(elt) for elt in node.elts)
        if isinstance(node, ast.Subscript):
            return self._contains_any(node.slice)
        return False

    def _format_annotation(self, node: ast.expr) -> str:
        """Format annotation node for human-readable output."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Attribute):
            return f"{self._format_annotation(node.value)}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            container = self._format_annotation(node.value)
            if isinstance(node.slice, ast.Tuple):
                params = ", ".join(self._format_annotation(elt) for elt in node.slice.elts)
            else:
                params = self._format_annotation(node.slice)
            return f"{container}[{params}]"
        return "<unknown>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions to check argument and return types."""
        # Check return annotation
        if node.returns:
            is_loose, type_name = self._is_loose_type(node.returns)
            if is_loose:
                self.findings.append(
                    (
                        node.lineno,
                        f"return of '{node.name}'",
                        self._format_annotation(node.returns),
                    )
                )

        # Check argument annotations
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.annotation:
                is_loose, type_name = self._is_loose_type(arg.annotation)
                if is_loose:
                    self.findings.append(
                        (
                            arg.lineno,
                            f"arg '{arg.arg}' in '{node.name}'",
                            self._format_annotation(arg.annotation),
                        )
                    )

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit annotated assignments (class attributes with type hints)."""
        if node.annotation:
            is_loose, type_name = self._is_loose_type(node.annotation)
            if is_loose:
                target_name = "<unknown>"
                if isinstance(node.target, ast.Name):
                    target_name = node.target.id
                elif isinstance(node.target, ast.Attribute):
                    target_name = node.target.attr

                self.findings.append(
                    (
                        node.lineno,
                        f"attribute '{target_name}'",
                        self._format_annotation(node.annotation),
                    )
                )

        self.generic_visit(node)


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    """Get repo-relative path string."""
    return path.relative_to(_REPO).as_posix()


@pytest.mark.xfail(reason="deterministic bug detector for #253", strict=False)
def test_port_contracts_no_loose_dict_types() -> None:
    """#253: Port contracts must not use raw 'dict' return types.

    Raw dict leaks implementation structure across the port boundary.
    Use TypedDict, dataclass, or Pydantic model instead.
    """
    violations: list[str] = []

    for path in _PORT_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        visitor = LooseTypeVisitor()
        visitor.visit(tree)

        for lineno, context, type_str in visitor.findings:
            if "dict" in type_str.lower() or "Dict" in type_str:
                violations.append(f"{_rel(path)}:{lineno}: {context} uses '{type_str}'")

    assert violations == [], (
        "Port contracts must not use raw dict types.\n"
        "Use TypedDict, dataclass, or Pydantic model for structured data:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #253", strict=False)
def test_port_contracts_no_any_types() -> None:
    """#253: Port contracts must not use 'Any' in type annotations.

    Any bypasses type safety and prevents static analysis.
    Use Union/Optional with concrete types, or Protocol for flexibility.
    """
    violations: list[str] = []

    for path in _PORT_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        visitor = LooseTypeVisitor()
        visitor.visit(tree)

        for lineno, context, type_str in visitor.findings:
            if "Any" in type_str:
                violations.append(f"{_rel(path)}:{lineno}: {context} uses '{type_str}'")

    assert violations == [], (
        "Port contracts must not use Any type.\n"
        "Use Union/Optional with concrete types, or Protocol for flexibility:\n"
        + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #253", strict=False)
def test_port_contracts_no_raw_list_types() -> None:
    """#253: Port contracts should not use raw 'list' without type parameters.

    Raw list without element type erases type information.
    Use list[ConcreteType] instead.
    """
    violations: list[str] = []

    for path in _PORT_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        visitor = LooseTypeVisitor()
        visitor.visit(tree)

        for lineno, context, type_str in visitor.findings:
            # Catch raw list/Dict (not subscripted)
            if type_str in ("list", "List", "dict", "Dict"):
                violations.append(f"{_rel(path)}:{lineno}: {context} uses raw '{type_str}'")

    assert violations == [], (
        "Port contracts must not use raw list/dict without type parameters.\n"
        "Use list[ConcreteType] or dict[KeyType, ValueType]:\n" + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #253", strict=False)
def test_dataclass_fields_no_loose_types() -> None:
    """#253: Dataclass fields in port files must not use loose types.

    ReviewReport and similar dataclasses are part of the port contract.
    Their fields should use specific types, not Any or raw dict.
    """
    violations: list[str] = []

    for path in _PORT_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        visitor = LooseTypeVisitor()
        visitor.visit(tree)

        for lineno, context, type_str in visitor.findings:
            if "attribute" in context:  # Only dataclass/attribute findings
                violations.append(f"{_rel(path)}:{lineno}: {context} uses loose type '{type_str}'")

    assert (
        violations == []
    ), "Dataclass fields in port contracts must use specific types:\n" + "\n".join(violations)
