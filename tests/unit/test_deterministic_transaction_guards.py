# tested-by: tests/unit/test_deterministic_transaction_guards.py
"""Deterministic transaction rollback guards for batch evidence operations.

These tests use AST analysis to detect batch database operations that lack
proper transaction rollback handling on partial failure.

Issue #216: Batch evidence operations must have transaction rollback on partial failure.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_DB_FILE = _SRC / "data" / "db.py"


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _get_function_node(tree: ast.Module, func_name: str) -> ast.FunctionDef | None:
    """Extract a function definition node by name."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node
    return None


def _has_rollback_in_exception_handler(body: list[ast.stmt]) -> bool:
    """Check if any exception handler in the body contains a rollback call."""
    for stmt in body:
        if isinstance(stmt, ast.Try):
            # Check all except handlers
            for handler in stmt.handlers:
                for child in ast.walk(handler):
                    if isinstance(child, ast.Call):
                        call_name = _call_name(child.func)
                        if call_name and "rollback" in call_name.lower():
                            return True
    return False


def _uses_transaction_context_manager(body: list[ast.stmt]) -> bool:
    """Check if the body uses 'with conn:' or 'with conn.transaction():' pattern."""
    for stmt in body:
        if isinstance(stmt, ast.With):
            for item in stmt.items:
                ctx_expr = item.context_expr
                # Check for 'with conn:'
                if isinstance(ctx_expr, ast.Name):
                    return True
                # Check for 'with conn.transaction():'
                if isinstance(ctx_expr, ast.Call):
                    if isinstance(ctx_expr.func, ast.Attribute):
                        if "transaction" in ctx_expr.func.attr.lower():
                            return True
    return False


def _call_name(node: ast.AST | None) -> str | None:
    """Extract the full name of a function call (e.g., 'conn.rollback')."""
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _is_batch_insert_function(func: ast.FunctionDef) -> bool:
    """Check if function performs batch inserts (iterates and inserts)."""
    source = ast.unparse(func)
    # Look for patterns indicating batch operations
    has_loop = any(
        isinstance(node, (ast.For, ast.While, ast.ListComp, ast.GeneratorExp))
        for node in ast.walk(func)
    )
    has_insert = "INSERT" in source.upper()
    has_batch_param = any(
        "results" in arg.arg.lower() or "batch" in arg.arg.lower() for arg in func.args.args
    )
    return has_loop and has_insert and has_batch_param


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #216 - batch evidence operations lack transaction rollback",
    strict=False,
)
def test_216_batch_evidence_operations_have_transaction_rollback() -> None:
    """Detect batch database operations without proper transaction rollback handling.

    Issue #216 (epic #146): Batch evidence operations must have transaction rollback
    on partial failure. Currently save_scan_results() iterates through results and
    inserts them one by one, but if one fails partway through, the preceding inserts
    are not rolled back — they're already committed.

    Violations:
        - Batch insert operations without explicit rollback in exception handler
        - Batch operations not using transaction context managers

    Acceptance criteria for fix:
        - All batch insert operations have proper rollback handling
        - Either use 'with conn:' context manager (auto-rollback on exception)
        - Or explicitly call conn.rollback() in the except block
    """
    violations: list[str] = []

    if not _DB_FILE.exists():
        violations.append(f"{_rel(_DB_FILE)}: file does not exist")
        pytest.fail("\n".join(violations))

    tree = _parse(_DB_FILE)

    # Check save_scan_results function specifically
    func = _get_function_node(tree, "save_scan_results")
    if func is None:
        violations.append(f"{_rel(_DB_FILE)}: save_scan_results function not found")
    else:
        if not _is_batch_insert_function(func):
            violations.append(
                f"{_rel(_DB_FILE)}:{func.lineno}: save_scan_results does not appear to be a batch insert function"
            )
        else:
            # Check for rollback or transaction context manager
            has_rollback = _has_rollback_in_exception_handler(func.body)
            has_transaction_ctx = _uses_transaction_context_manager(func.body)

            if not has_rollback and not has_transaction_ctx:
                violations.append(
                    f"{_rel(_DB_FILE)}:{func.lineno}: save_scan_results() lacks transaction rollback. "
                    f"Batch insert operations need either:\n"
                    f"  1. 'with conn:' context manager (auto-rollback on exception), or\n"
                    f"  2. Explicit conn.rollback() call in the except block\n"
                    f"Current code commits after each successful batch, but partial failures leave\n"
                    f"committed data in place without rollback."
                )

    assert violations == [], (
        "Batch evidence operations must have transaction rollback on partial failure:\n"
        + "\n".join(violations)
    )
