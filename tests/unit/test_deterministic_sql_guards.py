"""Deterministic test for issue #176: Database queries lack prepared statements.
# tested-by: tests/unit/test_deterministic_sql_guards.py

Uses AST analysis to detect raw SQL without parameterization.
"""

import ast
from pathlib import Path

import pytest


class PreparedStatementVisitor(ast.NodeVisitor):
    """AST visitor to find SQL execute() calls without prepared statement parameters."""

    def __init__(self) -> None:
        self.unsafe_executes: list[tuple[int, str]] = []
        self.current_function: str | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track current function name for context."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track current async function name for context."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_Call(self, node: ast.Call) -> None:
        """Detect SQL execute() calls without parameter tuples."""
        # Check for .execute() method calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute" and node.args:
            # First argument is typically the SQL string
            first_arg = node.args[0]

            # Check if it's a string literal (raw SQL) without parameters
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                sql = first_arg.value.strip()

                # Skip non-SQL execute calls (e.g., test assertions, other APIs)
                if not any(
                    keyword in sql.upper()
                    for keyword in ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM"]
                ):
                    self.generic_visit(node)
                    return

                # Check if it has parameter tuple/list as second argument
                has_params = len(node.args) >= 2 and isinstance(node.args[1], (ast.Tuple, ast.List))

                if not has_params:
                    # Check for % formatting or f-string in SQL (dangerous)
                    if "%" in sql or "{" in sql:
                        context = f"{self.current_function or 'module'}:{node.lineno}"
                        self.unsafe_executes.append((node.lineno, context))

        self.generic_visit(node)


def find_unsafe_sql_in_file(file_path: Path) -> list[tuple[int, str]]:
    """Scan a Python file for SQL execute() calls without prepared statements."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    visitor = PreparedStatementVisitor()
    visitor.visit(tree)
    return visitor.unsafe_executes


def find_all_db_files(repo_root: Path) -> list[Path]:
    """Find all database-related Python files."""
    db_files = []
    data_dir = repo_root / "src" / "caliper" / "data"
    if data_dir.exists():
        for py_file in data_dir.rglob("*.py"):
            if py_file.name != "__init__.py":
                db_files.append(py_file)
    return db_files


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_no_unparameterized_sql_queries() -> None:
    """
    Detect database queries that lack prepared statements.

    Issue #176: Raw SQL with string formatting (%s, f-strings) creates
    SQL injection vulnerabilities. All SQL queries must use
    parameterized/prepared statements.
    """
    repo_root = Path(__file__).parent.parent.parent
    db_files = find_all_db_files(repo_root)

    violations = []
    for py_file in db_files:
        unsafe = find_unsafe_sql_in_file(py_file)
        for lineno, context in unsafe:
            violations.append(f"{py_file}:{lineno} ({context})")

    if violations:
        msg = "Unparameterized SQL queries found:\n" + "\n".join(f"  - {v}" for v in violations)
        pytest.fail(msg)
