"""Deterministic detector for health check endpoints missing DB verification (#218).

# tested-by: tests/unit/test_deterministic_health_guards.py

This test uses AST analysis to detect health check endpoints that do not
verify database connectivity. Bug #184 (parent of #218) identified that
health checks must verify database connectivity to be meaningful.

The detector scans for:
1. Health check endpoints (functions named health*, check_health*, or containing /health)
2. Database connectivity verification patterns (DecisionRepository, db.connect, SELECT 1)

If a health check is found without DB verification, the test fails with a
helpful message explaining the bug and how to fix it.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence


def _find_source_files(src_dir: Path) -> list[Path]:
    """Find all Python source files in the src directory."""
    return list(src_dir.rglob("*.py"))


def _get_function_source(func: object) -> tuple[ast.AST, Path] | None:
    """Get AST and source path for a function, returning None if unavailable."""
    try:
        source_path = Path(inspect.getfile(func))
        source = source_path.read_text()
        return ast.parse(source), source_path
    except (OSError, TypeError, ValueError):
        return None


def _is_health_check_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if a function is a health check endpoint.

    Matches:
    - Functions named health*, check_health*, or check-health
    - Functions containing /health in their docstring
    """
    name = node.name.lower()

    # Name-based detection
    if any(
        pattern in name for pattern in ("health", "check_health", "check-health", "healthcheck")
    ):
        return True

    # Docstring-based detection
    docstring = ast.get_docstring(node)
    return bool(docstring and "/health" in docstring.lower())


def _has_db_connectivity_check(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_text: str,
) -> bool:
    """Check if a function contains database connectivity verification.

    Looks for:
    - DecisionRepository usage
    - db.connect() calls
    - ConnectionPool or similar DB connection patterns
    - "SELECT 1" queries (common DB health check)
    """
    # Convert function AST back to string for pattern matching
    func_source = ast.unparse(node)

    # Database connectivity patterns
    db_patterns = [
        "DecisionRepository",
        "db.connect",
        "ConnectionPool",
        "SELECT 1",
        "database_connected",
        "database_connection",
        "db_dsn",
    ]

    return any(pattern in func_source for pattern in db_patterns)


def _analyze_health_check_for_db_verification(
    tree: ast.AST,
    source_path: Path,
    source_text: str,
) -> Sequence[dict]:
    """Analyze AST for health check functions missing DB verification.

    Returns a list of dicts with details about each violation found.
    """
    violations: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        if not _is_health_check_function(node):
            continue

        # Found a health check function - check for DB verification
        if not _has_db_connectivity_check(node, source_text):
            violations.append(
                {
                    "function_name": node.name,
                    "line_number": node.lineno,
                    "source_path": source_path,
                    "source_snippet": (
                        ast.unparse(node)[:200] + "..."
                        if len(ast.unparse(node)) > 200
                        else ast.unparse(node)
                    ),
                }
            )

    return violations


@pytest.mark.xfail(reason="deterministic bug detector for #218/#184", strict=False)
def test_218_health_checks_must_verify_db_connectivity() -> None:
    """Detect health check endpoints that lack database connectivity verification.

    Bug #184 (parent of #218): Health check endpoints must verify database
    connectivity to provide meaningful status. A health check that only checks
    if the process is running but not if the database is accessible can
    mislead monitoring systems into thinking the service is healthy when
    it's actually in a degraded state.

    Target files to analyze:
    - src/caliper/cli/inspect_cmds.py (check_health command)
    - Any webhook or API endpoints with health checks
    - Any module-level health check functions

    Acceptance criteria:
    - Health check functions must call DecisionRepository.connect() or equivalent
    - Health checks should report database status in their output
    - Missing DB checks should fail the detector with clear guidance

    Fix: Add database connectivity check using DecisionRepository or
    equivalent pattern from caliper.data.db module.
    """
    repo_root = Path(__file__).parent.parent.parent
    src_dir = repo_root / "src" / "caliper"

    if not src_dir.exists():
        pytest.skip(f"Source directory not found: {src_dir}")

    all_violations: list[dict] = []

    # Analyze all source files
    for source_path in _find_source_files(src_dir):
        try:
            source_text = source_path.read_text()
            tree = ast.parse(source_text)
        except SyntaxError:
            continue  # Skip files with syntax errors

        violations = _analyze_health_check_for_db_verification(tree, source_path, source_text)
        all_violations.extend(violations)

    # Also check specific known health check functions via inspection
    try:
        from caliper.cli import inspect_cmds

        result = _get_function_source(inspect_cmds.check_health)
        if result:
            tree, source_path = result
            # For inspection-based check, verify the source contains DB patterns
            source_text = source_path.read_text()
            violations = _analyze_health_check_for_db_verification(tree, source_path, source_text)
            all_violations.extend(violations)
    except ImportError:
        pass  # Module not available

    # Report findings
    if all_violations:
        violation_messages = []
        for v in all_violations:
            msg = (
                f"  - {v['function_name']} at {v['source_path']}:{v['line_number']}\n"
                f"    Source: {v['source_snippet'][:100]}..."
            )
            violation_messages.append(msg)

        pytest.fail(
            f"BUG DETECTED: Health check(s) lacking database connectivity verification.\n\n"
            f"Violations found ({len(all_violations)}):\n" + "\n".join(violation_messages) + "\n\n"
            "Bug #184: Health checks must verify database connectivity.\n"
            "Impact: Monitoring systems may report 'healthy' when DB is down.\n\n"
            "Fix: Add DecisionRepository.connect() or equivalent DB check:\n"
            "  from caliper.data.db import DecisionRepository\n"
            "  from caliper.core.config import CaliperSettings\n"
            "  config = CaliperSettings()\n"
            "  db = DecisionRepository(dsn=config.db_dsn)\n"
            "  if db.connect():\n"
            "      print('Database OK')\n"
            "      db.close()\n"
            "  else:\n"
            "      print('Database UNAVAILABLE')\n"
            "      # Health check should fail\n"
        )


@pytest.mark.xfail(reason="deterministic bug detector for #218 - specific CLI check", strict=False)
def test_218_cli_check_health_verifies_db() -> None:
    """Specific check that CLI check_health command verifies database.

    This test directly inspects the check_health function source code
    to ensure it contains the database connectivity verification pattern.
    """
    from caliper.cli import inspect_cmds

    result = _get_function_source(inspect_cmds.check_health)
    if result is None:
        pytest.skip("Could not get source for check_health function")

    tree, source_path = result
    source_text = source_path.read_text()

    # Find the check_health function specifically
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "check_health":
                func_source = ast.unparse(node)

                # Required patterns for proper DB verification
                required_patterns = [
                    ("DecisionRepository", "Database repository import/usage"),
                    ("connect", "DB connection attempt"),
                ]

                missing = []
                for pattern, description in required_patterns:
                    if pattern not in func_source:
                        missing.append((pattern, description))

                if missing:
                    missing_desc = ", ".join(f"{desc} ({pat})" for pat, desc in missing)
                    pytest.fail(
                        f"BUG DETECTED: check_health command missing DB verification.\n"
                        f"Location: {source_path}:{node.lineno}\n"
                        f"Missing: {missing_desc}\n\n"
                        f"Bug #184: Health check must verify database connectivity.\n\n"
                        f"Current implementation may only check scanner binaries\n"
                        f"without verifying the database is accessible.\n\n"
                        f"Fix: Add database connectivity check as shown in\n"
                        f"test_deterministic_health_guards.py docstring."
                    )

                # If we found the function and it has patterns, we're good
                return

    # If we didn't find the function at all
    pytest.fail(
        "Could not locate check_health function in inspect_cmds module.\n"
        "The test may need updating if the code structure changed."
    )
