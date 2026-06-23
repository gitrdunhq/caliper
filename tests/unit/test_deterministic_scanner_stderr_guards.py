# tested-by: tests/unit/test_deterministic_scanner_stderr_guards.py
"""Deterministic guards for scanner subprocess stderr capture.

These tests use AST analysis to detect subprocess.run calls in scanner plugins
that capture stderr but don't log it on non-zero exit (issue #204).

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Scanner files where subprocess stderr must be captured and logged on failure (issue #204)
_SUBPROCESS_SCANNER_FILES: tuple[Path, ...] = (
    _SRC / "plugins" / "osv_scanner.py",
    _SRC / "plugins" / "syft.py",
    _SRC / "plugins" / "scancode.py",
    _SRC / "plugins" / "typos.py",
    _SRC / "plugins" / "mypy.py",
    _SRC / "plugins" / "clamav.py",
    _SRC / "plugins" / "ls_lint.py",
    _SRC / "plugins" / "_runners" / "semgrep_runner.py",
    _SRC / "plugins" / "_runners" / "cpd_runner.py",
    _SRC / "plugins" / "_runners" / "complexity_runner.py",
    _SRC / "plugins" / "_runners" / "cdk_nag_runner.py",
    _SRC / "plugins" / "_runners" / "cfn_nag_runner.py",
    _SRC / "plugins" / "_runners" / "kube_linter_runner.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _call_name(node: ast.AST) -> str | None:
    """Extract the full name of a function call (e.g., 'subprocess.run')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _has_capture_output(node: ast.Call) -> bool:
    """Check if subprocess.run has capture_output=True."""
    for kw in node.keywords:
        if kw.arg == "capture_output":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
            if isinstance(kw.value, ast.NameConstant) and kw.value.value is True:
                return True
    return False


def _find_subprocess_assignments(
    tree: ast.Module,
) -> list[tuple[ast.Call, ast.Assign | ast.AnnAssign, int, str]]:
    """Find all subprocess.run calls assigned to variables.

    Returns list of (call_node, assign_node, lineno, var_name) tuples.
    """
    results: list[tuple[ast.Call, ast.Assign | ast.AnnAssign, int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                    call_name = _call_name(node.value.func)
                    if call_name == "subprocess.run":
                        results.append((node.value, node, node.lineno or 0, target.id))
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and isinstance(node.value, ast.Call):
                call_name = _call_name(node.value.func)
                if call_name == "subprocess.run":
                    results.append((node.value, node, node.lineno or 0, node.target.id))

    return results


def _find_stderr_usage(tree: ast.Module, var_name: str) -> list[tuple[int, str]]:
    """Find all usages of var_name.stderr in the AST.

    Returns list of (lineno, usage_context) tuples.
    """
    usages: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        # Direct attribute access: r.stderr
        if isinstance(node, ast.Attribute) and node.attr == "stderr":
            if isinstance(node.value, ast.Name) and node.value.id == var_name:
                usages.append((node.lineno or 0, "access"))

        # Check if stderr is passed to logging/error functions
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if isinstance(kw.value, ast.Attribute) and kw.value.attr == "stderr":
                    if isinstance(kw.value.value, ast.Name) and kw.value.value.id == var_name:
                        func_name = _call_name(node.func)
                        usages.append((node.lineno or 0, f"{func_name}({kw.arg}=...)"))

    return usages


def _find_logger_usage(tree: ast.Module, var_name: str) -> list[int]:
    """Find if a variable is passed to any logger.* calls."""
    lines: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _call_name(node.func) or ""
            if "." in func_name and func_name.split(".")[0] in ("logger", "log"):
                # Check if var_name or var_name.stderr is in args/kwargs
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == var_name:
                        lines.append(node.lineno or 0)
                    if isinstance(arg, ast.Attribute) and arg.attr == "stderr":
                        if isinstance(arg.value, ast.Name) and arg.value.id == var_name:
                            lines.append(node.lineno or 0)
                for kw in node.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id == var_name:
                        lines.append(node.lineno or 0)
                    if isinstance(kw.value, ast.Attribute) and kw.value.attr == "stderr":
                        if isinstance(kw.value.value, ast.Name) and kw.value.value.id == var_name:
                            lines.append(node.lineno or 0)

    return lines


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #204 - Scanner stderr is not captured or logged on non-zero exit",
    strict=False,
)
def test_204_scanner_stderr_captured_and_logged_on_failure() -> None:
    """Detect subprocess.run calls in scanners that don't log stderr on failure.

    Issue #204 (epic #146): Scanner subprocess stderr is not captured or logged
    on non-zero exit. When external scanner tools fail, their error output is
    lost, making debugging difficult.

    Violations:
        - subprocess.run with capture_output=True where result.stderr is never logged
        - Error handling that doesn't include stderr context

    Acceptance criteria for fix:
        - All subprocess.run calls in scanners capture stderr (capture_output=True)
        - On non-zero exit, stderr is logged via logger.* or included in error result
        - Error context is preserved for debugging
    """
    violations: list[str] = []

    for path in _SUBPROCESS_SCANNER_FILES:
        if not path.exists():
            continue

        tree = _parse(path)
        assignments = _find_subprocess_assignments(tree)

        for call, _assign, lineno, var_name in assignments:
            # Must have capture_output=True
            if not _has_capture_output(call):
                violations.append(
                    f"{_rel(path)}:{lineno}: subprocess.run without capture_output=True "
                    f"(stderr not captured)"
                )
                continue

            # Check if stderr is used (accessed or logged)
            stderr_usages = _find_stderr_usage(tree, var_name)
            logger_usages = _find_logger_usage(tree, var_name)

            # If neither stderr is accessed nor variable logged, it's a violation
            if not stderr_usages and not logger_usages:
                violations.append(
                    f"{_rel(path)}:{lineno}: subprocess.run result '{var_name}' stderr not "
                    f"logged or used (stderr captured but lost on failure)"
                )

    assert (
        violations == []
    ), "Scanner subprocess calls must capture and log stderr on failure:\n" + "\n".join(violations)
