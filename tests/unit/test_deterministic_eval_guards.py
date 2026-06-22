"""Deterministic guard for eval() usage on untrusted input in policy rules — Issue #233 / Parent #199.

# tested-by: tests/unit/test_deterministic_eval_guards.py

This test uses AST analysis to detect dangerous eval() usage in policy-related
code that processes untrusted input. It uses @pytest.mark.xfail to document
the known security vulnerability without breaking the build.

Issue #233: Add deterministic rule for #199: Policy rule conditions use eval() on untrusted input
Issue #199: Policy rule conditions use eval() on untrusted input (security vulnerability)
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Set

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Policy-related files that handle rule conditions
_POLICY_RULE_FILES: tuple[Path, ...] = (
    _SRC / "core" / "policy.py",
    _SRC / "core" / "opa_adapter.py",
    _SRC / "core" / "policy_port.py",
    _SRC / "core" / "pipeline.py",
)

# Functions that might process untrusted input
_UNTRUSTED_INPUT_SOURCES: Set[str] = {
    "input",
    "findings",
    "package_metadata",
    "config",
    "raw_input",
    "user_input",
    "untrusted",
    "data",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _contains_eval_call(node: ast.AST) -> bool:
    """Check if AST node contains an eval() call."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id == "eval":
                return True
    return False


def _get_eval_calls(node: ast.AST) -> list[tuple[ast.Call, int]]:
    """Extract all eval() calls with their line numbers from an AST node."""
    eval_calls = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id == "eval":
                lineno = getattr(child, "lineno", 0)
                eval_calls.append((child, lineno))
    return eval_calls


def _is_untrusted_source(node: ast.AST) -> bool:
    """Check if node represents untrusted input (heuristic)."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in _UNTRUSTED_INPUT_SOURCES:
            return True
        # Check for attribute access on untrusted sources (e.g., input.findings)
        if isinstance(child, ast.Attribute):
            if isinstance(child.value, ast.Name) and child.value.id in _UNTRUSTED_INPUT_SOURCES:
                return True
    return False


@pytest.mark.xfail(
    reason="deterministic bug detector #233: eval() on untrusted input in policy rule conditions",
    strict=False,
)
def test_233_policy_rule_conditions_no_eval_on_untrusted_input() -> None:
    """Detect eval() usage on untrusted input in policy rule condition code.

    Issue #199 (via #233): Policy rule conditions must never use eval() on
    untrusted input. eval() executes arbitrary code and is a critical security
    vulnerability when processing external data.

    Violations to detect:
        - eval(input.findings) in policy condition evaluation
        - eval(config.rule_condition) where config comes from external source
        - eval(raw_condition) where condition is user-controlled

    Acceptance criteria for fix:
        - No eval() calls in policy rule condition code
        - Use ast.literal_eval() for safe parsing if needed
        - Use explicit rule evaluation (OPA/Rego) instead of dynamic Python eval

    Current detection: AST-based search for eval() calls in policy-related files.
    """
    violations: list[str] = []

    for path in _POLICY_RULE_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        # Walk the AST looking for eval() calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if this is an eval() call
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    lineno = getattr(node, "lineno", 0)

                    # Check if arguments contain untrusted sources
                    args_contain_untrusted = False
                    for arg in node.args:
                        if _is_untrusted_source(arg):
                            args_contain_untrusted = True
                            break

                    # Also check keyword arguments
                    for keyword in node.keywords:
                        if _is_untrusted_source(keyword.value):
                            args_contain_untrusted = True
                            break

                    # Report the violation
                    source_hint = " with untrusted input" if args_contain_untrusted else ""
                    violations.append(
                        f"{_rel(path)}:{lineno}: eval(){source_hint} detected - "
                        f"security vulnerability #199"
                    )

    assert violations == [], (
        "CRITICAL: eval() detected in policy rule code. "
        "eval() on untrusted input is a code execution vulnerability:\n"
        + "\n".join(violations)
        + "\n\nFix #199: Replace eval() with safe alternatives like ast.literal_eval() "
        "or explicit rule evaluation."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector #233: eval() usage in core policy modules",
    strict=False,
)
def test_233_no_eval_in_policy_core_modules() -> None:
    """Detect any eval() usage in core policy modules.

    This is a broader check that flags ANY eval() usage in policy-related
    code, even if not directly on untrusted input. eval() should never be
    used in security-critical policy evaluation paths.
    """
    violations: list[str] = []

    for path in _POLICY_RULE_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    lineno = getattr(node, "lineno", 0)
                    # Get context - what function/class contains this eval
                    context = ""
                    for parent in ast.walk(tree):
                        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if parent.lineno <= lineno:
                                context = f" in {parent.name}()"

                    violations.append(
                        f"{_rel(path)}:{lineno}: eval(){context} - "
                        f"forbidden in policy code per #199"
                    )

    assert violations == [], (
        "eval() is forbidden in policy core modules:\n"
        + "\n".join(violations)
        + "\n\nUse safe alternatives: ast.literal_eval(), json.loads(), or OPA/Rego."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: exec() usage in policy modules",
    strict=False,
)
def test_233_no_exec_in_policy_core_modules() -> None:
    """Detect exec() usage in policy modules (companion to eval check).

    exec() is equally dangerous as eval() for code execution vulnerabilities.
    Both should be absent from policy evaluation code.
    """
    violations: list[str] = []

    for path in _POLICY_RULE_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "exec":
                    lineno = getattr(node, "lineno", 0)
                    violations.append(
                        f"{_rel(path)}:{lineno}: exec() detected - "
                        f"forbidden in policy code per #199"
                    )

    assert violations == [], (
        "exec() is forbidden in policy core modules:\n"
        + "\n".join(violations)
        + "\n\nNeither eval() nor exec() should be used in security-critical code."
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: compile() with untrusted source in policy modules",
    strict=False,
)
def test_233_no_compile_of_untrusted_in_policy_modules() -> None:
    """Detect compile() of untrusted source in policy modules.

    compile() followed by exec() or eval() is equivalent to direct eval/exec.
    Detect compile() calls that might process untrusted input.
    """
    violations: list[str] = []

    for path in _POLICY_RULE_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "compile":
                    lineno = getattr(node, "lineno", 0)

                    # Check if first argument (source) might be untrusted
                    if node.args and _is_untrusted_source(node.args[0]):
                        violations.append(
                            f"{_rel(path)}:{lineno}: compile() of untrusted source - "
                            f"potential code execution vulnerability"
                        )

    assert violations == [], (
        "compile() of untrusted source detected in policy modules:\n"
        + "\n".join(violations)
        + "\n\nDo not compile() external input in security-critical code."
    )
