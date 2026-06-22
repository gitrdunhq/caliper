# tested-by: tests/unit/test_deterministic_validation_guards.py
"""Deterministic validation guards for input validation approach.

These tests intentionally encode security invariants as static checks.
They use @pytest.mark.xfail to allow the test suite to pass while
violations exist, documenting the security debt.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Blacklist pattern indicators in variable/constant names
_BLACKLIST_NAME_RE = re.compile(
    r"blacklist|whitelist|denylist|allowlist|dangerous|forbidden|bad_|evil_",
    re.IGNORECASE,
)

# Whitelist approach indicators (positive validation)
_WHITELIST_NAME_RE = re.compile(
    r"allowed|permitted|valid|safe|whitelist|allowlist",
    re.IGNORECASE,
)

# Files that contain input validation logic
_VALIDATION_FILES: tuple[Path, ...] = (
    _SRC / "core" / "solver.py",
    _SRC / "core" / "config.py",
    _SRC / "core" / "taskfit_validator.py",
    _SRC / "webhook" / "server.py",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _contains_blacklist_indicator(name: str) -> bool:
    """Check if a name indicates blacklist-based validation."""
    return bool(_BLACKLIST_NAME_RE.search(name))


def _contains_whitelist_indicator(name: str) -> bool:
    """Check if a name indicates whitelist-based validation."""
    return bool(_WHITELIST_NAME_RE.search(name))


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #180 - input validation uses blacklist instead of whitelist approach",
    strict=False,
)
def test_180_input_validation_uses_blacklist_instead_of_whitelist() -> None:
    """Detect blacklist-based validation patterns in security-critical code.

    Issue #180: Input validation should use whitelist (allowlist) approach instead
    of blacklist (denylist) approach. Blacklisting attempts to enumerate all
    "bad" inputs, which is inherently incomplete and prone to bypasses.

    Violations:
        - src/caliper/core/solver.py:42 - _DANGEROUS_PATTERNS regex
          Uses blacklist pattern to detect dangerous code constructs.
          Should use AST-based whitelist or sandboxed execution instead.

    Acceptance criteria for fix:
        - All input validation uses whitelist (positive validation) approach
        - Replace _DANGEROUS_PATTERNS blacklist with AST-based validation
        - Allow only explicitly permitted patterns rather than blocking known-bad ones
    """
    violations: list[str] = []

    for path in _VALIDATION_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            # Check variable/constant assignments for blacklist naming
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if _contains_blacklist_indicator(target.id):
                            # Check if it's a regex pattern (classic blacklist)
                            if isinstance(node.value, (ast.Constant, ast.Call)):
                                if isinstance(node.value, ast.Constant) and isinstance(
                                    node.value.value, str
                                ):
                                    violations.append(
                                        f"{_rel(path)}:{node.lineno}: "
                                        f"{target.id} = regex blacklist pattern (issue #180)"
                                    )
                                elif isinstance(node.value, ast.Call):
                                    call = node.value
                                    if isinstance(call.func, ast.Name):
                                        if call.func.id in ("compile", "re.compile"):
                                            violations.append(
                                                f"{_rel(path)}:{node.lineno}: "
                                                f"{target.id} = compiled regex blacklist (issue #180)"
                                            )

            # Check annotated assignments (class/module attributes)
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name):
                    if _contains_blacklist_indicator(node.target.id):
                        violations.append(
                            f"{_rel(path)}:{node.lineno}: "
                            f"{node.target.id} annotated with blacklist naming (issue #180)"
                        )

            # Check function names for blacklist indicators
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _contains_blacklist_indicator(node.name):
                    violations.append(
                        f"{_rel(path)}:{node.lineno}: "
                        f"function {node.name}() uses blacklist naming (issue #180)"
                    )

    assert (
        violations == []
    ), "Input validation must use whitelist (allowlist) approach, not blacklist:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #180 - solver uses dangerous pattern blacklist",
    strict=False,
)
def test_180_solver_dangerous_patterns_is_blacklist() -> None:
    """Specific test for solver._DANGEROUS_PATTERNS blacklist.

    The _DANGEROUS_PATTERNS regex in solver.py attempts to enumerate
    dangerous code patterns. This is a classic blacklist approach that:
    - Can miss variations of dangerous patterns
    - Is hard to maintain as new attack vectors emerge
    - Should be replaced with AST-based whitelist or sandboxed execution

    Issue #180: This should use a whitelist approach (only allow safe patterns)
    or proper AST analysis with a sandbox, not regex pattern matching.
    """
    path = _SRC / "core" / "solver.py"
    tree = _parse(path)

    violations: list[str] = []

    for node in ast.walk(tree):
        # Look for _DANGEROUS_PATTERNS assignment
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "_DANGEROUS_PATTERNS":
                    violations.append(
                        f"{_rel(path)}:{node.lineno}: "
                        "_DANGEROUS_PATTERNS is a regex blacklist for input validation. "
                        "Use AST-based whitelist or sandbox instead (issue #180)"
                    )

    assert violations == [], "\n".join(violations)
