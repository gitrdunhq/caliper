"""Fail-closed regression guard for the parting decision path (#525).

# tested-by: tests/unit/test_part_fail_closed_guard.py

WHY.md documents one deliberate exception to caliper's otherwise fail-open
design: "`caliper part` is fail-closed... a missing input, a classifier
timeout, or any partial result would silently change the cut and break the
determinism guarantee. There, a degraded input is a hard error, not a
continue." This is a single AST walk over the parting pipeline that turns
that promise into a mechanically enforced invariant instead of a one-time
manual audit:

- The actual decision path (``core/part_stock.py``, ``core/parting.py``,
  ``core/part_gate.py``, ``cli/part_script.py``, ``cli/part_pipeline.py``)
  must contain ZERO exception-swallowing patterns — no ``except`` clause
  that doesn't re-raise, no ``allow_fail=True``. A degraded input here must
  always be a hard error.
- The PR-resolution plumbing (``cli/part_pr.py``, ``cli/part_push.py``) is
  legitimately fail-open in specific, already-audited spots (best-effort
  origin-slug/base-branch detection, jj init fallback, a non-fatal
  stack-linking-comment failure) — none of these affect cut correctness.
  Those sites are allowed, but ONLY when the enclosing function's own source
  visibly says why (a "fail-open" comment/docstring line) — an un-justified
  new swallow anywhere in these two files still fails the test.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

_STRICT_FILES = [
    "core/part_stock.py",
    "core/parting.py",
    "core/part_gate.py",
    "core/part_script.py",
    "cli/part_pipeline.py",
]

_JUSTIFY_FILES = [
    "cli/part_pr.py",
    "cli/part_push.py",
]

_JUSTIFICATION_MARKER = "fail-open"


def _handler_swallows(handler: ast.ExceptHandler) -> bool:
    """True if this except handler does not re-raise anywhere in its body."""
    return not any(isinstance(n, ast.Raise) for n in ast.walk(handler))


def _dict_has_allow_fail_true(node: ast.Dict) -> bool:
    for key, value in zip(node.keys, node.values):
        if (
            isinstance(key, ast.Constant)
            and key.value == "allow_fail"
            and isinstance(value, ast.Constant)
            and value.value is True
        ):
            return True
    return False


def _call_has_allow_fail_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "allow_fail" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _find_swallow_sites(func: ast.AST) -> list[tuple[str, int]]:
    """Return (kind, lineno) for every swallowing except / allow_fail=True
    site found anywhere inside ``func``'s own subtree."""
    sites: list[tuple[str, int]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.ExceptHandler) and _handler_swallows(node):
            sites.append(("except", node.lineno))
        elif (
            isinstance(node, ast.Call)
            and _call_has_allow_fail_true(node)
            or isinstance(node, ast.Dict)
            and _dict_has_allow_fail_true(node)
        ):
            sites.append(("allow_fail", node.lineno))
    return sites


def _top_level_functions(tree: ast.Module) -> list[ast.AST]:
    """Module-level and class-level function defs (not nested closures) —
    enough granularity to attribute a "fail-open" justification to the right
    function without over- or under-matching across unrelated functions."""
    out: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(node)
    return out


def _rel(path: Path) -> str:
    return str(path.relative_to(_SRC))


def test_strict_files_have_zero_swallow_sites() -> None:
    violations: list[str] = []
    for rel in _STRICT_FILES:
        path = _SRC / rel
        tree = ast.parse(path.read_text(), filename=str(path))
        for func in _top_level_functions(tree):
            for kind, lineno in _find_swallow_sites(func):
                violations.append(f"{rel}:{lineno} ({kind}) in {func.name}()")
    assert not violations, (
        "The parting decision path must be fail-closed (WHY.md) — found "
        f"exception-swallowing or allow_fail=True with no re-raise: {violations}"
    )


def test_justify_files_require_a_fail_open_comment_on_every_swallow_site() -> None:
    violations: list[str] = []
    for rel in _JUSTIFY_FILES:
        path = _SRC / rel
        source = path.read_text()
        tree = ast.parse(source, filename=str(path))
        for func in _top_level_functions(tree):
            sites = _find_swallow_sites(func)
            if not sites:
                continue
            func_source = ast.get_source_segment(source, func) or ""
            if _JUSTIFICATION_MARKER not in func_source.lower():
                for kind, lineno in sites:
                    violations.append(
                        f"{rel}:{lineno} ({kind}) in {func.name}() has no "
                        f"{_JUSTIFICATION_MARKER!r} justification anywhere in the function"
                    )
    assert not violations, (
        "A new or un-justified fail-open pattern was found in the PR-resolution "
        f"plumbing — add a comment/docstring line naming why it's safe: {violations}"
    )


def test_strict_and_justify_file_lists_exist() -> None:
    """Guard the guard: a renamed/moved target file should fail loudly, not
    silently stop being checked."""
    missing = [rel for rel in (*_STRICT_FILES, *_JUSTIFY_FILES) if not (_SRC / rel).is_file()]
    assert not missing, f"Guarded file(s) no longer exist at the expected path: {missing}"
