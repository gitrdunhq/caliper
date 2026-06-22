# tested-by: tests/unit/test_deterministic_evidence_guards.py
"""Deterministic evidence integrity guards for known bug classes.

These tests intentionally encode evidence invariants as static checks.
They may fail while the corresponding bugs are still open.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_SEAL_FILE = _SRC / "core" / "seal.py"
_EVIDENCE_FILE = _SRC / "data" / "evidence.py"


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


def _get_function_body(tree: ast.Module, func_name: str) -> list[ast.stmt]:
    """Extract the body statements of a named function."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node.body
    return []


def _contains_call(body: list[ast.stmt], call_name: str) -> bool:
    """Check if any statement in the body contains a call to the named function."""
    for stmt in body:
        for child in ast.walk(stmt):
            if isinstance(child, ast.Call):
                # Check for direct name call
                if isinstance(child.func, ast.Name) and child.func.id == call_name:
                    return True
                # Check for attribute call (e.g., path.rglob)
                if isinstance(child.func, ast.Attribute) and child.func.attr == call_name:
                    return True
    return False


def _contains_iterdir_or_rglob(body: list[ast.stmt]) -> bool:
    """Check if body iterates over directory contents (iterdir or rglob)."""
    return _contains_call(body, "iterdir") or _contains_call(body, "rglob")


def _contains_unexpected_file_check(body: list[ast.stmt]) -> bool:
    """Check if body explicitly checks for unexpected/extra files."""
    source = ast.unparse(body)
    # Look for checks that compare actual files against expected manifest
    check_terms = [
        "unexpected",
        "extra",
        "additional",
        "surplus",
        "not in manifest",
        "not in artifacts",
        "len(",
        "count",
    ]
    return any(term in source.lower() for term in check_terms)


def test_verify_seal_checks_for_unexpected_files() -> None:
    """#264: Evidence seal verification must detect unexpected added files.

    The verify_seal function should check that the evidence directory contains
    exactly the files listed in the manifest — no more, no less. Currently it
    only validates the files in the manifest, ignoring any extra files that
    may have been added.
    """
    tree = _parse(_SEAL_FILE)
    body = _get_function_body(tree, "verify_seal")

    # The fix requires two things:
    # 1. Iterating over actual directory contents (to find all files)
    # 2. Checking those against the manifest (to detect unexpected files)

    has_directory_iteration = _contains_iterdir_or_rglob(body)
    has_unexpected_file_check = _contains_unexpected_file_check(body)

    violations: list[str] = []

    if not has_directory_iteration:
        violations.append(
            f"{_rel(_SEAL_FILE)}: verify_seal does not iterate over directory contents "
            "(needed to find all files including unexpected ones)"
        )

    if not has_unexpected_file_check:
        violations.append(
            f"{_rel(_SEAL_FILE)}: verify_seal does not check for unexpected/extra files "
            "that are not in the manifest"
        )

    assert not violations, (
        "Seal verification must detect unexpected added files by:\n"
        "1. Iterating over actual directory contents\n"
        "2. Comparing against the manifest to find extra files\n\n" + "\n".join(violations)
    )


def _find_unencrypted_zip_usage(tree: ast.Module) -> list[str]:
    """Find ZipFile usage without encryption (pwd parameter).

    Returns list of violation messages with line numbers.
    """
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            # Check for 'with zipfile.ZipFile(...) as zf:' pattern
            for item in node.items:
                ctx_expr = item.context_expr
                if isinstance(ctx_expr, ast.Call):
                    # Check if it's a ZipFile call
                    is_zipfile = (
                        isinstance(ctx_expr.func, ast.Name) and ctx_expr.func.id == "ZipFile"
                    ) or (
                        isinstance(ctx_expr.func, ast.Attribute) and ctx_expr.func.attr == "ZipFile"
                    )

                    if is_zipfile:
                        # Check for encryption: look for 'pwd' keyword argument
                        has_encryption = False
                        for kw in ctx_expr.keywords:
                            if kw.arg == "pwd":
                                has_encryption = True
                                break

                        if not has_encryption:
                            violations.append(
                                f"{_rel(_EVIDENCE_FILE)}:{node.lineno}: "
                                "ZipFile used without encryption (pwd parameter). "
                                "Use pyzipper with AES encryption for sensitive evidence."
                            )

    return violations


def test_189_evidence_compression_uses_encryption() -> None:
    """#189/#223: Evidence compression must use encrypted zip, not plain zip.

    Issue #189: Evidence compression uses zip without encryption for sensitive data.
    When compressing evidence artifacts, the zip file must be encrypted to protect
    sensitive data at rest. Standard zip encryption is weak; use pyzipper with
    AES256 encryption instead.

    Violations:
        - src/caliper/data/evidence.py uses zipfile.ZipFile without pwd parameter

    Acceptance criteria for fix:
        - All ZipFile calls include encryption (pwd parameter)
        - Use pyzipper.AESZipFile with AES256 encryption for new compression code
        - Remove or upgrade any standard zipfile usage with sensitive data
    """
    if not _EVIDENCE_FILE.exists():
        pytest.skip(f"Evidence file not found: {_EVIDENCE_FILE}")

    tree = _parse(_EVIDENCE_FILE)
    violations = _find_unencrypted_zip_usage(tree)

    assert not violations, (
        "Evidence compression must use encryption for sensitive data:\n"
        "- Standard zipfile.ZipFile without pwd is not secure\n"
        "- Use pyzipper.AESZipFile with AES256 encryption\n"
        "- Pass pwd parameter to enable encryption\n\n" + "\n".join(violations)
    )
