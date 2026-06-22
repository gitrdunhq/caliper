# tested-by: tests/unit/test_deterministic_upload_guards.py
"""Deterministic upload guards for MIME type validation.

These tests use AST analysis to detect file upload code that does not validate
MIME type against file extension. When violations are fixed, the test will
"pass" and xfail will report an XPASS, at which point the xfail marker should
be removed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Set

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files where file uploads should validate MIME type against extension (issue #178)
# These are entry points that handle user-provided file uploads
_UPLOAD_BOUNDARY_FILES: tuple[Path, ...] = (_SRC / "webhook" / "server.py",)

# File handling patterns that indicate potential upload handling
_UPLOAD_FUNCTION_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"upload", re.IGNORECASE),
    re.compile(r"file.*receive|receive.*file", re.IGNORECASE),
    re.compile(r"handle.*file|file.*handle", re.IGNORECASE),
    re.compile(r"multipart", re.IGNORECASE),
)

# MIME validation patterns - indicators that MIME type is being validated
_MIME_VALIDATION_INDICATORS: Set[str] = {
    "mimetypes",
    "mime",
    "content_type",
    "content-type",
    "magic",
    "filetype",
    "python-magic",
    "puremagic",
}

# Extension validation patterns
_EXTENSION_VALIDATION_INDICATORS: Set[str] = {
    "endswith",
    "splitext",
    "suffix",
    "extension",
    "pathlib",
    "os.path.splitext",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _is_upload_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if a function appears to handle file uploads based on its name."""
    func_name = node.name.lower()
    return any(pattern.search(func_name) for pattern in _UPLOAD_FUNCTION_PATTERNS)


def _contains_file_parameter(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check if function has parameters that suggest file handling."""
    all_args = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    if node.args.vararg:
        all_args.append(node.args.vararg)
    if node.args.kwarg:
        all_args.append(node.args.kwarg)

    file_patterns = re.compile(r"file|upload|blob|content|data", re.IGNORECASE)
    return any(file_patterns.search(arg.arg) for arg in all_args)


def _has_mime_validation(body: list[ast.stmt]) -> bool:
    """Check if function body contains MIME type validation."""
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        # Check for mimetypes module usage
        if isinstance(node, ast.Name) and node.id in _MIME_VALIDATION_INDICATORS:
            return True
        # Check for attribute access like mimetypes.guess_type
        if isinstance(node, ast.Attribute):
            if node.attr in _MIME_VALIDATION_INDICATORS:
                return True
            # Check for methods like guess_type, guess_extension
            if node.attr in {"guess_type", "guess_extension", "from_buffer", "from_file"}:
                return True
        # Check for string literals containing MIME type patterns
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(indicator in node.value.lower() for indicator in _MIME_VALIDATION_INDICATORS):
                return True
    return False


def _has_extension_validation(body: list[ast.stmt]) -> bool:
    """Check if function body contains file extension validation."""
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        # Check for common extension validation methods
        if isinstance(node, ast.Attribute):
            if node.attr in _EXTENSION_VALIDATION_INDICATORS:
                return True
        # Check for string methods like endswith('.jpg')
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in {"endswith", "startswith"}:
                    return True
    return False


def _has_mime_extension_comparison(body: list[ast.stmt]) -> bool:
    """
    Check if function body compares MIME type against file extension.

    This is the key security check - ensuring that the declared content type
    matches the actual file extension to prevent file type spoofing attacks.
    """
    body_str = ast.unparse(ast.Module(body=body, type_ignores=[]))

    # Look for patterns that indicate MIME vs extension validation
    mime_vs_ext_patterns = [
        # mimetypes.guess_type compared with filename
        re.compile(r"guess_type.*extension|extension.*guess_type", re.IGNORECASE),
        # content-type compared with file extension
        re.compile(r"content.type.*extension|extension.*content.type", re.IGNORECASE),
        # MIME type validation before processing
        re.compile(r"mime.*valid|valid.*mime", re.IGNORECASE),
    ]

    for pattern in mime_vs_ext_patterns:
        if pattern.search(body_str):
            return True

    # Check for both MIME and extension validation in the same function
    has_mime = _has_mime_validation(body)
    has_ext = _has_extension_validation(body)

    # If both exist, assume they're being compared (conservative approach)
    return bool(has_mime and has_ext)


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #178 - file uploads must validate MIME type against extension",
    strict=False,
)
def test_178_file_uploads_validate_mime_type_against_extension() -> None:
    """Detect file upload code that lacks MIME type vs extension validation.

    Issue #178: File upload handlers must validate that the declared MIME type
    matches the file extension to prevent file type spoofing attacks.

    Security risk: Attackers can upload malicious files with spoofed extensions
    (e.g., malware.exe renamed to report.pdf.exe) or incorrect MIME types that
    bypass security filters while being executed by the application.

    Violations:
        - File upload handlers that don't check MIME type
        - Upload handlers that don't compare MIME type against file extension
        - Missing validation between Content-Type header and actual file extension

    Acceptance criteria for fix:
        - All file upload functions validate MIME type using mimetypes or magic
        - Upload handlers compare declared MIME type against file extension
        - Mismatches between MIME type and extension are rejected
    """
    violations: list[str] = []

    for path in _UPLOAD_BOUNDARY_FILES:
        if not path.exists():
            violations.append(f"{_rel(path)}: file does not exist")
            continue

        tree = _parse(path)

        for node in ast.walk(tree):
            # Check function definitions for upload handling
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Skip if not an upload-related function
            if not (_is_upload_function(node) or _contains_file_parameter(node)):
                continue

            # Check if this function validates MIME against extension
            if not _has_mime_extension_comparison(node.body):
                func_name = node.name
                violations.append(
                    f"{_rel(path)}:{node.lineno}: "
                    f"{func_name}() handles file uploads but lacks MIME type vs extension validation "
                    f"(needed to prevent file type spoofing attacks)"
                )

    assert violations == [], (
        "File upload handlers must validate MIME type against file extension:\n"
        + "\n".join(violations)
        + "\n\nFix: Use mimetypes.guess_type() or python-magic to validate that the "
        "declared content type matches the actual file extension."
    )
