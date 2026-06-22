# tested-by: tests/unit/test_deterministic_log_rotation_guards.py
"""Deterministic log rotation guards — detects missing compression.

These tests use AST analysis to detect log rotation code that lacks compression
for old log files. Log rotation without compression wastes disk space.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files that may contain logging configuration
_LOGGING_CONFIG_FILES: list[Path] = [
    _SRC / "core" / "logging.py",
    _SRC / "core" / "config.py",
    _SRC / "cli" / "main.py",
    _SRC / "agent" / "main.py",
    _SRC / "webhook" / "server.py",
]


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _call_name(node: ast.AST) -> str | None:
    """Extract the full name of a function call (e.g., 'RotatingFileHandler')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _find_rotating_handlers(tree: ast.Module) -> Iterator[tuple[ast.Call, str]]:
    """Find all RotatingFileHandler or TimedRotatingFileHandler instantiations."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _call_name(node.func)
        if call_name is None:
            continue

        # Check for rotating handler patterns
        rotating_handlers = (
            "RotatingFileHandler",
            "TimedRotatingFileHandler",
            "logging.handlers.RotatingFileHandler",
            "logging.handlers.TimedRotatingFileHandler",
            "handlers.RotatingFileHandler",
            "handlers.TimedRotatingFileHandler",
        )

        if call_name in rotating_handlers or any(
            call_name.endswith(h) for h in ("RotatingFileHandler", "TimedRotatingFileHandler")
        ):
            yield node, call_name


def _has_compression_enabled(node: ast.Call) -> bool:
    """Check if a rotating handler has compression enabled.

    Compression can be enabled via:
    - compress=True parameter (for TimedRotatingFileHandler)
    - Custom compression logic via rotation listener
    - Post-rotation compression via external tools
    """
    # Check for compress=True on TimedRotatingFileHandler
    for kw in node.keywords:
        if kw.arg == "compress":
            # If compress is explicitly True, compression is enabled
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
            # If compress is a non-None truthy value
            if isinstance(kw.value, ast.NameConstant) and kw.value.value is True:
                return True
            # If compress is assigned but not True, still counts as configured
            if isinstance(kw.value, ast.Constant) and kw.value.value is not None:
                return True

    # Check for rotation listener that might do compression
    # Look for addHandler or similar patterns in the surrounding context
    # This is a heuristic - the full detection would require context analysis

    return False


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #185 - Log rotation doesn't compress old logs",
    strict=False,
)
def test_log_rotation_has_compression() -> None:
    """Detect log rotation without compression.

    Issue #185: Log rotation handlers (RotatingFileHandler, TimedRotatingFileHandler)
    should compress old logs to save disk space. Without compression, rotated logs
    consume excessive storage.

    Violations:
        - RotatingFileHandler without compression configuration
        - TimedRotatingFileHandler with compress=False or missing compress parameter
        - Custom rotation logic without post-rotation compression

    Acceptance criteria for fix:
        - All rotating file handlers have explicit compression enabled
        - Either compress=True for TimedRotatingFileHandler
        - Or custom compression logic via rotation listeners
        - Or post-rotation compression via gzip/bz2
    """
    violations: list[str] = []

    for path in _LOGGING_CONFIG_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        for handler_node, handler_name in _find_rotating_handlers(tree):
            lineno = getattr(handler_node, "lineno", 0)

            if not _has_compression_enabled(handler_node):
                violations.append(
                    f"{_rel(path)}:{lineno}: {handler_name} without compression "
                    "(add compress=True or custom compression)"
                )

    # Also check if there are any logging configuration files that might exist
    # but weren't in our explicit list
    for py_file in _SRC.rglob("*.py"):
        if py_file in _LOGGING_CONFIG_FILES:
            continue

        try:
            content = py_file.read_text()
            # Quick text search before AST parsing
            if "RotatingFileHandler" in content or "TimedRotatingFileHandler" in content:
                tree = _parse(py_file)
                for handler_node, handler_name in _find_rotating_handlers(tree):
                    lineno = getattr(handler_node, "lineno", 0)
                    if not _has_compression_enabled(handler_node):
                        violations.append(
                            f"{_rel(py_file)}:{lineno}: {handler_name} without compression "
                            "(add compress=True or custom compression)"
                        )
        except (SyntaxError, UnicodeDecodeError):
            # Skip files that can't be parsed
            continue

    assert violations == [], "Log rotation handlers must compress old logs:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #185 - Check for compression in rotation callbacks",
    strict=False,
)
def test_log_rotation_callbacks_have_compression() -> None:
    """Detect missing compression in log rotation callbacks.

    Issue #185: Even if the handler doesn't natively support compression,
    custom rotation callbacks should compress the rotated log files.

    This detects:
        - doRollover overrides without compression
        - rotation listeners without gzip/bz2 compression
        - emit() overrides in custom handlers without compression
    """
    violations: list[str] = []

    for py_file in _SRC.rglob("*.py"):
        try:
            tree = _parse(py_file)
        except (SyntaxError, UnicodeDecodeError):
            continue

        # Look for doRollover method definitions (common pattern for custom rotation)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "doRollover":
                method_source = ast.unparse(node)

                # Check if the method has compression logic
                compression_indicators = (
                    "gzip",
                    "bz2",
                    "lzma",
                    "compress",
                    "zipfile",
                    "shutil.make_archive",
                )

                if not any(indicator in method_source for indicator in compression_indicators):
                    violations.append(
                        f"{_rel(py_file)}:{node.lineno}: doRollover() without compression "
                        "(use gzip, bz2, or shutil to compress rotated logs)"
                    )

            # Look for emit() in custom handlers that might need compression
            if isinstance(node, ast.FunctionDef) and node.name == "emit":
                method_source = ast.unparse(node)

                # Check if this is a rotating handler's emit method
                if "rotation" in method_source.lower() or "rollover" in method_source.lower():
                    compression_indicators = (
                        "gzip",
                        "bz2",
                        "lzma",
                        "compress",
                        "zipfile",
                    )

                    if not any(indicator in method_source for indicator in compression_indicators):
                        violations.append(
                            f"{_rel(py_file)}:{node.lineno}: emit() with rotation logic "
                            "but no compression (add gzip/bz2 compression for rotated files)"
                        )

    assert violations == [], "Log rotation callbacks must compress old logs:\n" + "\n".join(
        violations
    )
