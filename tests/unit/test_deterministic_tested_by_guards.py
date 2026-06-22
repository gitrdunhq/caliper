# tested-by: tests/unit/test_deterministic_tested_by_guards.py
"""Deterministic detector for tested-by annotation issues (#258).

This test verifies that every source file in src/ has a valid tested-by annotation
and that those annotations point to existing test files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# This is a deterministic bug detector — it will fail until all source files
# have proper tested-by annotations pointing to existing test files.
pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — add tested-by annotations to fix",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Regex to find tested-by annotations
_TESTED_BY_RE = re.compile(r"#\s*tested-by:\s*([^\s,\n]+)", re.MULTILINE)


def _python_files(root: Path) -> list[Path]:
    """Return all Python files under root, excluding __pycache__."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    """Return repository-relative path as posix string."""
    return path.relative_to(_REPO).as_posix()


def _find_tested_by_annotations(file_content: str) -> list[str]:
    """Extract all tested-by references from file content."""
    return _TESTED_BY_RE.findall(file_content)


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_all_source_files_have_tested_by_annotations() -> None:
    """#258: every source file must have a tested-by annotation.

    This test scans all Python files in src/caliper/ and verifies:
    1. Each file has at least one tested-by annotation
    2. Each annotation points to a path that exists under tests/
    3. Each referenced test file actually exists in the repo
    """
    missing_annotations: list[str] = []
    stale_references: list[str] = []
    invalid_paths: list[str] = []

    for source_file in _python_files(_SRC):
        content = source_file.read_text()
        rel_path = _rel(source_file)

        # Find all tested-by annotations
        refs = _find_tested_by_annotations(content)

        if not refs:
            missing_annotations.append(rel_path)
            continue

        for ref in refs:
            # Verify it starts with tests/
            if not ref.startswith("tests/"):
                invalid_paths.append(f"{rel_path}: tested-by '{ref}' does not start with 'tests/'")
                continue

            # Verify the referenced file exists
            test_file = _REPO / ref
            if not test_file.exists():
                stale_references.append(
                    f"{rel_path}: tested-by '{ref}' points to non-existent file"
                )

    # Build detailed failure message
    failures: list[str] = []
    if missing_annotations:
        failures.append(
            f"\nMissing tested-by annotations ({len(missing_annotations)} files):\n"
            + "\n".join(f"  - {p}" for p in missing_annotations)
        )
    if invalid_paths:
        failures.append(
            "\nInvalid tested-by paths (must start with 'tests/'):\n"
            + "\n".join(f"  - {p}" for p in invalid_paths)
        )
    if stale_references:
        failures.append(
            "\nStale tested-by references (target test does not exist):\n"
            + "\n".join(f"  - {p}" for p in stale_references)
        )

    assert not (missing_annotations or stale_references or invalid_paths), (
        "Found tested-by annotation issues. "
        "Every source file must have a valid # tested-by: tests/unit/test_xxx.py annotation.\n"
        + "\n".join(failures)
    )
