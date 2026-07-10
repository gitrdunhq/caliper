"""Shared helpers used by more than one CLI command module."""

# tested-by: tests/unit/test_cli.py

from __future__ import annotations

import sys
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Source-file suffixes the review/audit commands enumerate. Centralised so the
# file source (git ls-files vs. walk) is the single place that decides *which*
# files exist, and these decide which extensions we care about.
_REVIEW_SUFFIXES: tuple[str, ...] = (
    ".py",
    ".ts",
    ".js",
    ".tf",
    ".yaml",
    ".yml",
    ".json",
    ".swift",
)
_AUDIT_SUFFIXES: tuple[str, ...] = tuple(s for s in _REVIEW_SUFFIXES if s != ".swift")


def _collect_repo_files(
    root: Path, suffixes: tuple[str, ...], *, prefer: str | None = None
) -> list[str]:
    """Enumerate scannable files under *root* via the resolved file source.

    Replaces the ad-hoc ``rglob(ext)`` + ``should_ignore`` loops; the source
    (git ls-files when *root* is a usable repo, else an ignore-aware walk)
    applies caliper's exclusion rules uniformly.
    """
    from caliper.core.file_source import select_file_source

    source = select_file_source(root, prefer=prefer)
    return [str(p) for p in source.list_files(root, suffixes=suffixes)]


def _write_output(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _read_diff(diff_path: str) -> str:
    if diff_path == "-":
        return (
            sys.stdin.read()
        )  # nosemgrep: file-read-all-python — diff content must be fully buffered for parsing
    path = Path(diff_path)
    if not path.exists():
        logger.warning("diff_file_not_found", path=diff_path)
        return ""
    return path.read_text()
