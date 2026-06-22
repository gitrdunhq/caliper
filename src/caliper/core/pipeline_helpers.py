"""Pipeline helper functions — extracted to keep pipeline.py under 500 lines.
# tested-by: tests/unit/test_pipeline.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import structlog

from caliper.core.diff import DependencyDiffDetector
from caliper.core.models import (
    OperatingMode,
    RequestType,
    ReviewRequest,
    ScanResult,
    ScanResultStatus,
)

logger = structlog.get_logger(__name__)


def resolve_git_sha(repo_path: Path) -> str | None:
    """Get the HEAD commit SHA from the repo. Returns None if not a git repo."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        logger.debug("resolve_git_sha.failed", repo_path=str(repo_path))
    return None


def count_transitive_deps_from_scan(scan_results: list[ScanResult]) -> int | None:
    """Extract transitive dependency count from the Syft SBOM scan result."""
    for result in scan_results:
        if result.tool_name == "syft" and result.status == ScanResultStatus.success:
            msg = result.message or ""
            if "components detected" in msg:
                try:
                    return int(msg.split(":")[1].split("components")[0].strip())
                except (ValueError, IndexError):
                    pass
    return None


def _parse_single_file(
    basename: str,
    fpath: str,
    before_content: str,
    after_content: str,
    detector: DependencyDiffDetector | None = None,
) -> list[dict]:
    """Parse dependency changes for a single file given before/after content."""
    if basename in ("requirements.txt", "requirements-dev.txt"):
        d = detector or DependencyDiffDetector()
        return d.parse_requirements_diff(before_content, after_content)
    if basename == "pyproject.toml":
        d = detector or DependencyDiffDetector()
        changes = d.parse_pyproject_diff(before_content, after_content)
        # Fall back to sentinel when TOML parse fails but content changed
        if not changes and before_content != after_content:
            return [
                {
                    "package_name": "(manifest:pyproject.toml)",
                    "version": None,
                    "ecosystem": "python",
                    "change_type": "manifest_changed",
                    "source_file": fpath,
                }
            ]
        return changes
    if basename in ("setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock"):
        # These manifests changed — flag for SBOM diff review.
        # A full parser per format is tracked in #210; for now we signal that
        # the manifest changed so the pipeline routes to SBOM-based evaluation.
        if before_content != after_content:
            return [
                {
                    "package_name": f"(manifest:{basename})",
                    "version": None,
                    "ecosystem": "python",
                    "change_type": "manifest_changed",
                    "source_file": fpath,
                }
            ]
        return []
    logger.warning("unsupported_dependency_file", file=fpath, basename=basename)
    return []


def parse_changes(
    detector: DependencyDiffDetector | None = None,
    diff_text: str | None = None,
    changed_files: list[str] | None = None,
    *,
    before_content: str | None = None,
    after_content: str | None = None,
    file_path: str | None = None,
) -> list[dict]:
    """Parse dependency changes from a diff or from per-file before/after content.

    Two calling conventions are supported:

    1. Per-file (new): ``parse_changes(before_content=..., after_content=..., file_path=...)``
    2. Full-diff (legacy): ``parse_changes(detector, diff_text, changed_files)``
    """
    # Per-file API
    if before_content is not None and file_path is not None:
        basename = file_path.rsplit("/", maxsplit=1)[-1] if "/" in file_path else file_path
        return _parse_single_file(
            basename, file_path, before_content, after_content or "", detector
        )

    # Legacy full-diff API
    if detector is None or diff_text is None or changed_files is None:
        return []

    all_changes: list[dict] = []
    for fpath in changed_files:
        basename = fpath.rsplit("/", maxsplit=1)[-1] if "/" in fpath else fpath
        bc, ac = detector.extract_file_content_from_diff(diff_text, fpath)
        all_changes.extend(_parse_single_file(basename, fpath, bc, ac, detector))
    return all_changes


def sbom_changes_to_requests(
    changes: list[dict],
    team: str,
    pr_url: str | None,
    operating_mode: OperatingMode,
) -> list[ReviewRequest]:
    """Convert SBOM diff change dicts into ReviewRequest objects."""
    requests: list[ReviewRequest] = []

    for change in changes:
        action = change["action"]
        if action == "removed":
            continue

        req_type = RequestType.new_package if action == "added" else RequestType.upgrade
        current_version = change.get("old_version") if action != "added" else None
        target_version = change.get("new_version") or "unknown"

        requests.append(
            ReviewRequest(
                request_type=req_type,
                ecosystem=change.get("ecosystem", "unknown"),
                package_name=change["package"],
                target_version=target_version,
                current_version=current_version,
                team=team,
                pr_url=pr_url,
                operating_mode=operating_mode,
            )
        )

    return requests
