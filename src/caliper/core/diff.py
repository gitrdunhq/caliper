"""Dependency diff detection -- identifies changed packages from git diffs.
# tested-by: tests/unit/test_diff.py

Parses git diff output and dependency file contents (requirements.txt,
pyproject.toml) to detect added, removed, upgraded, and downgraded packages.
"""

from __future__ import annotations

import json
import re
import tomllib

import structlog
from packaging.version import InvalidVersion, Version  # noqa: F401

from caliper.core.models import (
    OperatingMode,
    RequestType,
    ReviewRequest,
)

logger = structlog.get_logger(__name__)

# Dependency file basenames that indicate a dependency change
_DEPENDENCY_FILES = frozenset(
    {
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "package.json",
        "package-lock.json",
    }
)

# Leading npm version-range operators stripped to recover a concrete version.
_NPM_RANGE_RE = re.compile(r"^[\^~>=<\s]+")
# A "name": "spec" line in package.json (used for the diff-fragment fallback).
_NPM_DEP_LINE_RE = re.compile(r'"([^"]+)"\s*:\s*"([^"]+)"')
# package.json top-level string fields that are NOT dependencies.
_NPM_NON_DEP_KEYS = frozenset(
    {"version", "name", "license", "main", "types", "module", "author", "description", "homepage"}
)
# A value that plausibly denotes a version/range (vs. a URL, path, or free text).
_NPM_VERSION_VALUE_RE = re.compile(r"^[\^~>=<]*\d")

# Regex to extract file paths from unified diff headers
_DIFF_FILE_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)$", re.MULTILINE)

# Regex to parse a requirements.txt line into package name and version
# Handles: package==1.0, package>=1.0, package[extra]==1.0, package~=1.0
_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9][\w.-]*)"  # package name
    r"(?:\[[^\]]+\])?"  # optional extras like [security]
    r"(?:[><=!~]+(.+))?"  # optional version specifier
    r"$"
)


def _parse_requirement_line(line: str) -> tuple[str, str | None] | None:
    """Parse a single requirements.txt line into (package_name, version).

    Returns None for comments, blank lines, and unparseable lines.
    The version is the raw version string after the operator, or None
    if no version is pinned.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
        return None

    match = _REQ_LINE_RE.match(stripped)
    if not match:
        return None

    pkg = match.group(1).lower()
    version = match.group(2)
    if version:
        version = version.strip()
    return (pkg, version if version else None)


def _parse_requirements(content: str) -> dict[str, str | None]:
    """Parse requirements.txt content into {package: version} dict."""
    result: dict[str, str | None] = {}
    for line in content.splitlines():
        parsed = _parse_requirement_line(line)
        if parsed is not None:
            result[parsed[0]] = parsed[1]
    return result


def _parse_pyproject_deps(content: str) -> dict[str, str | None]:
    """Parse [project.dependencies] from pyproject.toml content.

    Returns {package: version} dict. Version is extracted from the
    version specifier if present.
    """
    try:
        data = tomllib.loads(content)
    except Exception:
        logger.warning("pyproject_toml_parse_failed", exc_info=True)
        return {}

    deps = data.get("project", {}).get("dependencies", [])
    result: dict[str, str | None] = {}

    for dep_str in deps:
        parsed = _parse_requirement_line(dep_str)
        if parsed is not None:
            result[parsed[0]] = parsed[1]

    return result


def _clean_npm_version(spec: str | None) -> str | None:
    """Strip leading range operators (``^``, ``~``, ``>=`` …) to a concrete version.

    Returns None for empty/non-pinned specs that cannot map to a single version
    (``*``, ``latest``, git/file/workspace URLs); the caller fetch fails open on those.
    """
    if not spec:
        return None
    cleaned = _NPM_RANGE_RE.sub("", spec.strip())
    if not cleaned or cleaned in {"*", "latest", "x"}:
        return None
    if any(tok in cleaned for tok in (":", "/", " ", "||")):
        return None  # git/file/workspace URL or compound range — not a single version
    return cleaned


def _parse_package_json_deps(content: str) -> dict[str, str | None]:
    """Parse npm dependency maps from package.json into {package: version}.

    A unified diff usually yields only a *fragment* of package.json (the changed
    hunk), which is not valid JSON. So we try a full JSON parse first and fall
    back to a line-based scan of ``"name": "spec"`` entries that look like
    versions — robust to the partial content reconstructed from a diff.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return _parse_package_json_fragment(content)
    if not isinstance(data, dict):
        # Valid JSON but not a JSON *object* (bare number, string, list, bool,
        # or null) — fall back to the fragment scan instead of crashing with
        # AttributeError on ``data.get(...)`` below.
        return _parse_package_json_fragment(content)
    result: dict[str, str | None] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            result[str(name)] = _clean_npm_version(str(spec) if spec is not None else None)
    return result


def _parse_package_json_fragment(content: str) -> dict[str, str | None]:
    """Line-based fallback: pull ``"name": "version"`` pairs from a JSON fragment."""
    result: dict[str, str | None] = {}
    for line in content.splitlines():
        match = _NPM_DEP_LINE_RE.search(line)
        if not match:
            continue
        name, spec = match.group(1), match.group(2)
        if name in _NPM_NON_DEP_KEYS or not _NPM_VERSION_VALUE_RE.match(spec):
            continue
        result[name] = _clean_npm_version(spec)
    return result


def _compute_diff(before: dict[str, str | None], after: dict[str, str | None]) -> list[dict]:
    """Compare before/after package dicts and return a list of change dicts."""
    changes: list[dict] = []
    all_pkgs = set(before.keys()) | set(after.keys())

    for pkg in sorted(all_pkgs):
        old_ver = before.get(pkg)
        new_ver = after.get(pkg)
        in_before = pkg in before
        in_after = pkg in after

        if in_after and not in_before:
            changes.append(
                {
                    "action": "added",
                    "package": pkg,
                    "old_version": None,
                    "new_version": new_ver,
                }
            )
        elif in_before and not in_after:
            changes.append(
                {
                    "action": "removed",
                    "package": pkg,
                    "old_version": old_ver,
                    "new_version": None,
                }
            )
        elif old_ver != new_ver:
            # Both present but versions differ
            if old_ver is not None and new_ver is not None:
                try:
                    action = "upgraded" if Version(old_ver) < Version(new_ver) else "downgraded"
                except InvalidVersion:
                    logger.warning(
                        "version_parse_failed",
                        package=pkg,
                        old_version=old_ver,
                        new_version=new_ver,
                    )
                    action = "upgraded"
            elif old_ver is None and new_ver is not None:
                action = "upgraded"
            elif old_ver is not None and new_ver is None:
                action = "downgraded"
            else:
                action = "upgraded"

            changes.append(
                {
                    "action": action,
                    "package": pkg,
                    "old_version": old_ver,
                    "new_version": new_ver,
                }
            )

    return changes


class DependencyDiffDetector:
    """Detects dependency changes from git diffs and file contents."""

    def extract_file_content_from_diff(self, diff_text: str, filename: str) -> tuple[str, str]:
        """Extract before and after content for a file from a unified diff.

        Parses unified diff format. For the given filename:
        - ``before_content``: context lines + lines removed (``-`` prefix stripped)
        - ``after_content``: context lines + lines added (``+`` prefix stripped)

        Returns ``("", "")`` if the file is not present in the diff.
        """
        before_lines: list[str] = []
        after_lines: list[str] = []
        in_target: bool = False
        in_hunk: bool = False

        for line in diff_text.splitlines():
            if line.startswith("diff --git "):
                b_idx = line.rfind(" b/")
                b_path = line[b_idx + 3 :] if b_idx >= 0 else ""
                in_target = b_path == filename
                in_hunk = False
                continue

            if not in_target:
                continue

            if line.startswith("--- ") or line.startswith("+++ ") or line.startswith("index "):
                continue

            if line.startswith("@@"):
                in_hunk = True
                continue

            if in_hunk:
                if line.startswith("-"):
                    before_lines.append(line[1:])
                elif line.startswith("+"):
                    after_lines.append(line[1:])
                elif line.startswith(" "):
                    before_lines.append(line[1:])
                    after_lines.append(line[1:])

        return "\n".join(before_lines), "\n".join(after_lines)

    def detect_changed_files(self, diff_text: str) -> list[str]:
        """Find dependency files that changed in a git diff.

        Returns a list of changed file paths that match known dependency
        file patterns.
        """
        changed: list[str] = []
        seen: set[str] = set()

        for match in _DIFF_FILE_RE.finditer(diff_text):
            file_path = match.group(2)  # b/ side is the "after" path
            basename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path

            if basename in _DEPENDENCY_FILES and file_path not in seen:
                changed.append(file_path)
                seen.add(file_path)

        return changed

    def parse_requirements_diff(self, before: str, after: str) -> list[dict]:
        """Parse before/after requirements.txt content and identify changes.

        Returns list of dicts with keys: action, package, old_version, new_version.
        Actions: added, removed, upgraded, downgraded.
        """
        before_pkgs = _parse_requirements(before)
        after_pkgs = _parse_requirements(after)
        return _compute_diff(before_pkgs, after_pkgs)

    def parse_pyproject_diff(self, before: str, after: str) -> list[dict]:
        """Parse before/after pyproject.toml and identify dependency changes.

        Only looks at [project.dependencies]. Same output format as
        parse_requirements_diff.
        """
        before_pkgs = _parse_pyproject_deps(before)
        after_pkgs = _parse_pyproject_deps(after)
        return _compute_diff(before_pkgs, after_pkgs)

    def parse_package_json_diff(self, before: str, after: str) -> list[dict]:
        """Parse before/after package.json and identify dependency changes.

        Looks at dependencies, devDependencies, and optionalDependencies. Same
        output shape as parse_requirements_diff (versions stripped of range ops).
        """
        before_pkgs = _parse_package_json_deps(before)
        after_pkgs = _parse_package_json_deps(after)
        return _compute_diff(before_pkgs, after_pkgs)

    def create_requests(
        self,
        changes: list[dict],
        ecosystem: str,
        team: str,
        pr_url: str | None,
        operating_mode: OperatingMode,
    ) -> list[ReviewRequest]:
        """Convert change dicts into ReviewRequest objects.

        - added -> request_type=new_package
        - upgraded/downgraded -> request_type=upgrade (with current_version)
        - removed -> skipped (no review needed)
        """
        requests: list[ReviewRequest] = []

        for change in changes:
            action = change["action"]

            if action == "removed":
                continue

            if action == "added":
                req_type = RequestType.new_package
                current_version = None
            else:
                # upgraded or downgraded
                req_type = RequestType.upgrade
                current_version = change["old_version"]

            target_version = change["new_version"] or "unknown"

            requests.append(
                ReviewRequest(
                    request_type=req_type,
                    ecosystem=ecosystem,
                    package_name=change["package"],
                    target_version=target_version,
                    current_version=current_version,
                    team=team,
                    pr_url=pr_url,
                    operating_mode=operating_mode,
                )
            )

        return requests
