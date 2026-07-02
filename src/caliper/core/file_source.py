# tested-by: tests/unit/test_file_source.py
"""File-source adapters — one seam for "which files does caliper scan?".

Two strategies satisfy :class:`~caliper.core.ports.FileSourcePort`:

* :class:`GitLsFilesSource` (key ``"git"``) — ``git ls-files --cached --others
  --exclude-standard`` under the root. Tracked **plus** untracked-but-not-
  ``.gitignore``d files, so it respects ``.gitignore`` for free while still
  surfacing brand-new working-tree files a reviewer cares about.
* :class:`WalkFileSource` (key ``"walk"``) — ``os.walk`` with caliper's own
  ignore rules. The fail-open fallback for non-git targets (read-only mounts,
  tarball extracts, ``dom ../somedir``).

Both then apply the caliper exclusion layer (:mod:`caliper.core.ignore`) on top, so
tracked-but-not-ours paths (e.g. ``tests/e2e/fixtures``) are skipped regardless
of source. :func:`select_file_source` chooses git when the root is a usable git
repo and falls back to walk otherwise, with an ``CALIPER_FILE_SOURCE`` override.

This is the single place that decides enumeration; plugins, the CLI, and the
deterministic scanner consume the resolved port and never call ``rglob`` /
``os.walk`` / ``git`` themselves.
"""

from __future__ import annotations

import os
from pathlib import Path

import structlog

from caliper.core.ignore import load_ignore_patterns, should_ignore
from caliper.core.registries import FILE_SOURCES
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

logger = structlog.get_logger(__name__)

# Directories never worth descending into, mirrored from manifest_discovery so
# the walk source prunes them before fnmatch even runs.
_ALWAYS_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "vendor",
        ".claude",
        ".wfc",
        ".caliper",
        ".dogfood",
    }
)

_GIT_TIMEOUT = 30


def _matches_suffix(rel_posix: str, suffixes: tuple[str, ...] | None) -> bool:
    """Return True when *rel_posix* ends with one of *suffixes* (or no filter)."""
    if suffixes is None:
        return True
    return rel_posix.endswith(suffixes)


@FILE_SOURCES.register("walk")
class WalkFileSource:
    """Enumerate files via ``os.walk`` + caliper ignore rules (non-git fallback)."""

    name: str = "walk"

    def is_available(self, root: Path) -> bool:  # noqa: ARG002 - always usable
        return True

    def list_files(self, root: Path, *, suffixes: tuple[str, ...] | None = None) -> list[Path]:
        if not root.exists() or not root.is_dir():
            return []

        patterns = load_ignore_patterns(root)
        root_resolved = root.resolve()
        out: list[Path] = []

        for dirpath_str, dirnames, filenames in os.walk(root):
            dirpath = Path(dirpath_str)
            rel_dir = dirpath.relative_to(root)

            # Prune ignored / always-skip directories in-place.
            kept: list[str] = []
            for d in sorted(dirnames):
                if d in _ALWAYS_SKIP_DIRS:
                    continue
                child_rel = (rel_dir / d).as_posix()
                if should_ignore(child_rel + "/", patterns):
                    continue
                kept.append(d)
            dirnames[:] = kept

            for filename in filenames:
                rel = (rel_dir / filename).as_posix()
                if not _matches_suffix(rel, suffixes):
                    continue
                if should_ignore(rel, patterns):
                    continue
                full = dirpath / filename
                # Reject paths escaping the root via symlink.
                try:
                    full.resolve().relative_to(root_resolved)
                except ValueError:
                    continue
                out.append(full)

        return sorted(out)


@FILE_SOURCES.register("git")
class GitLsFilesSource:
    """Enumerate files via ``git ls-files`` (tracked + untracked-not-ignored)."""

    name: str = "git"

    def __init__(self, runner: ToolRunnerPort | None = None) -> None:
        self._runner: ToolRunnerPort = runner or SubprocessToolRunner()

    def is_available(self, root: Path) -> bool:
        """True when *root* is inside a git work tree and git can run."""
        if not (root / ".git").exists():
            return False
        result = self._runner.run(
            ToolInvocation(
                cmd=[*self._git_base(root), "rev-parse", "--is-inside-work-tree"],
                cwd=str(root),
                timeout=_GIT_TIMEOUT,
            )
        )
        return result.exit_code == 0 and result.stdout.strip() == "true"

    @staticmethod
    def _git_base(root: Path) -> list[str]:
        """git invocation prefix that tolerates a repo owned by another user.

        caliper scans read-only *mounts* in CI, where the work tree is owned by a
        different uid than the scanner process; without this git aborts with
        "detected dubious ownership". Scoped to *root* only.
        """
        return ["git", "-c", f"safe.directory={root}"]

    def list_files(self, root: Path, *, suffixes: tuple[str, ...] | None = None) -> list[Path]:
        if not self.is_available(root):
            return []

        result = self._runner.run(
            ToolInvocation(
                cmd=[
                    *self._git_base(root),
                    "ls-files",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                    "-z",
                ],
                cwd=str(root),
                timeout=_GIT_TIMEOUT,
            )
        )
        if result.exit_code != 0:
            logger.warning("git_ls_files_failed", root=str(root), stderr=result.stderr[:200])
            return []

        patterns = load_ignore_patterns(root)
        root_resolved = root.resolve()
        out: list[Path] = []
        seen: set[str] = set()
        for rel in result.stdout.split("\0"):
            if not rel or rel in seen:
                continue
            seen.add(rel)
            if not _matches_suffix(rel, suffixes):
                continue
            if should_ignore(rel, patterns):  # caliper exclusions on top of .gitignore
                continue
            full = root / rel
            # Reject paths escaping the root via symlink — git tracks a symlink's
            # target string as a blob, so ls-files surfaces it same as any other
            # file even when it points outside the repo.
            try:
                full.resolve().relative_to(root_resolved)
            except ValueError:
                continue
            out.append(full)

        return sorted(out)


def select_file_source(
    root: Path,
    *,
    prefer: str | None = None,
    runner: ToolRunnerPort | None = None,
) -> WalkFileSource | GitLsFilesSource:
    """Resolve the file source for *root* — git when usable, else walk.

    The decision is made **once** here (not per plugin). ``prefer`` (or the
    ``CALIPER_FILE_SOURCE`` env var) forces ``"git"`` or ``"walk"``; the default
    ``"auto"`` probes for a usable git work tree and falls back to walk.
    """
    choice = (prefer or os.environ.get("CALIPER_FILE_SOURCE", "auto")).strip().lower()

    if choice == "walk":
        return WalkFileSource()
    if choice == "git":
        return GitLsFilesSource(runner=runner)

    git = GitLsFilesSource(runner=runner)
    if git.is_available(root):
        return git
    return WalkFileSource()
