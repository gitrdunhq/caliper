# tested-by: tests/unit/test_repo_snapshot_adapter.py
"""GitWorktreeSnapshot — RepoSnapshotPort adapter using git worktree.

Creates an isolated git worktree at a temp directory for a given ref,
and removes it via cleanup().
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from eedom.core.ports import RepoSnapshotPort


class GitWorktreeSnapshot:
    """Implements RepoSnapshotPort by creating a git worktree at a temp directory."""

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self._worktree_path: Path | None = None

    def checkout_ref(self, ref: str) -> Path:
        """Create a git worktree at a temp dir for the given ref. Returns the Path."""
        temp_dir = tempfile.mkdtemp()
        result = subprocess.run(
            ["git", "worktree", "add", temp_dir, ref],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"git worktree add failed for ref '{ref}': {result.stderr.strip()}")
        self._worktree_path = Path(temp_dir)
        return self._worktree_path

    def cleanup(self) -> None:
        """Remove the git worktree and delete the temp directory."""
        if self._worktree_path is None:
            return
        worktree_path = self._worktree_path
        self._worktree_path = None
        subprocess.run(
            ["git", "worktree", "remove", str(worktree_path)],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        shutil.rmtree(worktree_path, ignore_errors=True)


assert isinstance(
    GitWorktreeSnapshot(Path(".")), RepoSnapshotPort
), "GitWorktreeSnapshot must satisfy RepoSnapshotPort"


class NullRepoSnapshot:
    """No-op RepoSnapshotPort — never touches git; for tests and fakes wiring."""

    def checkout_ref(self, ref: str) -> Path:
        return Path(".")

    def cleanup(self) -> None:
        return None


from eedom.core.registries import REPO_SNAPSHOTS  # noqa: E402  (registration wiring)


@REPO_SNAPSHOTS.register("git")
def build_git_snapshot(*, repo_path: Path) -> GitWorktreeSnapshot:
    return GitWorktreeSnapshot(repo_path=repo_path)


@REPO_SNAPSHOTS.register("fake")
def build_fake_snapshot() -> NullRepoSnapshot:
    return NullRepoSnapshot()
