# tested-by: tests/unit/test_repo_snapshot_adapter.py
"""Contract tests for GitWorktreeSnapshot adapter (issue #176).

RED phase: all tests import from caliper.adapters.repo_snapshot which does not exist yet.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from caliper.adapters.repo_snapshot import (
    GitWorktreeSnapshot,  # noqa: F401 — will ImportError until green
)
from caliper.core.ports import RepoSnapshotPort

# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_git_worktree_snapshot_satisfies_repo_snapshot_port(self):
        """GitWorktreeSnapshot must be an instance of RepoSnapshotPort (runtime-checkable)."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        assert isinstance(snap, RepoSnapshotPort)


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_constructor_accepts_repo_path(self):
        """Constructor takes a repo_path: Path argument."""
        snap = GitWorktreeSnapshot(repo_path=Path("/some/repo"))
        assert snap.repo_path == Path("/some/repo")

    def test_worktree_path_initially_none(self):
        """No worktree is checked out until checkout_ref is called."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        assert snap._worktree_path is None


# ---------------------------------------------------------------------------
# checkout_ref — happy path
# ---------------------------------------------------------------------------


class TestCheckoutRef:
    def test_checkout_ref_returns_a_path(self):
        """checkout_ref must return a Path object."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("tempfile.mkdtemp", return_value="/tmp/wt_abc"):
                result = snap.checkout_ref("abc123")
        assert isinstance(result, Path)

    def test_checkout_ref_calls_git_worktree_add(self):
        """checkout_ref must invoke `git worktree add <temp> <ref>`."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("tempfile.mkdtemp", return_value="/tmp/wt_xyz"):
                snap.checkout_ref("HEAD~1")
        args = mock_run.call_args[0][0]
        assert args[:3] == ["git", "worktree", "add"]
        assert "HEAD~1" in args

    def test_checkout_ref_uses_repo_path_as_cwd(self):
        """git worktree add must be run with cwd=repo_path."""
        snap = GitWorktreeSnapshot(repo_path=Path("/my/repo"))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("tempfile.mkdtemp", return_value="/tmp/wt_cwd"):
                snap.checkout_ref("main")
        kwargs = mock_run.call_args[1]
        assert kwargs.get("cwd") == Path("/my/repo")

    def test_checkout_ref_stores_worktree_path(self):
        """After checkout_ref, _worktree_path must be set to the returned Path."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("tempfile.mkdtemp", return_value="/tmp/wt_store"):
                result = snap.checkout_ref("v1.2.3")
        assert snap._worktree_path == result

    def test_checkout_ref_returned_path_matches_temp_dir(self):
        """The returned Path must match the temp directory created."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("tempfile.mkdtemp", return_value="/tmp/wt_match"):
                result = snap.checkout_ref("sha256abc")
        assert str(result) == "/tmp/wt_match"


# ---------------------------------------------------------------------------
# checkout_ref — error handling
# ---------------------------------------------------------------------------


class TestCheckoutRefErrors:
    def test_checkout_ref_raises_on_nonzero_exit(self):
        """checkout_ref raises RuntimeError when git worktree add returns non-zero."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="fatal: bad ref")
            with patch("tempfile.mkdtemp", return_value="/tmp/wt_fail"):
                with pytest.raises(RuntimeError, match="git worktree add"):
                    snap.checkout_ref("bad-ref")

    def test_checkout_ref_raises_on_subprocess_error(self):
        """checkout_ref propagates CalledProcessError from git."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        with (
            patch(
                "subprocess.run",
                side_effect=subprocess.CalledProcessError(128, "git"),
            ),
            patch("tempfile.mkdtemp", return_value="/tmp/wt_err"),
        ):
            with pytest.raises(subprocess.CalledProcessError):
                snap.checkout_ref("missing-ref")


# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    def test_cleanup_calls_git_worktree_remove(self):
        """cleanup must call `git worktree remove <path>`."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        snap._worktree_path = Path("/tmp/wt_clean")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("shutil.rmtree") as mock_rm:
                snap.cleanup()
        args = mock_run.call_args[0][0]
        assert args[:3] == ["git", "worktree", "remove"]
        assert "/tmp/wt_clean" in args

    def test_cleanup_removes_temp_dir(self):
        """cleanup must remove the temp directory from the filesystem."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        snap._worktree_path = Path("/tmp/wt_rmdir")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("shutil.rmtree") as mock_rm:
                snap.cleanup()
        mock_rm.assert_called_once_with(Path("/tmp/wt_rmdir"), ignore_errors=True)

    def test_cleanup_resets_worktree_path_to_none(self):
        """After cleanup, _worktree_path must be reset to None."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        snap._worktree_path = Path("/tmp/wt_reset")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("shutil.rmtree"):
                snap.cleanup()
        assert snap._worktree_path is None

    def test_cleanup_is_noop_when_no_worktree(self):
        """cleanup when _worktree_path is None must not call subprocess or rmtree."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        with patch("subprocess.run") as mock_run, patch("shutil.rmtree") as mock_rm:
            snap.cleanup()
        mock_run.assert_not_called()
        mock_rm.assert_not_called()

    def test_cleanup_uses_repo_path_as_cwd(self):
        """git worktree remove must run with cwd=repo_path."""
        snap = GitWorktreeSnapshot(repo_path=Path("/my/repo"))
        snap._worktree_path = Path("/tmp/wt_cwd2")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("shutil.rmtree"):
                snap.cleanup()
        kwargs = mock_run.call_args[1]
        assert kwargs.get("cwd") == Path("/my/repo")

    def test_cleanup_subprocess_has_timeout(self):
        """cleanup() must pass timeout=30 to subprocess.run (DPS-5)."""
        snap = GitWorktreeSnapshot(repo_path=Path("/repo"))
        snap._worktree_path = Path("/tmp/wt_timeout")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("shutil.rmtree"):
                snap.cleanup()
        kwargs = mock_run.call_args[1]
        assert "timeout" in kwargs, "subprocess.run() in cleanup() must include a timeout"
        assert kwargs["timeout"] == 30, "cleanup() timeout must be 30 seconds"
