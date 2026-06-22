"""Deterministic regression guard for subprocess timeouts in publisher adapters (Issue #260).

This is a REGRESSION GUARD — the bug is fixed.  These tests PASS and must
continue to pass.  A future refactor that removes timeout= arguments would break
these tests, giving early warning of the regression.

Bug was: GitHubPublisher and GitWorktreeSnapshot launched subprocesses without
explicit timeout= arguments.  A hung gh CLI call or a slow git worktree command
could block the pipeline indefinitely.

Fix (verified): Explicit timeouts were added to all subprocess.run() calls in
both adapters:
  - adapters/github_publisher.py line 45: timeout=30
  - adapters/repo_snapshot.py line 33: timeout=60 (checkout_ref)
  - adapters/repo_snapshot.py line 52: timeout=30 (cleanup worktree remove)

Parent bug: #226 / Epic: #146.
Status: PASSES — regression guard, not xfail.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_PUBLISHER_SRC = _REPO / "src" / "caliper" / "adapters" / "github_publisher.py"
_SNAPSHOT_SRC = _REPO / "src" / "caliper" / "adapters" / "repo_snapshot.py"


def _read(path: Path) -> str:
    assert path.exists(), f"Source file not found: {path}"
    content = path.read_text(encoding="utf-8")
    assert len(content) > 100, f"Source file is suspiciously short: {path}"
    return content


def test_260_github_publisher_subprocess_has_timeout() -> None:
    """GitHubPublisher._run() must pass timeout= to subprocess.run().

    Without a timeout, a gh CLI call that hangs (network issue, broken pipe,
    GitHub API timeout) would block the caliper pipeline indefinitely.
    The regression guard ensures timeout= is not accidentally removed.
    """
    src = _read(_PUBLISHER_SRC)
    assert "timeout=30" in src, (
        "REGRESSION #260: GitHubPublisher._run() lost its timeout=30 argument. "
        "A hanging gh CLI call will now block the pipeline indefinitely.  "
        "Restore `timeout=30` to the subprocess.run() call in _run()."
    )


def test_260_repo_snapshot_checkout_has_timeout() -> None:
    """GitWorktreeSnapshot.checkout_ref() must pass timeout= to subprocess.run().

    Cloning or adding a worktree for a large repository can be slow.  Without a
    timeout, a hung git operation would stall the caliper pipeline with no recovery.
    """
    src = _read(_SNAPSHOT_SRC)
    assert "timeout=60" in src, (
        "REGRESSION #260: GitWorktreeSnapshot.checkout_ref() lost its timeout=60 argument. "
        "A hung git worktree add call will now block indefinitely.  "
        "Restore `timeout=60` to the subprocess.run() call in checkout_ref()."
    )


def test_260_repo_snapshot_cleanup_has_timeout() -> None:
    """GitWorktreeSnapshot.cleanup() must pass timeout= to subprocess.run().

    The git worktree remove call in cleanup() can also hang if the repository is
    in a bad state.  A timeout ensures cleanup does not block shutdown.
    """
    src = _read(_SNAPSHOT_SRC)
    # cleanup() uses timeout=30 for the worktree remove call
    # Verify at least one timeout= is present in cleanup context
    # The source has two timeout= calls; we check both exist in the file.
    timeout_count = src.count("timeout=")
    assert timeout_count >= 2, (
        f"REGRESSION #260: Expected at least 2 timeout= arguments in {_SNAPSHOT_SRC.name} "
        f"(one in checkout_ref, one in cleanup) but found {timeout_count}. "
        "A subprocess.run() call in GitWorktreeSnapshot is missing its timeout."
    )
