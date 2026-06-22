"""Regression guard for #206: SBOM base generation mutates the active checkout.

Bug (FIXED): agent/tool_helpers.py ran 'git checkout <base-sha>' directly in the
active repository to generate the base SBOM, then attempted to restore the prior
SHA in a finally block. This could disturb live checkouts and lose uncommitted state.

Fix: the helper now uses 'git worktree add' to create an isolated checkout so
the shared working directory is never touched during base SBOM generation.

These tests PASS while the fix is in place. They fail if someone reverts to the
in-place 'git checkout' pattern. See issues #206 and #240.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (_REPO / relative_path).read_text(encoding="utf-8")


class TestSbomBaseGenerationUsesWorktree:
    """tool_helpers.py must generate the base SBOM from an isolated worktree."""

    def test_sbom_generation_uses_git_worktree_not_checkout(self) -> None:
        """SBOM base generation must use 'git worktree' not 'git checkout'.

        Using 'git checkout' in the shared working directory can disturb a live
        checkout and lose uncommitted state. 'git worktree add' creates an
        isolated copy that is safe to operate on concurrently.

        Regression: if 'git checkout <sha>' reappears in _generate_base_sbom
        or equivalent without a worktree guard, this test fails.
        """
        content = _read("src/caliper/agent/tool_helpers.py")
        assert "worktree" in content, (
            "tool_helpers.py does not use 'git worktree'. "
            "SBOM base generation must create an isolated worktree rather than "
            "checking out a different SHA in the active repository. "
            "Regression of #206: in-place checkout can corrupt live checkouts. "
            "Fix: use 'git worktree add <path> <sha>' for SBOM base generation."
        )

    def test_sbom_generation_does_not_checkout_in_place(self) -> None:
        """SBOM base generation must not run 'git checkout' in the active repo path.

        The original bug was git checkout run in repo_path (the live working tree).
        If this pattern re-appears alongside a worktree approach it is also a bug —
        a stale fallback that mutates the live checkout.
        """
        content = _read("src/caliper/agent/tool_helpers.py")

        # Detect the buggy pattern: subprocess call with "checkout" and the live repo path
        # (worktree add is fine; bare "git checkout" on the live path is not)
        bare_checkout = re.search(r'"git",\s*"-C",\s*repo_path.*?"checkout"', content, re.DOTALL)
        assert bare_checkout is None, (
            "tool_helpers.py still runs 'git -C repo_path checkout <sha>' — "
            "this mutates the active checkout. "
            "The SBOM base must be generated from a temporary worktree. "
            "See issue #206."
        )
