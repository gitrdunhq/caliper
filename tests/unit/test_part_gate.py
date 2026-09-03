"""Tests for the parting safety gate — ``core.part_gate.run_gate``.

# tested-by: tests/unit/test_part_gate.py

A fake ``ToolRunnerPort`` stands in for jj/git, so the gate logic is verified
with no real jj installed. Covers every abort case (no state change), the
success path (backup bookmark + rollback rescue point), and that revsets are
resolved to explicit commit ids for the provenance.

Property domains (DPS-12):
  Atomicity     SAFETY  a failed precondition leaves no partial state (no bookmark)
  Reversibility LIVENESS success records a rescue op id + immutable backup bookmark
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.part_gate import PartingGateError, run_gate
from caliper.core.tool_runner import ToolInvocation, ToolResult


class FakeJJ:
    """Configurable canned jj/git responses; records every invocation."""

    def __init__(
        self,
        *,
        dirty: bool = False,
        untracked: str = "",
        stash: str = "",
        pushed: bool = False,
        immutable_overlap: bool = False,
        jj_missing: bool = False,
        git_missing: bool = False,
    ) -> None:
        self.dirty = dirty
        self.untracked = untracked
        self.stash = stash
        self.pushed = pushed
        self.immutable_overlap = immutable_overlap
        self.jj_missing = jj_missing
        self.git_missing = git_missing
        self.calls: list[list[str]] = []

    def run(self, invocation: ToolInvocation) -> ToolResult:
        cmd = invocation.cmd
        self.calls.append(cmd)

        def ok(out: str = "") -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        if cmd[0] == "jj":
            if self.jj_missing:
                return ToolResult(exit_code=127, stdout="", stderr="", not_installed=True)
            if "--version" in cmd:
                return ok("jj 0.99.0\n")
            if cmd[1] == "root":
                return ok("/repo\n")
            if cmd[1] == "st":
                return ok("Working copy changes:\nM x\n" if self.dirty else "no changes.\n")
            if cmd[1] == "op":
                return ok("op-rescue-1\n")
            if cmd[1] == "bookmark":
                return ok()
            if cmd[1] == "log":
                rev = cmd[cmd.index("-r") + 1]
                if rev == "@ & ::(remote_bookmarks())":
                    return ok("pushed-commit\n" if self.pushed else "")
                if "immutable()" in rev:
                    return ok("imm-commit\n" if self.immutable_overlap else "")
                ids = {"base": "baseid", "head": "headid", "@": "atid", "trunk()": "trunkid"}
                return ok(ids.get(rev, "someid") + "\n")
            return ok()
        if cmd[0] == "git":
            if "rev-parse" in cmd and "--git-dir" in cmd:
                if self.git_missing:
                    return ToolResult(exit_code=127, stdout="", stderr="", not_installed=True)
                return ok(".git\n")
            if "ls-files" in cmd:
                return ok(self.untracked)
            if "stash" in cmd:
                return ok(self.stash)
            return ok()
        return ok()


def _made_backup(runner: FakeJJ) -> bool:
    return any(c[0] == "jj" and len(c) > 1 and c[1] == "bookmark" for c in runner.calls)


def _gate(runner: FakeJJ, force: bool = False):
    return run_gate(
        Path("/repo"), "base", "head", timestamp="20260629T0000", runner=runner, force=force
    )


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


def test_gate_success_creates_backup_and_rescue_point() -> None:
    runner = FakeJJ()
    result = _gate(runner)
    assert result.backup_bookmark == "caliper-part-backup-20260629T0000"
    assert result.rescue_op_id == "op-rescue-1"
    assert result.jj_version == "jj 0.99.0"
    assert _made_backup(runner)


def test_gate_resolves_revsets_to_explicit_commit_ids() -> None:
    """Revsets are resolved to pinned commit ids that appear in the provenance."""
    result = _gate(FakeJJ())
    assert result.resolved_revsets == {
        "base": "baseid",
        "head": "headid",
        "@": "atid",
        "trunk": "trunkid",
    }


def test_backup_bookmark_is_the_final_gate_step() -> None:
    """The backup bookmark (the only state change) is created LAST — after every
    read-only precondition check and the rescue-point capture — so a failure at
    any earlier check leaves no state change."""
    runner = FakeJJ()
    _gate(runner)
    # the bookmark create is the very last command the gate runs
    assert runner.calls[-1][0] == "jj" and runner.calls[-1][1] == "bookmark"
    # and it is preceded by the rescue-point capture (jj op log) and the checks
    bookmark_idx = next(i for i, c in enumerate(runner.calls) if c[1] == "bookmark")
    op_idx = next(i for i, c in enumerate(runner.calls) if c[1] == "op")
    st_idx = next(i for i, c in enumerate(runner.calls) if c[1] == "st")
    assert st_idx < op_idx < bookmark_idx
    # the backup is anchored on the RESOLVED BASE (not @) so the rebuilt parts are
    # exactly the linear chain `backup+::@`.
    assert runner.calls[-1] == [
        "jj",
        "bookmark",
        "create",
        "caliper-part-backup-20260629T0000",
        "-r",
        "baseid",
    ]


# ---------------------------------------------------------------------------
# Abort cases — each leaves NO state change (no backup bookmark)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "case"),
    [
        ({"dirty": True}, "dirty-tree"),
        ({"untracked": "stray.py\n"}, "untracked-files"),
        ({"stash": "stash@{0}: WIP\n"}, "git-stash"),
        ({"pushed": True}, "already-pushed"),
        ({"immutable_overlap": True}, "immutable-overlap"),
    ],
)
def test_gate_aborts_with_no_state_change(kwargs: dict, case: str) -> None:
    runner = FakeJJ(**kwargs)
    with pytest.raises(PartingGateError) as exc:
        _gate(runner)
    assert exc.value.case == case
    assert not _made_backup(runner), "gate must not change state on abort"


def test_force_overrides_already_pushed() -> None:
    runner = FakeJJ(pushed=True)
    result = _gate(runner, force=True)
    assert _made_backup(runner)
    assert result.backup_bookmark.startswith("caliper-part-backup-")


# ---------------------------------------------------------------------------
# Backend detection (#520) — jj preferred, git the fallback when jj is absent.
# ---------------------------------------------------------------------------


def test_backend_defaults_to_jj_when_both_usable() -> None:
    result = _gate(FakeJJ())
    assert result.backend == "jj"


def test_jj_missing_falls_back_to_git_backend() -> None:
    result = _gate(FakeJJ(jj_missing=True))
    assert result.backend == "git"
    assert result.jj_version == ""


def test_missing_vcs_when_both_absent() -> None:
    runner = FakeJJ(jj_missing=True, git_missing=True)
    with pytest.raises(PartingGateError) as exc:
        _gate(runner)
    assert exc.value.case == "missing-vcs"


# ---------------------------------------------------------------------------
# git-only backend preconditions (#520) — no jj on PATH.
# ---------------------------------------------------------------------------


class FakeGitOnly:
    """Simulates a repo where jj is absent — every command is plain git."""

    def __init__(
        self,
        *,
        dirty: bool = False,
        untracked: bool = False,
        stash: str = "",
        pushed: bool = False,
        immutable_overlap: bool = False,
        detached: bool = False,
    ) -> None:
        self.dirty = dirty
        self.untracked = untracked
        self.stash = stash
        self.pushed = pushed
        self.immutable_overlap = immutable_overlap
        self.detached = detached
        self.calls: list[list[str]] = []

    def run(self, invocation: ToolInvocation) -> ToolResult:
        cmd = invocation.cmd
        self.calls.append(cmd)

        def ok(out: str = "") -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        if cmd[0] == "jj":
            return ToolResult(exit_code=127, stdout="", stderr="", not_installed=True)

        assert cmd[0] == "git"
        if "rev-parse" in cmd and "--git-dir" in cmd:
            return ok(".git\n")
        if "status" in cmd:
            lines = []
            if self.dirty:
                lines.append(" M changed.py")
            if self.untracked:
                lines.append("?? stray.py")
            return ok("\n".join(lines) + ("\n" if lines else ""))
        if "stash" in cmd:
            return ok(self.stash)
        if "rev-parse" in cmd:
            rev = cmd[-1]
            shas = {"base": "basesha", "head": "headsha", "HEAD": "headcurrent"}
            if rev == "origin/HEAD":
                return ToolResult(exit_code=128, stdout="", stderr="fatal: ambiguous")
            return ok(shas.get(rev, rev) + "\n")
        if "branch" in cmd and "--contains" in cmd:
            return ok("origin/main\n" if self.pushed else "")
        if "rev-list" in cmd:
            # unfiltered call always sees one stock commit; the `--not --remotes`
            # call sees it too UNLESS it's already reachable from a remote.
            if "--not" in cmd:
                return ok("" if self.immutable_overlap else "stock-commit\n")
            return ok("stock-commit\n")
        if "symbolic-ref" in cmd:
            if self.detached:
                return ToolResult(exit_code=1, stdout="", stderr="fatal: not on a branch")
            return ok("feature-branch\n")
        return ok()  # branch create (backup), and any other command not modeled above


def _made_git_backup(runner: FakeGitOnly) -> bool:
    return any(c[0] == "git" and "branch" in c and "--contains" not in c for c in runner.calls)


def _git_gate(runner: FakeGitOnly, force: bool = False):
    return run_gate(
        Path("/repo"), "base", "head", timestamp="20260629T0000", runner=runner, force=force
    )


def test_git_gate_success() -> None:
    result = _git_gate(FakeGitOnly())
    assert result.backend == "git"
    assert result.backup_bookmark == "caliper-part-backup-20260629T0000"
    assert result.rescue_op_id == "feature-branch"
    assert result.resolved_revsets["base"] == "basesha"
    assert result.resolved_revsets["head"] == "headsha"
    assert result.resolved_revsets["@"] == "headcurrent"
    assert result.resolved_revsets["trunk"] == ""  # no origin/HEAD — fails open, not raised


def test_git_gate_rescue_ref_is_head_sha_when_detached() -> None:
    result = _git_gate(FakeGitOnly(detached=True))
    assert result.rescue_op_id == "headcurrent"


@pytest.mark.parametrize(
    ("kwargs", "case"),
    [
        ({"dirty": True}, "dirty-tree"),
        ({"untracked": True}, "untracked-files"),
        ({"stash": "stash@{0}: WIP\n"}, "git-stash"),
        ({"pushed": True}, "already-pushed"),
        ({"immutable_overlap": True}, "immutable-overlap"),
    ],
)
def test_git_gate_aborts_with_no_state_change(kwargs: dict, case: str) -> None:
    runner = FakeGitOnly(**kwargs)
    with pytest.raises(PartingGateError) as exc:
        _git_gate(runner)
    assert exc.value.case == case
    assert not _made_git_backup(runner), "git gate must not change state on abort"


def test_git_gate_force_overrides_already_pushed_and_immutable() -> None:
    runner = FakeGitOnly(pushed=True, immutable_overlap=True)
    result = _git_gate(runner, force=True)
    assert result.backend == "git"
    assert _made_git_backup(runner)
