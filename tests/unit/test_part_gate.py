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
    ) -> None:
        self.dirty = dirty
        self.untracked = untracked
        self.stash = stash
        self.pushed = pushed
        self.immutable_overlap = immutable_overlap
        self.jj_missing = jj_missing
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
        ({"jj_missing": True}, "missing-jj"),
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
