"""Tests for the shared parting orchestrator — ``cli.part_pipeline.run_part``.

# tested-by: tests/unit/test_part_pipeline.py

Both `caliper part` (CLI) and `caliper part --serve` (web sidecar) call
`run_part` so the gate -> cut -> suggest -> describe -> script sequence is
defined once. The safety gate and jj-capability probe run through a fake
``ToolRunnerPort`` (no real jj needed); the cut step (`core/part_stock.py`)
shells out to real git, so these tests build a small real git repo on disk —
`tests/integration/test_part_e2e.py` is the real-jj end-to-end complement.

Property domains (DPS-12):
  Atomicity  SAFETY  a failed gate leaves no artifacts written to out_dir
  Idempotency INVARIANT  the same inputs (same fake runner) produce the same script bytes
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from caliper.cli.part_pipeline import run_part
from caliper.core.part_gate import PartingGateError
from caliper.core.repo_config import PartingConfig
from caliper.core.tier_suggester import SuggestedRule, SuggestRequest, TierSuggesterPort
from caliper.core.tool_runner import ToolInvocation, ToolResult


def _git(cmd: list[str], cwd: Path, env: dict) -> str:
    proc = subprocess.run(["git", *cmd], cwd=cwd, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"git {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout


@pytest.fixture()
def repo(tmp_path: Path):
    """A plain git repo (no jj) with a base commit and a head commit that edits
    an untiered .py file and a documentation file."""
    w = tmp_path / "repo"
    w.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    _git(["init", "-q", "."], w, env)
    _git(["config", "user.email", "t@t"], w, env)
    _git(["config", "user.name", "t"], w, env)
    (w / "svc.py").write_text("x\n")
    (w / "README.md").write_text("doc\n")
    _git(["add", "-A"], w, env)
    _git(["commit", "-qm", "base"], w, env)
    base = _git(["rev-parse", "HEAD"], w, env).strip()

    (w / "svc.py").write_text("x\ny\n")
    (w / "README.md").write_text("doc\nmore\n")
    _git(["add", "-A"], w, env)
    _git(["commit", "-qm", "head"], w, env)
    head = _git(["rev-parse", "HEAD"], w, env).strip()
    return w, base, head


class _FakeGateRunner:
    """A fake jj/git ``ToolRunnerPort`` for the gate + probe seam. Resolves the
    ``base``/``head`` revsets to the real commit ids so provenance stays honest,
    with no real jj installed."""

    def __init__(
        self,
        *,
        base_id: str,
        head_id: str,
        dirty: bool = False,
        pushed: bool = False,
        can_reconstruct: bool = True,
    ) -> None:
        self.base_id = base_id
        self.head_id = head_id
        self.dirty = dirty
        self.pushed = pushed
        self.restore_help = "--from <REV> [PATHS]..." if can_reconstruct else "--from <REV>"
        self.calls: list[list[str]] = []

    def run(self, invocation: ToolInvocation) -> ToolResult:
        cmd = invocation.cmd
        self.calls.append(cmd)

        def ok(out: str = "") -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        if cmd[0] == "jj":
            if "--version" in cmd:
                return ok("jj 0.99.0\n")
            if cmd[1] == "root":
                return ok("/repo\n")
            if cmd[1] == "st":
                return ok("Working copy changes:\nM x\n" if self.dirty else "no changes.\n")
            if cmd[1] == "restore":
                return ok(self.restore_help)
            if cmd[1] == "op":
                return ok("op-rescue-1\n")
            if cmd[1] == "bookmark":
                return ok()
            if cmd[1] == "log":
                rev = cmd[cmd.index("-r") + 1]
                if rev == "@ & ::(remote_bookmarks())":
                    return ok("pushed-commit\n" if self.pushed else "")
                if "immutable()" in rev:
                    return ok("")
                ids = {self.base_id: self.base_id, self.head_id: self.head_id, "@": "atid"}
                return ok(ids.get(rev, "trunkid" if rev == "trunk()" else "someid") + "\n")
            return ok()
        if cmd[0] == "git":
            if "ls-files" in cmd:
                return ok("")
            if "stash" in cmd:
                return ok("")
            return ok()
        return ok()


class _StubSuggester(TierSuggesterPort):
    def __init__(self, rules: list[SuggestedRule]) -> None:
        self.rules = rules

    def suggest(self, request: SuggestRequest) -> list[SuggestedRule]:
        return self.rules


def test_run_part_writes_restack_and_cutlist(tmp_path: Path, repo) -> None:
    w, base, head = repo
    out = tmp_path / "out"
    runner = _FakeGateRunner(base_id=base, head_id=head)

    result = run_part(
        w,
        base,
        head,
        PartingConfig(),
        timestamp="20260629T000000000000",
        runner=runner,
        out_dir=out,
    )

    assert result.backup_bookmark == "caliper-part-backup-20260629T000000000000"
    assert result.rescue_op_id == "op-rescue-1"
    assert result.can_reconstruct is True
    assert result.cutlist.provenance.base_sha == base
    assert result.cutlist.provenance.head_sha == head
    assert result.cutlist.provenance.resolved_revsets["base"] == base
    assert result.cutlist.provenance.resolved_revsets["head"] == head

    assert result.restack_path == str(out / "restack.sh")
    assert result.cutlist_path == str(out / "cutlist.json")
    script = (out / "restack.sh").read_text()
    assert script.splitlines()[0] == "#!/usr/bin/env bash"
    assert "jj op restore" in script
    assert script == result.script_text
    assert json.loads((out / "cutlist.json").read_text())["parts"]


def test_run_part_without_out_dir_writes_nothing(tmp_path: Path, repo) -> None:
    w, base, head = repo
    runner = _FakeGateRunner(base_id=base, head_id=head)

    result = run_part(w, base, head, PartingConfig(), timestamp="20260629T000001", runner=runner)

    assert result.restack_path is None
    assert result.cutlist_path is None
    assert result.script_text  # still rendered, just not persisted


def test_run_part_gate_failure_writes_no_artifacts(tmp_path: Path, repo) -> None:
    w, base, head = repo
    out = tmp_path / "out"
    runner = _FakeGateRunner(base_id=base, head_id=head, dirty=True)

    with pytest.raises(PartingGateError) as exc_info:
        run_part(
            w, base, head, PartingConfig(), timestamp="20260629T000002", runner=runner, out_dir=out
        )

    assert exc_info.value.case == "dirty-tree"
    assert not out.exists()


def test_run_part_force_overrides_already_pushed_gate(tmp_path: Path, repo) -> None:
    w, base, head = repo
    runner = _FakeGateRunner(base_id=base, head_id=head, pushed=True)

    with pytest.raises(PartingGateError) as exc_info:
        run_part(w, base, head, PartingConfig(), timestamp="20260629T000003", runner=runner)
    assert exc_info.value.case == "already-pushed"

    # force=True lets the same otherwise-pushed target through.
    result = run_part(
        w, base, head, PartingConfig(), timestamp="20260629T000004", force=True, runner=runner
    )
    assert result.cutlist.parts


def test_run_part_probe_false_when_jj_lacks_path_restore(tmp_path: Path, repo) -> None:
    w, base, head = repo
    runner = _FakeGateRunner(base_id=base, head_id=head, can_reconstruct=False)

    result = run_part(w, base, head, PartingConfig(), timestamp="20260629T000005", runner=runner)

    assert result.can_reconstruct is False
    assert "manual" in result.script_text.lower()


def test_run_part_suggest_apply_writes_override_and_reparts(tmp_path: Path, repo) -> None:
    w, base, head = repo
    store = tmp_path / "override-store"
    runner = _FakeGateRunner(base_id=base, head_id=head)
    suggester = _StubSuggester([SuggestedRule(glob="*.py", bucket="business")])

    result = run_part(
        w,
        base,
        head,
        PartingConfig(),
        timestamp="20260629T000006",
        runner=runner,
        suggester=suggester,
        suggest_apply=True,
        override_write_target=store,
    )

    assert len(result.proposed_overrides) == 1
    assert result.applied_overrides == result.proposed_overrides
    assert (store / ".caliper.yaml").exists()
    assert not (w / ".caliper.yaml").exists()
    business_files = [
        f for p in result.cutlist.parts if p.bucket.value == "business" for f in p.files
    ]
    assert "svc.py" in business_files


def test_run_part_suggest_without_apply_does_not_write_or_repart(tmp_path: Path, repo) -> None:
    w, base, head = repo
    runner = _FakeGateRunner(base_id=base, head_id=head)
    suggester = _StubSuggester([SuggestedRule(glob="*.py", bucket="business")])

    result = run_part(
        w,
        base,
        head,
        PartingConfig(),
        timestamp="20260629T000007",
        runner=runner,
        suggester=suggester,
    )

    assert len(result.proposed_overrides) == 1
    assert result.applied_overrides == []
    assert not (w / ".caliper.yaml").exists()
    logic_files = [f for p in result.cutlist.parts if p.bucket.value == "logic" for f in p.files]
    assert "svc.py" in logic_files


def test_run_part_describe_defaults_to_no_subjects(tmp_path: Path, repo) -> None:
    w, base, head = repo
    runner = _FakeGateRunner(base_id=base, head_id=head)

    result = run_part(w, base, head, PartingConfig(), timestamp="20260629T000008", runner=runner)

    assert result.subjects == {}
