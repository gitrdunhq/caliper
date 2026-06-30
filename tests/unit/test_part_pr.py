"""Tests for PR resolution into an isolated clone — ``cli.part_pr``.

# tested-by: tests/unit/test_part_pr.py

Offline: a fake ``ToolRunnerPort`` returns canned git/gh/jj output, so no real
network, clone, or jj install is needed. ``--pr`` always clones the PR into a
throwaway workdir (never the user's repo) and neutralizes jj immutability there,
so the parting gate can read the diff of an already-pushed PR.

Property domains (DPS-12):
  Determinism   INVARIANT   same canned repo state -> identical ResolvedPr
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.cli.part_pr import (
    PrResolveError,
    ResolvedPr,
    detect_origin_slug,
    resolve_pr,
)
from caliper.core.pr_ref import PrRef
from caliper.core.tool_runner import ToolInvocation, ToolResult

_HEAD = "hhhhhhhhhhhh"
_BASE = "bbbbbbbbbbbb"


class FakeRunner:
    """Canned git/gh/jj output keyed by subcommand; records every invocation."""

    def __init__(
        self,
        *,
        base_branch: str = "main",
        clone_ok: bool = True,
        gh_ok: bool = True,
    ) -> None:
        self.calls: list[list[str]] = []
        self._bb = base_branch
        self._clone_ok = clone_ok
        self._gh_ok = gh_ok

    def run(self, inv: ToolInvocation) -> ToolResult:
        cmd = inv.cmd
        self.calls.append(cmd)

        def ok(out: str = "") -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        def fail() -> ToolResult:
            return ToolResult(exit_code=1, stdout="", stderr="boom")

        if cmd[0] == "git":
            if "clone" in cmd:
                if not self._clone_ok:
                    return fail()
                # Simulate a real clone touching disk, so cleanup is observable.
                (Path(cmd[-1]) / ".git").mkdir(parents=True, exist_ok=True)
                return ok()
            if "rev-parse" in cmd:
                return ok(_HEAD + "\n")
            if "merge-base" in cmd:
                return ok(_BASE + "\n")
            if "get-url" in cmd:
                return ok("git@github.com:owner/repo.git\n")
            if "show" in cmd:  # git remote show origin
                return ok(f"* remote origin\n  HEAD branch: {self._bb}\n")
            if "fetch" in cmd or "checkout" in cmd:
                return ok()
        if cmd[0] == "gh":
            return ok(self._bb + "\n") if self._gh_ok else fail()
        if cmd[0] == "jj":
            if cmd[1:2] == ["root"]:
                return fail()  # not yet a jj repo -> init fires
            return ok()
        return ok()


def _ref(owner: str = "owner", repo: str = "repo", number: int = 5) -> PrRef:
    return PrRef(owner=owner, repo=repo, number=number)


def test_resolve_clones_and_resolves(tmp_path: Path) -> None:
    runner = FakeRunner()
    res = resolve_pr(_ref(), runner=runner, workdir_root=tmp_path)

    assert isinstance(res, ResolvedPr)
    assert res.base == _BASE
    assert res.head == _HEAD
    assert res.repo_path == tmp_path / "repo-pr5"
    assert res.slug == "owner/repo"
    assert res.number == 5

    joined = [" ".join(c) for c in runner.calls]
    assert any(c[0] == "git" and "clone" in c for c in runner.calls)
    assert any("refs/pull/5/head" in j for j in joined)
    # jj init (colocate or plain) + immutability neutralized in the throwaway clone
    assert any(c[:3] == ["jj", "git", "init"] for c in runner.calls)
    assert any("immutable_heads" in j for j in joined)


def test_wipes_stale_clone(tmp_path: Path) -> None:
    # A leftover clone from a prior run must be wiped to a clean slate.
    stale = tmp_path / "repo-pr5"
    stale.mkdir(parents=True)
    (stale / "stale.txt").write_text("old")
    runner = FakeRunner()
    resolve_pr(_ref(), runner=runner, workdir_root=tmp_path)
    assert not (stale / "stale.txt").exists()
    assert any(c[0] == "git" and "clone" in c for c in runner.calls)


def test_failure_cleans_up_partial_clone(tmp_path: Path) -> None:
    # gh fails and origin shows no HEAD branch -> base-branch resolution raises
    # mid-run; the partial clone must not linger to poison the next run.
    runner = FakeRunner(gh_ok=False, base_branch="")
    with pytest.raises(PrResolveError):
        resolve_pr(_ref(owner="o", repo="r", number=1), runner=runner, workdir_root=tmp_path)
    assert not (tmp_path / "r-pr1").exists()


def test_refuses_to_remove_outside_workdir(tmp_path: Path) -> None:
    from caliper.cli.part_pr import _safe_rmtree

    outside = tmp_path.parent
    with pytest.raises(PrResolveError, match="outside"):
        _safe_rmtree(outside, tmp_path)


def test_gh_failure_falls_back_to_remote_show(tmp_path: Path) -> None:
    runner = FakeRunner(gh_ok=False, base_branch="develop")
    resolve_pr(_ref(owner="o", repo="r", number=1), runner=runner, workdir_root=tmp_path)
    # base branch came from `git remote show origin` -> fetch develop
    assert any(c[0] == "git" and "fetch" in c and "develop" in c for c in runner.calls)


def test_clone_failure_raises(tmp_path: Path) -> None:
    runner = FakeRunner(clone_ok=False)
    with pytest.raises(PrResolveError, match="clone"):
        resolve_pr(_ref(owner="o", repo="r", number=1), runner=runner, workdir_root=tmp_path)


def test_detect_origin_slug(tmp_path: Path) -> None:
    assert detect_origin_slug(tmp_path, FakeRunner()) == "owner/repo"


class TestProperties:
    def test_determinism(self, tmp_path: Path) -> None:
        a = resolve_pr(_ref(number=2), runner=FakeRunner(), workdir_root=tmp_path)
        b = resolve_pr(_ref(number=2), runner=FakeRunner(), workdir_root=tmp_path)
        assert (a.base, a.head, a.slug, a.number) == (b.base, b.head, b.slug, b.number)
