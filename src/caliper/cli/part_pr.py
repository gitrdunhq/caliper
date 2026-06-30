"""Resolve a GitHub PR into an isolated, parseable clone — imperative shell.

# tested-by: tests/unit/test_part_pr.py

``caliper part --pr`` always clones the PR into a throwaway workdir (never the
user's repo) and neutralizes jj immutability *there*, so the parting gate can
read the diff of an already-pushed PR without ever touching the user's history.

Self-healing, no weird states: the clone dir is wiped to a clean slate at the
start of every run, and a partial/failed clone is removed before the error
propagates — so a crashed run never poisons the next one. A successful clone
persists (its cut list / restack script reference it) but is replaced fresh on
the next ``--pr`` for the same PR.

All git/gh/jj IO goes through the ``ToolRunnerPort`` seam (``core/tool_runner``)
so resolution is testable with a fake runner and no real network/clone/jj.
Fail-closed: a missing tool, non-zero exit, or timeout on a required step is a
hard ``PrResolveError``.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import structlog

from caliper.core.pr_ref import PrRef
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

logger = structlog.get_logger(__name__)

_CLONE_TIMEOUT = 300
_FETCH_TIMEOUT = 120
_QUICK_TIMEOUT = 30
_ORIGIN_RE = re.compile(r"github\.com[:/](?P<slug>.+?)(?:\.git)?$")
_HEAD_BRANCH_RE = re.compile(r"HEAD branch:\s*(?P<branch>\S+)")


class PrResolveError(Exception):
    """A required step in PR resolution failed (clone/fetch/merge-base/etc)."""


@dataclass(frozen=True)
class ResolvedPr:
    """Where the PR landed and the two endpoints to part as ``base..head``."""

    repo_path: Path
    base: str
    head: str
    slug: str
    number: int
    workdir: Path
    out_dir: Path  # managed output dir (restack.sh / cutlist.json), wiped each run


def _run(
    runner: ToolRunnerPort,
    args: list[str],
    cwd: Path,
    *,
    timeout: int,
    what: str,
    allow_fail: bool = False,
) -> str | None:
    """Run one tool invocation; fail-closed unless ``allow_fail`` (then ``None``)."""
    result = runner.run(ToolInvocation(cmd=args, cwd=str(cwd), timeout=timeout))
    if result.not_installed:
        if allow_fail:
            return None
        raise PrResolveError(f"{args[0]} is not installed — --pr requires git, gh, and jj")
    if result.timed_out:
        if allow_fail:
            return None
        raise PrResolveError(f"timed out after {timeout}s while trying to {what}")
    if result.exit_code != 0:
        if allow_fail:
            return None
        raise PrResolveError(
            f"failed to {what} (exit {result.exit_code}): {result.stderr.strip()[:300]}"
        )
    return result.stdout


def detect_origin_slug(repo_path: Path, runner: ToolRunnerPort | None = None) -> str | None:
    """Best-effort owner/repo of the repo's origin remote, for bare-number PR refs."""
    runner = runner or SubprocessToolRunner()
    out = _run(
        runner,
        ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
        repo_path,
        timeout=_QUICK_TIMEOUT,
        what="read origin remote",
        allow_fail=True,
    )
    if not out:
        return None
    m = _ORIGIN_RE.search(out.strip())
    return m["slug"] if m else None


def _safe_rmtree(path: Path, workdir_root: Path) -> None:
    """Remove ``path`` only if it is inside ``workdir_root`` (never escape .temp)."""
    path = path.resolve()
    root = workdir_root.resolve()
    if path == root or root not in path.parents:
        raise PrResolveError(f"refusing to remove {path} — outside the parting workdir")
    if path.exists():
        shutil.rmtree(path)


def _base_branch(runner: ToolRunnerPort, clone_dir: Path, pr_ref: PrRef) -> str:
    """Resolve the PR's base branch via gh, falling back to origin's default branch."""
    out = _run(
        runner,
        [
            "gh",
            "pr",
            "view",
            str(pr_ref.number),
            "--repo",
            pr_ref.slug,
            "--json",
            "baseRefName",
            "-q",
            ".baseRefName",
        ],
        clone_dir,
        timeout=_QUICK_TIMEOUT,
        what="read the PR base branch via gh",
        allow_fail=True,
    )
    if out and out.strip():
        return out.strip()
    out = _run(
        runner,
        ["git", "remote", "show", "origin"],
        clone_dir,
        timeout=_QUICK_TIMEOUT,
        what="read origin's default branch",
        allow_fail=True,
    )
    if out:
        m = _HEAD_BRANCH_RE.search(out)
        if m:
            return m["branch"]
    raise PrResolveError(
        "could not determine the PR base branch (gh and 'git remote show origin' both failed)"
    )


def resolve_pr(
    pr_ref: PrRef,
    *,
    runner: ToolRunnerPort | None = None,
    workdir_root: Path,
) -> ResolvedPr:
    """Clone the PR into an isolated, jj-ready workdir and resolve ``base..head``."""
    runner = runner or SubprocessToolRunner()
    workdir_root = Path(workdir_root)
    workdir_root.mkdir(parents=True, exist_ok=True)
    clone_dir = workdir_root / f"{pr_ref.repo}-pr{pr_ref.number}"
    out_dir = workdir_root / f"{pr_ref.repo}-pr{pr_ref.number}-out"
    n = pr_ref.number

    # Clean slate every run: a stale/dirty/partial clone from a prior run would
    # trip the parting gate (dirty tree) or resolve against stale refs. Wipe the
    # managed output dir too so a re-run never leaves stale restack.sh/cutlist.json
    # from a different cut lying around — "run part again" means redo from scratch.
    _safe_rmtree(clone_dir, workdir_root)
    _safe_rmtree(out_dir, workdir_root)

    try:
        logger.info("part_pr.clone", url=pr_ref.clone_url, dest=str(clone_dir))
        _run(
            runner,
            ["git", "clone", pr_ref.clone_url, str(clone_dir)],
            workdir_root,
            timeout=_CLONE_TIMEOUT,
            what=f"clone {pr_ref.slug}",
        )
        _run(
            runner,
            ["git", "fetch", "-q", "origin", f"+refs/pull/{n}/head:refs/remotes/origin/pr/{n}"],
            clone_dir,
            timeout=_FETCH_TIMEOUT,
            what=f"fetch PR #{n} head",
        )
        head = (
            _run(
                runner,
                ["git", "rev-parse", f"refs/remotes/origin/pr/{n}"],
                clone_dir,
                timeout=_QUICK_TIMEOUT,
                what="resolve the PR head sha",
            )
            or ""
        ).strip()

        base_branch = _base_branch(runner, clone_dir, pr_ref)
        _run(
            runner,
            ["git", "fetch", "-q", "origin", base_branch],
            clone_dir,
            timeout=_FETCH_TIMEOUT,
            what=f"fetch base branch {base_branch}",
        )
        base = (
            _run(
                runner,
                ["git", "merge-base", f"origin/{base_branch}", head],
                clone_dir,
                timeout=_QUICK_TIMEOUT,
                what="compute the merge-base",
            )
            or ""
        ).strip()

        # Put the working tree at the PR head (advisory) — diff is read from objects.
        _run(
            runner,
            ["git", "checkout", "-q", "--detach", head],
            clone_dir,
            timeout=_QUICK_TIMEOUT,
            what="check out the PR head",
            allow_fail=True,
        )
        # part's gate needs a jj repo; init colocated, fall back to plain init.
        # `and` short-circuits: probe jj, then colocate only if absent, then plain
        # init only if colocate failed.
        _jj = dict(timeout=_QUICK_TIMEOUT, allow_fail=True)
        if (
            _run(runner, ["jj", "root"], clone_dir, what="probe jj", **_jj) is None
            and _run(
                runner,
                ["jj", "git", "init", "--colocate"],
                clone_dir,
                what="jj git init --colocate",
                **_jj,
            )
            is None
        ):
            _run(runner, ["jj", "git", "init"], clone_dir, what="jj git init", **_jj)
        # A PR's commits are pushed => jj treats them as immutable. This is a
        # throwaway clone we never push, so neutralize it so the gate reads the diff.
        _run(
            runner,
            ["jj", "config", "set", "--repo", "revset-aliases.'immutable_heads()'", "none()"],
            clone_dir,
            timeout=_QUICK_TIMEOUT,
            what="neutralize jj immutability",
            allow_fail=True,
        )

        if not base or not head:
            raise PrResolveError(f"resolved empty base/head for {pr_ref.slug}#{n}")
    except BaseException:
        # No poisoned half-clone left behind for the next run to choke on.
        _safe_rmtree(clone_dir, workdir_root)
        raise

    return ResolvedPr(
        repo_path=clone_dir,
        base=base,
        head=head,
        slug=pr_ref.slug,
        number=n,
        workdir=workdir_root,
        out_dir=out_dir,
    )
