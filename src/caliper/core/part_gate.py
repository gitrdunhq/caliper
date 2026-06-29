"""Parting safety gate — non-destructive precondition checks before any surgery.
# tested-by: tests/unit/test_part_gate.py

Parting hands the git surgery to jj, which gives reversibility by construction
(every command is one entry in the operation log, undoable with ``jj undo`` /
``jj op restore``). This module enforces the preconditions that make that
guarantee hold, and runs them **before anything is touched**: if any check fails
the gate aborts with no state change.

All jj/git IO runs through the ``ToolRunnerPort`` seam so the gate is fully
testable with a fake runner and no real jj (jj need not be installed to test the
logic). The gate is fail-closed: an unexpected git/jj failure aborts.

Determinism caution honoured here: every revset is resolved to explicit commit
ids at gate time and those ids are returned for the provenance. The caller pins
them and never re-evaluates a named revset mid-run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from caliper.core.parting import PartingError
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

_GIT_TIMEOUT = 30
_JJ_TIMEOUT = 30
_COMMIT_ID_TEMPLATE = 'commit_id ++ "\\n"'


class PartingGateError(PartingError):
    """Raised when a precondition fails — the gate aborts before any state change.

    ``case`` is a stable identifier for the failing precondition so callers and
    tests can branch on the reason without string matching.
    """

    def __init__(self, case: str, message: str) -> None:
        super().__init__(message)
        self.case = case


@dataclass(frozen=True)
class GateResult:
    """Outcome of a passing gate — the rescue point and the pinned commit ids."""

    backup_bookmark: str
    rescue_op_id: str
    jj_version: str
    resolved_revsets: dict[str, str] = field(default_factory=dict)


def _git_base(root: Path) -> list[str]:
    return ["git", "-c", f"safe.directory={root}"]


def _run(runner: ToolRunnerPort, root: Path, cmd: list[str], timeout: int) -> str:
    result = runner.run(ToolInvocation(cmd=cmd, cwd=str(root), timeout=timeout))
    if result.not_installed:
        raise PartingGateError("missing-jj", f"required tool not installed: {cmd[0]}")
    if result.timed_out:
        raise PartingError(f"{cmd[0]} timed out after {timeout}s")
    if result.exit_code != 0:
        raise PartingError(
            f"{' '.join(cmd)} failed (exit {result.exit_code}): {result.stderr[:300]}"
        )
    return result.stdout


def _jj(runner: ToolRunnerPort, root: Path, args: list[str]) -> str:
    return _run(runner, root, ["jj", *args], _JJ_TIMEOUT)


def _git(runner: ToolRunnerPort, root: Path, args: list[str]) -> str:
    return _run(runner, root, [*_git_base(root), *args], _GIT_TIMEOUT)


def _resolve(runner: ToolRunnerPort, root: Path, revset: str) -> str:
    """Resolve a revset to a single explicit commit id (first match), pinned."""
    out = _jj(runner, root, ["log", "-r", revset, "--no-graph", "-T", _COMMIT_ID_TEMPLATE])
    ids = [line.strip() for line in out.splitlines() if line.strip()]
    return ids[0] if ids else ""


def _revset_ids(runner: ToolRunnerPort, root: Path, revset: str) -> list[str]:
    out = _jj(runner, root, ["log", "-r", revset, "--no-graph", "-T", _COMMIT_ID_TEMPLATE])
    return [line.strip() for line in out.splitlines() if line.strip()]


def run_gate(
    repo_path: Path,
    base: str,
    head: str,
    *,
    timestamp: str,
    runner: ToolRunnerPort | None = None,
    force: bool = False,
) -> GateResult:
    """Run all preconditions; on success record a rescue point and backup bookmark.

    Aborts with ``PartingGateError`` (no state change) on: missing jj, a non-jj
    repo, a dirty working copy, untracked non-ignored files, a present git stash,
    an already-pushed target, or a stock that overlaps immutable history. The
    backup bookmark (the only state change) is created last, after every check
    passes.
    """
    runner = runner or SubprocessToolRunner()
    root = repo_path
    stock_revset = f"{base}..{head}"
    resolved: dict[str, str] = {}

    # 1. jj present and the repo is jj / colocated.
    jj_version = _jj(runner, root, ["--version"]).strip()
    _jj(runner, root, ["root"])  # raises if not a jj repo

    # 2. Clean tree — authoritative check is jj-native (the working copy is @).
    st = _jj(runner, root, ["st"])
    if "Working copy changes:" in st:
        raise PartingGateError(
            "dirty-tree",
            "working copy has uncommitted changes; commit them into a change or run "
            "`jj new` to set them aside before parting",
        )

    # 3. No untracked, non-ignored files (jj would snapshot them into the stock).
    untracked = _git(runner, root, ["ls-files", "-o", "--exclude-standard"]).strip()
    if untracked:
        raise PartingGateError(
            "untracked-files",
            "untracked, non-ignored files present; gitignore them or remove them first",
        )

    # 4. No git stash (jj does not see it — outside the op log / rollback guarantee).
    if _git(runner, root, ["stash", "list"]).strip():
        raise PartingGateError(
            "git-stash",
            "a git stash is present; it is outside jj's operation log and cannot be "
            "protected — resolve it before parting",
        )

    # 5. Target not already on a remote, expressed as a revset (not string matching).
    if not force and _revset_ids(runner, root, "@ & ::(remote_bookmarks())"):
        raise PartingGateError(
            "already-pushed",
            "the working copy is reachable from a remote bookmark (already pushed); "
            "refusing to rewrite shared history (use force to override)",
        )

    # 6. Freeze shared history: none of the stock may overlap immutable() commits.
    if _revset_ids(runner, root, f"({stock_revset}) & immutable()"):
        raise PartingGateError(
            "immutable-overlap",
            "the stock overlaps immutable history (at/below trunk); jj would refuse "
            "to rewrite it — re-base the work above trunk first",
        )

    # Resolve every revset to explicit commit ids and pin them (for provenance).
    resolved["base"] = _resolve(runner, root, base)
    resolved["head"] = _resolve(runner, root, head)
    resolved["@"] = _resolve(runner, root, "@")
    resolved["trunk"] = _resolve(runner, root, "trunk()")

    # 7. Rescue point: the current op-log head (read-only).
    rescue_op_id = (
        _jj(runner, root, ["op", "log", "--no-graph", "--limit", "1", "-T", 'id ++ "\\n"'])
        .splitlines()[0]
        .strip()
    )

    # 8. The only state change: an additive backup bookmark anchored on the
    # resolved BASE. The restack rebuilds the parts as children of base, so the
    # rebuilt stack is exactly the linear chain `backup+::@`. Full rollback is via
    # `jj op restore <rescue_op_id>`; the original commits remain in the op log.
    backup = f"caliper-part-backup-{timestamp}"
    _jj(runner, root, ["bookmark", "create", backup, "-r", resolved["base"]])

    return GateResult(
        backup_bookmark=backup,
        rescue_op_id=rescue_op_id,
        jj_version=jj_version,
        resolved_revsets=resolved,
    )
