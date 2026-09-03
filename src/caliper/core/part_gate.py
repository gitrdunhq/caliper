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
    """Outcome of a passing gate — the rescue point and the pinned commit ids.

    ``backend`` is ``"jj"`` or ``"git"`` (#520): which substrate the gate ran
    preconditions against and the restack script must target. For ``"git"``,
    ``rescue_op_id`` holds the pre-parting HEAD sha (not a jj operation id) —
    rollback is a hard reset to that sha, not an operation-log restore; see
    ``part_script.rollback_header``.
    """

    backup_bookmark: str
    rescue_op_id: str
    jj_version: str
    resolved_revsets: dict[str, str] = field(default_factory=dict)
    backend: str = "jj"


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


def detect_backend(runner: ToolRunnerPort, root: Path) -> str:
    """Probe which substrate is usable: ``"jj"`` (preferred) or ``"git"`` (#520).

    Non-raising probes only — this never mutates state. Prefers jj when both are
    usable (it gives the stronger op-log rollback guarantee); falls back to git
    when jj is absent or ``root`` is not a jj/colocated repo.
    """
    jj_probe = runner.run(ToolInvocation(cmd=["jj", "root"], cwd=str(root), timeout=_JJ_TIMEOUT))
    if not jj_probe.not_installed and jj_probe.exit_code == 0:
        return "jj"
    git_probe = runner.run(
        ToolInvocation(
            cmd=[*_git_base(root), "rev-parse", "--git-dir"], cwd=str(root), timeout=_GIT_TIMEOUT
        )
    )
    if not git_probe.not_installed and git_probe.exit_code == 0:
        return "git"
    raise PartingGateError("missing-vcs", "neither jj nor git is usable at this path")


def run_gate(
    repo_path: Path,
    base: str,
    head: str,
    *,
    timestamp: str,
    runner: ToolRunnerPort | None = None,
    force: bool = False,
    backend: str | None = None,
) -> GateResult:
    """Run all preconditions; on success record a rescue point and backup bookmark.

    ``backend`` picks the substrate (``"jj"`` or ``"git"``); auto-detected via
    ``detect_backend`` when omitted. See ``_gate_jj``/``_gate_git`` for the
    per-backend precondition set. Either path is fail-closed: an abort raises
    ``PartingGateError`` with no state change, and the backup ref (the only
    state change) is created last, after every check passes.
    """
    runner = runner or SubprocessToolRunner()
    backend = backend or detect_backend(runner, repo_path)
    if backend == "git":
        return _gate_git(runner, repo_path, base, head, timestamp=timestamp, force=force)
    return _gate_jj(runner, repo_path, base, head, timestamp=timestamp, force=force)


def _gate_jj(
    runner: ToolRunnerPort,
    root: Path,
    base: str,
    head: str,
    *,
    timestamp: str,
    force: bool,
) -> GateResult:
    """jj-backed preconditions: missing jj, a non-jj repo, a dirty working copy,
    untracked non-ignored files, a present git stash, an already-pushed target,
    or a stock that overlaps immutable history."""
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
        backend="jj",
    )


def _git_status_lines(runner: ToolRunnerPort, root: Path) -> list[str]:
    out = _git(runner, root, ["status", "--porcelain=v1", "--untracked-files=all"])
    return [line for line in out.splitlines() if line.strip()]


def _gate_git(
    runner: ToolRunnerPort,
    root: Path,
    base: str,
    head: str,
    *,
    timestamp: str,
    force: bool,
) -> GateResult:
    """git-only preconditions (#520) — the fallback when jj is absent.

    Mirrors ``_gate_jj``'s case taxonomy (dirty-tree, untracked-files, git-stash,
    already-pushed, immutable-overlap) but git has no operation log, so the
    rescue point is the current ref (branch name, or the HEAD sha if detached)
    captured BEFORE the gate runs — the restack script only ever creates new,
    additively-named branches and never touches this ref, so rollback is simply
    checking it back out and deleting the branches the script created (see
    ``part_script.rollback_header``), not a destructive reset.
    """
    resolved: dict[str, str] = {}

    # 1. Working tree must be clean: no tracked changes, no untracked files.
    status = _git_status_lines(runner, root)
    dirty = [line for line in status if not line.startswith("??")]
    if dirty:
        raise PartingGateError(
            "dirty-tree",
            "working tree has uncommitted changes; commit or stash them before parting",
        )
    untracked = [line for line in status if line.startswith("??")]
    if untracked:
        raise PartingGateError(
            "untracked-files",
            "untracked, non-ignored files present; gitignore them or remove them first",
        )

    # 2. No git stash (orthogonal state a rollback wouldn't restore either way).
    if _git(runner, root, ["stash", "list"]).strip():
        raise PartingGateError(
            "git-stash",
            "a git stash is present; resolve it before parting",
        )

    resolved["base"] = _git(runner, root, ["rev-parse", base]).strip()
    resolved["head"] = _git(runner, root, ["rev-parse", head]).strip()
    resolved["@"] = _git(runner, root, ["rev-parse", "HEAD"]).strip()
    # Best-effort only: no remote/origin/HEAD is a normal, valid setup — never abort for it.
    origin_probe = runner.run(
        ToolInvocation(
            cmd=[*_git_base(root), "rev-parse", "origin/HEAD"], cwd=str(root), timeout=_GIT_TIMEOUT
        )
    )
    resolved["trunk"] = origin_probe.stdout.strip() if origin_probe.exit_code == 0 else ""

    # 3. Target not already pushed: HEAD reachable from a remote-tracking branch.
    if not force and _git(runner, root, ["branch", "-r", "--contains", resolved["head"]]).strip():
        raise PartingGateError(
            "already-pushed",
            "the target is reachable from a remote-tracking branch (already pushed); "
            "refusing to rewrite shared history (use force to override)",
        )

    # 4. Freeze shared history: none of the stock may already be on a remote.
    # `--not --remotes` EXCLUDES commits reachable from any remote ref (it does
    # not add them as extra positive tips, despite reading that way) — so a
    # shorter result than the unfiltered range means some stock commit is
    # already on a remote.
    stock_range = f"{resolved['base']}..{resolved['head']}"
    full = _git(runner, root, ["rev-list", stock_range]).split()
    unshared = _git(runner, root, ["rev-list", stock_range, "--not", "--remotes"]).split()
    if not force and len(unshared) < len(full):
        raise PartingGateError(
            "immutable-overlap",
            "the stock overlaps commits already reachable from a remote-tracking "
            "branch — re-base the work above the unpushed tip first",
        )

    # 5. Rescue point: the ref checked out right now — a branch name when on one,
    # else the current HEAD sha (detached). Read-only; not moved by this gate.
    # `symbolic-ref` exits non-zero when detached, so this is a raw, non-raising
    # probe rather than `_git()` (which would raise on that exit code).
    branch_probe = runner.run(
        ToolInvocation(
            cmd=[*_git_base(root), "symbolic-ref", "-q", "--short", "HEAD"],
            cwd=str(root),
            timeout=_GIT_TIMEOUT,
        )
    )
    branch = branch_probe.stdout.strip() if branch_probe.exit_code == 0 else ""
    rescue_ref = branch or resolved["@"]

    # 6. The only state change: an additive backup branch anchored on base,
    # mirroring the jj bookmark contract. Never moved or deleted by the script.
    backup = f"caliper-part-backup-{timestamp}"
    _git(runner, root, ["branch", backup, resolved["base"]])

    return GateResult(
        backup_bookmark=backup,
        rescue_op_id=rescue_ref,
        jj_version="",
        resolved_revsets=resolved,
        backend="git",
    )
