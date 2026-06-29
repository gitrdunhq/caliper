"""Stock producer — build classified ``Record`` objects from git, for parting.
# tested-by: tests/unit/test_part_stock.py

This is the *producer* side of the parting producer/consumer flow: it does the
git IO (the impure step) and hands the pure ``core.parting.part()`` consumer a
complete, already-classified stock. All git runs through the ``ToolRunnerPort``
seam (``core/tool_runner.py``) so the producer is testable with a fake runner and
no real repo.

Determinism over ambient config: every git invocation pins its flags and reads
no ambient git config that could change classification — fixed rename/copy
thresholds, a fixed rename limit, ``core.ignorecase=false`` — and the tracked
file universe comes from ``git ls-files``. The stock is computed from
``<base>..<head>`` here; a hand-supplied diff is never trusted (its provenance and
two-dot/three-dot semantics cannot be verified).

Fail-closed: this is the deliberate carve-out from caliper's fail-open design. A
missing git, a non-zero exit, or a timeout is a hard error (``PartingError``),
never a silent partial result — a degraded input would change the cut and break
determinism.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from caliper.core.models import ChangeType, Record
from caliper.core.parting import PartingError
from caliper.core.repo_config import PartingConfig
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

_GIT_TIMEOUT = 60
_SYMLINK_MODE = "120000"
_GITLINK_MODE = "160000"


@dataclass(frozen=True)
class Stock:
    """The producer's output: classified records plus the resolved endpoints."""

    records: list[Record]
    base_sha: str
    head_sha: str


def _git_base(root: Path) -> list[str]:
    """Pinned git prefix: tolerate foreign-owned mounts, ignore ambient ignorecase."""
    return ["git", "-c", f"safe.directory={root}", "-c", "core.ignorecase=false"]


def _run_git(runner: ToolRunnerPort, root: Path, args: list[str]) -> str:
    """Run a pinned git command, fail-closed on any non-success outcome."""
    result = runner.run(
        ToolInvocation(cmd=[*_git_base(root), *args], cwd=str(root), timeout=_GIT_TIMEOUT)
    )
    if result.not_installed:
        raise PartingError("git is not installed; parting requires git")
    if result.timed_out:
        raise PartingError(f"git timed out after {_GIT_TIMEOUT}s: git {' '.join(args)}")
    if result.exit_code != 0:
        raise PartingError(
            f"git failed (exit {result.exit_code}): git {' '.join(args)}\n{result.stderr[:400]}"
        )
    return result.stdout


def _match_globs(path: str, globs: list[str]) -> bool:
    """fnmatch *path* and its basename against any glob (``**`` treated loosely)."""
    base = path.rsplit("/", 1)[-1]
    for g in globs:
        if fnmatch.fnmatch(path, g) or fnmatch.fnmatch(base, g):
            return True
        # Support a leading "**/" by also matching the bare suffix anywhere.
        if g.startswith("**/") and fnmatch.fnmatch(path, g[3:]):
            return True
    return False


def _numstat_new_path(rest: str) -> str:
    """Resolve a numstat path field to the new path (handles rename arrows)."""
    if "{" in rest and " => " in rest:
        pre, after = rest.split("{", 1)
        mid, post = after.split("}", 1)
        new = mid.split(" => ", 1)[1]
        return pre + new + post
    if " => " in rest:
        return rest.split(" => ", 1)[1]
    return rest


def _parse_numstat(text: str) -> dict[str, int | None]:
    """Map new-path -> size (added+removed), or ``None`` for binary (``-`` columns)."""
    sizes: dict[str, int | None] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        added, removed, rest = line.split("\t", 2)
        path = _numstat_new_path(rest)
        if added == "-" or removed == "-":
            sizes[path] = None
        else:
            sizes[path] = int(added) + int(removed)
    return sizes


def _parse_ls_files_modes(text: str) -> dict[str, str]:
    """Parse ``git ls-files -s`` into new-path -> mode bits."""
    modes: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        meta, _, path = line.partition("\t")
        mode = meta.split(" ", 1)[0]
        modes[path] = mode
    return modes


# Glob precedence, most-specific-first. Each entry is (PartingConfig field name,
# resulting bucket). ``generated`` leads; the greedy generic ``config`` sits low so
# the specific buckets (ci_cd, infra, schema_contracts, supply_chain) win first;
# the architectural code tiers are last before the ``logic`` residual. This order
# IS the product — changing it changes classifications, so it is asserted by tests.
_GLOB_PRECEDENCE: tuple[tuple[str, ChangeType], ...] = (
    ("generated_globs", ChangeType.generated),
    ("security_policy_globs", ChangeType.security_policy),
    ("supply_chain_globs", ChangeType.supply_chain),
    ("ci_cd_globs", ChangeType.ci_cd),
    ("schema_contracts_globs", ChangeType.schema_contracts),
    ("test_globs", ChangeType.test),
    ("documentation_globs", ChangeType.documentation),
    ("config_globs", ChangeType.config),
    ("infra_globs", ChangeType.infra),
    ("data_globs", ChangeType.data),
    ("frontend_globs", ChangeType.frontend),
    ("business_globs", ChangeType.business),
)


def _classify_by_globs(path: str, cfg: PartingConfig) -> ChangeType:
    """Apply the ordered glob precedence to a path; ``logic`` if nothing matches.

    Pure path heuristics only — no structural facts and no override table (those
    are decided by ``_classify`` before this runs). ``logic`` is the honest
    "untiered code" residual, not a failure.
    """
    for field, bucket in _GLOB_PRECEDENCE:
        if _match_globs(path, getattr(cfg, field)):
            return bucket
    return ChangeType.logic


def _classify(
    status: str,
    new_path: str,
    size: int | None,
    mode: str | None,
    cfg: PartingConfig,
) -> ChangeType:
    """Classify one record from diff status, size, mode bits, and path globs only.

    Precedence (deterministic): structural facts first — delete, then move, then
    binary (binary content, symlink, gitlink, or type-change) — and these are
    never overridable. Then the ordered glob heuristics in ``_GLOB_PRECEDENCE``,
    falling to ``logic`` (untiered residual). The human override table is applied
    by the caller before the glob heuristics (it cannot reclassify structural
    facts). The pure ``part()`` later re-emits an over-delta move as ``logic``.
    """
    code = status[0]
    if code == "D":
        return ChangeType.delete
    if code in ("R", "C"):
        return ChangeType.move
    if (
        size is None  # numstat reported binary
        or code == "T"  # type change (e.g. file <-> symlink)
        or mode in (_SYMLINK_MODE, _GITLINK_MODE)
    ):
        return ChangeType.binary
    return _classify_by_globs(new_path, cfg)


def _parse_name_status(text: str) -> list[tuple[str, str, str | None]]:
    """Parse ``git diff --name-status`` into (status, new_path, old_path) tuples."""
    out: list[tuple[str, str, str | None]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        status = fields[0]
        if status[0] in ("R", "C"):
            old_path, new_path = fields[1], fields[2]
        else:
            old_path, new_path = None, fields[1]
        out.append((status, new_path, old_path))
    return out


def build_stock(
    repo_path: Path,
    base: str,
    head: str,
    cfg: PartingConfig,
    runner: ToolRunnerPort | None = None,
) -> Stock:
    """Compute the stock: classified records for ``<base>..<head>``. Fail-closed.

    The file is the unit (no hunk-level splitting in v0). Records are returned
    sorted by canonical key (new path) so the stock is itself order-stable; the
    pure ``part()`` is order-independent regardless.
    """
    runner = runner or SubprocessToolRunner()
    root = repo_path

    base_sha = _run_git(runner, root, ["rev-parse", base]).strip()
    head_sha = _run_git(runner, root, ["rev-parse", head]).strip()

    universe = {p for p in _run_git(runner, root, ["ls-files"]).splitlines() if p.strip()}
    modes = _parse_ls_files_modes(_run_git(runner, root, ["ls-files", "-s"]))

    diff_flags = [
        "diff",
        "--no-color",
        f"--find-renames={cfg.rename_threshold}%",
        f"--find-copies={cfg.copy_threshold}%",
        "-l",
        str(cfg.rename_limit),
    ]
    name_status = _run_git(runner, root, [*diff_flags, "--name-status", base, head])
    numstat = _run_git(runner, root, [*diff_flags, "--numstat", base, head])

    sizes = _parse_numstat(numstat)

    records: list[Record] = []
    for status, new_path, old_path in _parse_name_status(name_status):
        is_delete = status[0] == "D"
        # Exclude untracked stray paths via the ls-files universe; deletions are
        # gone at head so they are never in the universe — always keep them.
        if not is_delete and universe and new_path not in universe:
            continue
        size = sizes.get(new_path)
        change_type = _classify(status, new_path, size, modes.get(new_path), cfg)
        # binary records have no defined size
        rec_size = None if change_type == ChangeType.binary else (size or 0)
        records.append(
            Record(
                file=new_path,
                change_type=change_type,
                size=rec_size,
                old_path=old_path if change_type == ChangeType.move else None,
            )
        )

    records.sort(key=lambda r: r.file)
    return Stock(records=records, base_sha=base_sha, head_sha=head_sha)
