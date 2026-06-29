"""Substrate handoff — render the jj ``restack.sh`` that performs the cut.

# tested-by: tests/unit/test_part_script.py

``caliper part`` decides the cuts; it does not perform the git surgery. It emits
a file-granular jj script that hands the mechanics to jj so no interactive hunk
selection is needed. The renderer is pure (cut list + endpoints -> shell text);
the jj capability is probed separately (``probe_path_capability``) and passed in,
honouring "probe the installed CLI; do not hardcode flags from memory".

Mechanism (validated against real jj): the stock is the committed range
``base..head`` and the working copy ``@`` is clean (the gate enforces this). The
script reconstructs the cut list as a fresh stack on ``base`` by restoring each
part's file set from ``head`` (``jj restore --from <head> <paths>``), bottom-first.
Each restore is path-granular and non-interactive; the top of the resulting stack
reproduces ``head`` exactly. A rename's old path is restored alongside its new
path so the old path is removed.

Non-destructive ordering contract: capture, then build new, then verify, then
stop. The script never deletes, force-pushes, rebases a shared branch, or moves
the backup bookmark. Pushing and submitting stay printed comments the developer
runs by choice. Every script opens with the rollback header.
"""

from __future__ import annotations

import shlex

from caliper.core.models import ChangeType, CutList, PartTarget
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

_JJ_TIMEOUT = 30


def rollback_header(backup_bookmark: str, rescue_op_id: str) -> list[str]:
    """The rollback escape hatch printed atop every script and every cut list.

    A developer who does not know jj still has the one command that returns the
    repo to the pre-parting state.
    """
    return [
        "ROLLBACK — parting is non-destructive and fully reversible:",
        f"  backup bookmark : {backup_bookmark}  (anchors the pre-parting base; never moved)",
        f"  undo everything : jj op restore {rescue_op_id}",
    ]


def probe_path_capability(repo_path: str, runner: ToolRunnerPort | None = None) -> tuple[bool, str]:
    """Probe the installed jj for non-interactive path restore. Best-effort, never raises.

    Returns ``(can_reconstruct, jj_version)``. When jj is absent or the probe
    fails, returns ``(False, "")`` so the caller emits manual steps instead.
    """
    runner = runner or SubprocessToolRunner()

    def _run(args: list[str]) -> str:
        result = runner.run(ToolInvocation(cmd=["jj", *args], cwd=repo_path, timeout=_JJ_TIMEOUT))
        if result.not_installed or result.timed_out or result.exit_code != 0:
            return ""
        return result.stdout

    version = _run(["--version"]).strip()
    help_text = _run(["restore", "--help"]).upper()
    can = "FILESET" in help_text or "PATHS" in help_text or "PATH" in help_text
    return can, version


def _peel_message(index: int, total: int, part) -> str:
    note = ""
    if part.oversized:
        note = " OVERSIZED: over the size cap and cannot be split further in v0"
    elif part.bucket == ChangeType.delete:
        note = " DELETE: review for cross-part deletion safety (v0 has no graph for this)"
    return f"caliper part {index}/{total}: {part.bucket} {part.id}{note}"


def _restore_paths(part, old_paths: dict[str, str]) -> list[str]:
    """The paths to restore for a part: its files plus any rename old paths."""
    paths = list(part.files)
    for f in part.files:
        old = old_paths.get(f)
        if old and old not in paths:
            paths.append(old)
    return sorted(paths)


def render_restack_script(
    cutlist: CutList,
    *,
    base_rev: str,
    head_rev: str,
    backup_bookmark: str,
    rescue_op_id: str,
    jj_version: str,
    target: PartTarget,
    old_paths: dict[str, str] | None = None,
    validate_command: str = "",
    can_reconstruct: bool,
) -> str:
    """Render ``restack.sh`` for *cutlist*. Pure: same inputs -> same bytes.

    ``--target series`` changes only this script (one tip bookmark instead of one
    bookmark per part) — never the cut list, which is identical between targets.
    """
    old_paths = old_paths or {}
    n = len(cutlist.parts)
    lines: list[str] = ["#!/usr/bin/env bash", "#"]
    lines.append(f"# caliper part — restack script (target: {target})")
    lines.append("#")
    for h in rollback_header(backup_bookmark, rescue_op_id):
        lines.append(f"# {h}")
    lines.append("#")
    lines.append(
        f"# Non-interactive path reconstruction available: {'yes' if can_reconstruct else 'no'}"
    )
    lines.append(f"# jj version: {jj_version or 'unknown'}")
    lines.append("# NOTE: the validate command's side effects (installs, migrations, codegen) are")
    lines.append("#       OUTSIDE jj's rollback guarantee; it is advisory and off by default.")
    lines.append(
        f"# Provenance: base={cutlist.provenance.base_sha or '?'} "
        f"head={cutlist.provenance.head_sha or '?'} "
        f"config={cutlist.provenance.config_digest[:12]}"
    )
    lines.append("#")
    lines.append("set -euo pipefail")
    lines.append("")

    if not can_reconstruct:
        lines.append(
            "# The installed jj cannot reconstruct by path non-interactively. Listing each"
        )
        lines.append(
            "# part's file set with manual steps. Build each change by hand, bottom-first."
        )
        lines.append("")
        for i, part in enumerate(cutlist.parts, start=1):
            lines.append(f"# --- {_peel_message(i, n, part)} ---")
            for f in _restore_paths(part, old_paths):
                lines.append(f"#   {f}")
            lines.append("")
        lines.extend(_publish_footer(backup_bookmark))
        return "\n".join(lines) + "\n"

    # Build a fresh stack on base, peeling each part bottom-first via path restore.
    lines.append(f"jj new {shlex.quote(base_rev)} -m 'caliper part: reconstruct stock on base'")
    lines.append("")
    for i, part in enumerate(cutlist.parts, start=1):
        msg = _peel_message(i, n, part)
        quoted = " ".join(shlex.quote(p) for p in _restore_paths(part, old_paths))
        lines.append(f"# --- {msg} ---")
        lines.append(f"jj restore --from {shlex.quote(head_rev)} {quoted}")
        if validate_command:
            lines.append("# validate (advisory; side effects outside rollback):")
            lines.append(
                f"if ! ( {validate_command} ); then "
                f'echo "validate failed at part {i}/{n}" >&2; exit 1; fi'
            )
        lines.append(f"jj describe -r @ -m {shlex.quote(msg)}")
        if target == PartTarget.stack:
            lines.append(f"jj bookmark create caliper-part-{i} -r @")
        if i < n:
            lines.append("jj new -m 'caliper part: next'")
        lines.append("")

    if target == PartTarget.series:
        lines.append("# single tip bookmark for the whole series:")
        lines.append("jj bookmark create caliper-part-series -r @")
        lines.append("")

    lines.extend(_publish_footer(backup_bookmark))
    return "\n".join(lines) + "\n"


def _publish_footer(backup_bookmark: str) -> list[str]:
    """Push/submit stay printed comments — a force-push is the one irreversible boundary."""
    return [
        "# ============================================================",
        "# Publish when ready — run these YOURSELF. Parting never pushes or force-pushes.",
        "#   jj git push --bookmark <name>",
        "#   (open the PR(s) with your usual tool)",
        f"# The backup bookmark {backup_bookmark} is never moved or deleted by this script.",
        "# ============================================================",
    ]
