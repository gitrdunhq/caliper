"""Pure human-readable rendering for ``caliper part``'s CLI output.

# tested-by: tests/unit/test_part_cmd.py
# tested-by: tests/integration/test_part_e2e.py

Split out of ``part_cmd.py`` (a thin CLI adapter that parses args and
orchestrates) once it crossed the file-size review trigger: these three
functions are pure string formatting with no click/argument-parsing
dependency — a real seam between "how to present a cut list" and "how to
parse and orchestrate a part run", not an arbitrary split.
"""

from __future__ import annotations

from caliper.core.models import CutList
from caliper.core.part_script import rollback_header
from caliper.core.parting import diff_cutlists
from caliper.core.repo_config import OverrideRule


def render_cutlist_diff(previous: CutList | None, new: CutList) -> str:
    """What changed since the last cut on this PR (#524). Empty string when
    there's no prior cut to compare against (first run).

    Labels the head-sha transition explicitly: a part-count or bucket change
    with an UNMOVED head means config/overrides changed, not new commits —
    conflating the two would misread as "the PR moved" when it didn't.
    """
    if previous is None:
        return ""
    diff = diff_cutlists(previous, new)
    old_head = (previous.provenance.head_sha or "?")[:12]
    new_head = (new.provenance.head_sha or "?")[:12]
    head_moved = previous.provenance.head_sha != new.provenance.head_sha
    config_changed = previous.provenance.config_digest != new.provenance.config_digest
    lines: list[str] = ["", f"since the last cut (head {old_head} -> {new_head}):"]
    if not diff.changed:
        if not head_moved and config_changed:
            lines.append("  same base/head; changed by config/overrides")
        else:
            lines.append("  no change since the last cut")
        return "\n".join(lines)
    if not head_moved and config_changed:
        lines.append("  head unchanged; below reflects a config/override change, not new commits")
    for f in diff.added_files:
        lines.append(f"  + {f}")
    for f in diff.removed_files:
        lines.append(f"  - {f}")
    for f, old_bucket, new_bucket in diff.moved_files:
        lines.append(f"  ~ {f}  {old_bucket.value} -> {new_bucket.value}")
    if diff.part_count_before != diff.part_count_after:
        lines.append(f"  parts: {diff.part_count_before} -> {diff.part_count_after}")
    return "\n".join(lines)


def render_cutlist(cut: CutList, *, backup_bookmark: str | None, rescue_op_id: str | None) -> str:
    """Human-readable cut list, opening with the rollback header (escape hatch)."""
    lines: list[str] = []
    if backup_bookmark and rescue_op_id:
        for h in rollback_header(backup_bookmark, rescue_op_id, backend=cut.provenance.backend):
            lines.append(h)
    else:
        lines.append("ROLLBACK — the rollback header was emitted with the original restack.sh")
    lines.append("")
    p = cut.provenance
    bucket_count = len({part.bucket for part in cut.parts})
    cap_str = "none (1 part/bucket)" if cut.size_cap is None else str(cut.size_cap)
    lines.append(
        f"cut list — {cut.stats.part_count} parts across {bucket_count} buckets, "
        f"{cut.stats.file_count} files, cap {cap_str} "
        f"(size p50={cut.stats.size_p50} p90={cut.stats.size_p90})"
    )
    lines.append(
        f"provenance: caliper {p.caliper_version or '?'}  base={p.base_sha or '?'}  "
        f"head={p.head_sha or '?'}  rename={p.rename_threshold}%  cfg={p.config_digest[:12]}"
    )
    lines.append("(proposal, not a verdict — bottom of stack first)")
    lines.append("")
    for i, part in enumerate(cut.parts, start=1):
        flags = []
        if part.oversized:
            flags.append("OVERSIZED")
        if part.bucket.value == "delete":
            flags.append("DELETE-REVIEW")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        lines.append(
            f"  {i}. {part.bucket} ({len(part.files)} files, size {part.size}) "
            f"kerf={part.opened_by.fired_rule}{flag_str}"
        )
        for f in part.files:
            reason = cut.match_reasons.get(f)
            lines.append(f"       {f}" + (f"  [{reason}]" if reason else ""))
    if cut.ambiguities:
        lines.append("")
        lines.append("ambiguities (emitted as logic, review classification):")
        for a in cut.ambiguities:
            lines.append(f"  - {a.file}: {a.reason}")
    return "\n".join(lines) + "\n"


def render_overrides_yaml(rules: list[OverrideRule]) -> str:
    """Paste-ready ``parting.overrides`` block for the suggested rules (print mode)."""
    lines = ["parting:", "  overrides:"]
    for r in rules:
        lines.append(f"    - glob: {r.glob!r}")
        lines.append(f"      bucket: {r.bucket.value}")
        if r.note:
            lines.append(f"      note: {r.note!r}")
    return "\n".join(lines)
