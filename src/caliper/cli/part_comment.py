"""Advisory PR comment for a proposed cut — foreman/CI comment mode (#524).

# tested-by: tests/unit/test_part_comment.py

Pure rendering only: turns an already-computed ``CutList`` into a GitHub-
flavored markdown body proposing the cut. Deliberately carries no restack/jj
instructions — a reviewer reading this in a PR never ran ``caliper part``
themselves, so a "run this command" recipe would be noise, not help. The
comment is informational; nothing is applied by posting it.
"""

from __future__ import annotations

from caliper.core.models import CutList

MAX_PARTS_SHOWN = 15


def render_part_comment(cut: CutList, *, slug: str, pr_num: int) -> str:
    """Render the advisory comment body for ``slug#pr_num``'s proposed cut."""
    bucket_count = len({part.bucket for part in cut.parts})
    lines: list[str] = [
        f"## 🦅 Caliper — proposed cut for {slug}#{pr_num}",
        "",
        "> **Advisory** — this is a suggested commit split for review, not an "
        "automatic action. No branches, commits, or comments beyond this one "
        "were created.",
        "",
        f"**{cut.stats.part_count} parts across {bucket_count} buckets, "
        f"{cut.stats.file_count} files** "
        f"(head `{cut.provenance.head_sha[:12]}`)",
        "",
    ]
    for i, part in enumerate(cut.parts[:MAX_PARTS_SHOWN], start=1):
        flags = []
        if part.oversized:
            flags.append("OVERSIZED")
        if part.bucket.value == "delete":
            flags.append("DELETE-REVIEW")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        lines.append(f"{i}. **{part.bucket.value}** — {len(part.files)} files{flag_str}")
    remaining = len(cut.parts) - MAX_PARTS_SHOWN
    if remaining > 0:
        lines.append(f"- *...{remaining} more*")
    return "\n".join(lines)
