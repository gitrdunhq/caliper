"""Advisory PR comment for a proposed cut — foreman/CI comment mode (#524).

# tested-by: tests/unit/test_part_comment.py

Pure rendering only: turns an already-computed ``CutList`` into a GitHub-
flavored markdown body proposing the cut. Deliberately carries no restack/jj
instructions — a reviewer reading this in a PR never ran ``caliper part``
themselves, so a "run this command" recipe would be noise, not help. The
comment is informational; nothing is applied by posting it.
"""

from __future__ import annotations

from caliper.core.models import CutList, Part

MAX_PARTS_SHOWN = 15
MAX_FILES_SHOWN = 20


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


def render_stack_pr_body(part: Part, *, index: int, total: int, slug: str, pr_num: int) -> str:
    """Render one part's own PR body — part N of the stack (#524).

    Same "advisory, informational" posture as ``render_part_comment``: links
    back to the original PR and lists this part's files, but carries no
    restack/jj instructions — whoever reviews this PR never ran ``caliper
    part`` themselves.
    """
    lines: list[str] = [
        f"part {index} of {total} — split from " f"https://github.com/{slug}/pull/{pr_num}",
        "",
        f"**{part.bucket.value}** — {len(part.files)} files",
        "",
    ]
    for f in part.files[:MAX_FILES_SHOWN]:
        lines.append(f"- {f}")
    remaining = len(part.files) - MAX_FILES_SHOWN
    if remaining > 0:
        lines.append(f"- *...{remaining} more*")
    return "\n".join(lines)


def render_stack_link_comment(urls: list[str], *, slug: str, pr_num: int) -> str:
    """Render the comment posted on the original PR once the stack is fully
    open — a courtesy notification, not a status change to that PR."""
    if not urls:
        raise ValueError("cannot link an empty stack")
    lines: list[str] = [
        f"## 🦅 Caliper — {slug}#{pr_num} split into a stack of {len(urls)} PR(s)",
        "",
        "> This PR is left open and untouched. The split above is a "
        "parallel proposal — review and merge the stack below in order:",
        "",
    ]
    for i, url in enumerate(urls, start=1):
        lines.append(f"{i}. {url}")
    return "\n".join(lines)
