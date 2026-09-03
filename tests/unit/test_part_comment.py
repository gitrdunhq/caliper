"""Tests for ``cli.part_comment`` — the foreman/CI advisory PR comment (#524).

# tested-by: tests/unit/test_part_comment.py

Pure rendering: turns an already-computed ``CutList`` into a GitHub-flavored
markdown comment body proposing the cut, with no jj/restack instructions —
it's advisory only, posted by a CI job so a team sees the suggestion in
review without anyone running anything locally.
"""

from __future__ import annotations

from caliper.cli.part_comment import MAX_PARTS_SHOWN, render_part_comment
from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance


def _provenance() -> Provenance:
    return Provenance(
        caliper_version="0.2.47",
        base_sha="aaaa1111",
        head_sha="bbbb2222",
        rename_threshold=50,
        config_digest="d" * 16,
    )


def _stats(n: int, files: int) -> CutStats:
    return CutStats(part_count=n, file_count=files, size_p50=10, size_p90=20, move_logic_pure=True)


def _part(id_: str, bucket: ChangeType, *files: str, oversized: bool = False) -> Part:
    return Part(
        id=id_,
        files=sorted(files),
        bucket=bucket,
        size=len(files) * 10,
        opened_by=Kerf(fired_rule="bucket-end"),
        oversized=oversized,
    )


def _cutlist(*parts: Part) -> CutList:
    files = sum((len(p.files) for p in parts), 0)
    return CutList(parts=list(parts), provenance=_provenance(), stats=_stats(len(parts), files))


def test_header_names_the_pr() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py"))
    out = render_part_comment(cut, slug="owner/repo", pr_num=21)
    assert "owner/repo#21" in out


def test_is_explicitly_advisory_and_no_restack_instructions() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py"))
    out = render_part_comment(cut, slug="owner/repo", pr_num=21)
    assert "advisory" in out.lower()
    # The load-bearing property: no fenced command block a reviewer could paste
    # into a shell. A bare substring check ("restack" not in out) would pass
    # today for reasons unrelated to this guarantee and say nothing about a
    # future template that reintroduces a command via a different word.
    assert "```" not in out


def test_summary_counts_match_the_cutlist() -> None:
    cut = _cutlist(
        _part("p1", ChangeType.business, "a.py", "b.py"),
        _part("p2", ChangeType.logic, "c.py"),
    )
    out = render_part_comment(cut, slug="owner/repo", pr_num=21)
    assert "2 parts" in out
    assert "3 files" in out
    assert "2 buckets" in out


def test_each_part_is_listed_with_bucket_and_file_count() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"))
    out = render_part_comment(cut, slug="owner/repo", pr_num=21)
    assert "business" in out
    assert "2 files" in out or "(2)" in out


def test_oversized_part_is_flagged() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py", oversized=True))
    out = render_part_comment(cut, slug="owner/repo", pr_num=21)
    assert "OVERSIZED" in out


def test_truncates_beyond_max_parts_shown() -> None:
    parts = [_part(f"p{i}", ChangeType.logic, f"f{i}.py") for i in range(MAX_PARTS_SHOWN + 5)]
    cut = _cutlist(*parts)
    out = render_part_comment(cut, slug="owner/repo", pr_num=21)
    assert "5 more" in out


def test_head_sha_is_shown_for_traceability() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py"))
    out = render_part_comment(cut, slug="owner/repo", pr_num=21)
    assert "bbbb2222"[:12] in out or "bbbb2222" in out
