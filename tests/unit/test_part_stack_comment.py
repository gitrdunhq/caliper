"""Tests for stacked-PR body/comment rendering — ``cli.part_comment`` (#524).

# tested-by: tests/unit/test_part_stack_comment.py

Pure rendering: ``render_stack_pr_body`` is the body for one part's own PR
(links back to the original PR, states its position in the stack, lists its
files — no restack/jj instructions, same "advisory, informational" posture
as the whole-stack comment). ``render_stack_link_comment`` is what gets
posted on the original PR once the full stack is open, listing every stack
PR URL in order. Neither touches the filesystem or network.
"""

from __future__ import annotations

import pytest

from caliper.cli.part_comment import render_stack_link_comment, render_stack_pr_body
from caliper.core.models import ChangeType, Kerf, Part


def _part(bucket: ChangeType, *files: str, oversized: bool = False) -> Part:
    return Part(
        id="p1",
        files=sorted(files),
        bucket=bucket,
        size=len(files) * 10,
        opened_by=Kerf(fired_rule="bucket-end"),
        oversized=oversized,
    )


class TestRenderStackPrBody:
    def test_states_stack_position(self) -> None:
        part = _part(ChangeType.business, "a.py")
        out = render_stack_pr_body(part, index=2, total=4, slug="owner/repo", pr_num=21)
        assert "part 2 of 4" in out

    def test_links_to_the_original_pr(self) -> None:
        part = _part(ChangeType.business, "a.py")
        out = render_stack_pr_body(part, index=1, total=1, slug="owner/repo", pr_num=21)
        assert "https://github.com/owner/repo/pull/21" in out

    def test_names_bucket_and_file_count(self) -> None:
        part = _part(ChangeType.documentation, "a.md", "b.md")
        out = render_stack_pr_body(part, index=1, total=2, slug="owner/repo", pr_num=21)
        assert "documentation" in out
        assert "2" in out

    def test_lists_the_parts_files(self) -> None:
        part = _part(ChangeType.business, "a.py", "b.py")
        out = render_stack_pr_body(part, index=1, total=1, slug="owner/repo", pr_num=21)
        assert "a.py" in out
        assert "b.py" in out

    def test_truncates_beyond_cap_with_a_more_line(self) -> None:
        files = [f"f{i}.py" for i in range(30)]
        part = _part(ChangeType.logic, *files)
        out = render_stack_pr_body(part, index=1, total=1, slug="owner/repo", pr_num=21)
        assert "more" in out.lower()

    def test_never_contains_restack_or_jj_instructions(self) -> None:
        part = _part(ChangeType.business, "a.py")
        out = render_stack_pr_body(part, index=1, total=1, slug="owner/repo", pr_num=21)
        assert "```" not in out
        assert "jj " not in out

    def test_pure_same_inputs_same_output(self) -> None:
        part = _part(ChangeType.business, "a.py")
        a = render_stack_pr_body(part, index=1, total=3, slug="owner/repo", pr_num=21)
        b = render_stack_pr_body(part, index=1, total=3, slug="owner/repo", pr_num=21)
        assert a == b


class TestRenderStackLinkComment:
    def test_lists_urls_in_order(self) -> None:
        urls = [
            "https://github.com/owner/repo/pull/22",
            "https://github.com/owner/repo/pull/23",
            "https://github.com/owner/repo/pull/24",
        ]
        out = render_stack_link_comment(urls, slug="owner/repo", pr_num=21)
        for u in urls:
            assert u in out
        first_pos = out.index(urls[0])
        second_pos = out.index(urls[1])
        third_pos = out.index(urls[2])
        assert first_pos < second_pos < third_pos

    def test_numbers_urls_starting_at_one(self) -> None:
        urls = ["https://github.com/owner/repo/pull/22", "https://github.com/owner/repo/pull/23"]
        out = render_stack_link_comment(urls, slug="owner/repo", pr_num=21)
        assert "1" in out
        assert "2" in out

    def test_states_original_pr_left_open_and_untouched(self) -> None:
        urls = ["https://github.com/owner/repo/pull/22"]
        out = render_stack_link_comment(urls, slug="owner/repo", pr_num=21)
        assert "untouched" in out.lower() or "left open" in out.lower()

    def test_empty_urls_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            render_stack_link_comment([], slug="owner/repo", pr_num=21)

    def test_pure_same_inputs_same_output(self) -> None:
        urls = ["https://github.com/owner/repo/pull/22"]
        a = render_stack_link_comment(urls, slug="owner/repo", pr_num=21)
        b = render_stack_link_comment(urls, slug="owner/repo", pr_num=21)
        assert a == b
