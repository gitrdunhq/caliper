"""Tests for ``caliper part``'s CLI usage guards.

# tested-by: tests/unit/test_part_cmd.py

Pure argument-parsing checks: flag combinations that must never silently
no-op or half-run (e.g. --post-comment/--push without --pr, or alongside
--serve, which returns before the posting/pushing code would ever run).
Pure rendering is covered separately in tests/unit/test_part_render.py.
"""

from __future__ import annotations

from click.testing import CliRunner

from caliper.cli.part_cmd import part


def test_post_comment_requires_pr(tmp_path) -> None:
    # #524 bullet 3: foreman comment mode only ever fires for a --pr run — never
    # posts to GitHub without the operator naming a PR to post to.
    result = CliRunner().invoke(part, ["--post-comment", "--repo", str(tmp_path)])
    assert result.exit_code != 0
    assert "--post-comment requires --pr" in result.output


def test_post_comment_incompatible_with_serve(tmp_path) -> None:
    # --serve returns before the posting code ever runs — without this guard
    # the combination would silently no-op instead of erroring.
    result = CliRunner().invoke(
        part, ["--post-comment", "--pr", "1", "--serve", "--repo", str(tmp_path)]
    )
    assert result.exit_code != 0
    assert "--post-comment is incompatible with --serve" in result.output
