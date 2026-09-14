"""Tests for ``caliper part``'s CLI usage guards.

# tested-by: tests/unit/test_part_cmd.py

Pure argument-parsing checks: flag combinations that must never silently
no-op or half-run (e.g. --post-comment/--push without --pr, or alongside
--serve, which returns before the posting/pushing code would ever run).
Pure rendering is covered separately in tests/unit/test_part_render.py.
"""

from __future__ import annotations

import click
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


class TestRepoPathFlagParity:
    """`--repo-path` must mean "the repository root" on every command.

    It did not. `caliper review` took `--repo-path`; `caliper part` took only
    `--repo`. Worse, `--repo` is not a synonym: on `review` it names a GitHub
    `owner/name` slug for --pr mode, while on `part` it is a filesystem path.
    The same flag meant two different things on sibling commands, and reaching
    for the one you learned from the other command costs a failed run:

        Error: No such option '--repo-path'. Did you mean '--repo'?

    `--repo-path` is now the portable spelling for a path on both. `--repo`
    keeps its existing meaning on each command so nothing breaks.
    """

    @staticmethod
    def _opts(name: str) -> set[str]:
        from caliper.cli.main import cli

        cmd = cli.get_command(None, name)
        return {o for p in cmd.params for o in getattr(p, "opts", [])}

    def test_part_accepts_repo_path(self) -> None:
        assert "--repo-path" in self._opts("part")

    def test_part_still_accepts_repo(self) -> None:
        """Back-compat: the existing spelling keeps working."""
        assert "--repo" in self._opts("part")

    def test_review_still_accepts_repo_path(self) -> None:
        assert "--repo-path" in self._opts("review")

    def test_repo_path_names_a_path_on_both_commands(self) -> None:
        """Same flag, same meaning: a filesystem path, not a GitHub slug."""
        from caliper.cli.main import cli

        for name in ("part", "review"):
            cmd = cli.get_command(None, name)
            param = next(p for p in cmd.params if "--repo-path" in getattr(p, "opts", []))
            assert isinstance(param.type, click.Path), f"{name}: --repo-path is not a path"

    def test_part_repo_and_repo_path_are_the_same_parameter(self) -> None:
        """Aliases, not two competing options that could disagree."""
        from caliper.cli.main import cli

        cmd = cli.get_command(None, "part")
        holders = [p for p in cmd.params if {"--repo", "--repo-path"} & set(getattr(p, "opts", []))]
        assert len(holders) == 1, "--repo and --repo-path must be one parameter on part"
