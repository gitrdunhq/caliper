"""Helpers extracted from cli.main.review() — input resolution and output rendering.

# tested-by: tests/unit/test_review_cmd.py

Split out of the `review()` Click command (cyclomatic complexity 74) to isolate the
two branchy concerns — building the file list for a scan scope, and formatting/
emitting the scan result — as independently testable functions. No behavior change:
each function's body is the original inline code, moved verbatim.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import click

from caliper.core.repo_config import RepoConfig
from caliper.core.use_cases import ScanScope

if TYPE_CHECKING:
    from caliper.core.review_summary import ReviewSummary


# Plugins that are expensive or noisy enough that they should never run
# just because a repo config or --disable list happens to be silent about
# them. Off by default; --enable <name> (or repo config plugins.enabled)
# overrides per run_all's disabled/enabled precedence rule.
DEFAULT_OPT_IN_PLUGINS: frozenset[str] = frozenset({"clamav"})


def resolve_plugin_selection(
    repo_config: RepoConfig, *, disable: str, enable: str
) -> tuple[set[str], set[str]]:
    """Merge --disable/--enable CLI flags into the repo config's plugin lists."""
    disabled_names: set[str] = set(DEFAULT_OPT_IN_PLUGINS)
    disabled_names |= set(repo_config.plugins.disabled or [])
    if disable:
        for _d in disable.split(","):
            disabled_names.add(_d.strip())
    disabled_names.discard("")

    enabled_names: set[str] = set(repo_config.plugins.enabled or [])
    if enable:
        for _e in enable.split(","):
            enabled_names.add(_e.strip())
    enabled_names.discard("")

    return disabled_names, enabled_names


def build_file_lists(
    *,
    repo: Path,
    resolved_scope: ScanScope | None,
    diff: str | None,
    package: str | None,
    collect_repo_files: Callable[[Path, tuple[str, ...]], list[str]],
    read_diff: Callable[[str], str],
    review_suffixes: tuple[str, ...],
) -> tuple[list[str], list[str] | None]:
    """Return (files, repo_files). repo_files is non-None only in diff scope."""

    def _all_repo_files() -> list[str]:
        return collect_repo_files(repo, review_suffixes)

    def _diff_files() -> list[str]:
        from caliper.core.ignore import load_ignore_patterns, should_ignore

        ignore_patterns = load_ignore_patterns(repo)
        diff_text = read_diff(diff)  # type: ignore[arg-type]
        files: list[str] = []
        for line in diff_text.split("\n"):
            if line.startswith("diff --git"):
                parts = line.split(" b/")
                if len(parts) == 2:
                    fpath = parts[1].strip()
                    full = (repo / fpath).resolve()
                    if not full.is_relative_to(repo.resolve()):
                        continue
                    if (
                        full.exists()
                        and not fpath.startswith(".git")
                        and not should_ignore(fpath, ignore_patterns)
                    ):
                        files.append(str(full))
        return files

    if resolved_scope == ScanScope.DIFF:
        return _diff_files(), _all_repo_files()
    if resolved_scope == ScanScope.FOLDER:
        folder = Path(package).resolve()  # type: ignore[arg-type]
        return collect_repo_files(folder, review_suffixes), None
    if diff:
        return _diff_files(), None
    return _all_repo_files(), None


def render_review_output(
    *,
    results: list,
    summary: ReviewSummary | None,
    output_format: str,
    output: str | None,
    pr: int | None,
    gh_repo: str | None,
    sarif_max_findings: int,
    repo: Path,
    repo_name: str,
    pr_num: int,
    title: str,
    file_count: int,
    plugin_map: dict,
    write_output: Callable[[str, str], None],
) -> None:
    """Format and emit review results (sarif/PR-post, json, vex, or markdown).

    Mirrors review()'s original inline dispatch. Calls sys.exit(1) on a --pr
    posting failure or a GitHub repo/diff-files resolution error, matching the
    original behavior exactly.
    """
    if output_format == "sarif" or pr is not None:
        import orjson

        from caliper.core.sarif import to_sarif

        sarif_doc = to_sarif(
            results,
            repo_path=str(repo),
            max_findings_per_run=sarif_max_findings,
            summary=summary,
        )

        if pr is not None:
            from caliper.core.pr_review import (
                detect_gh_repo,
                get_pr_diff_files,
                post_review,
                sarif_to_review,
            )

            target_repo = gh_repo or detect_gh_repo()
            if not target_repo:
                click.echo("Could not detect GitHub repo. Use --repo owner/name.", err=True)
                sys.exit(1)

            try:
                diff_files = get_pr_diff_files(target_repo, pr)
            except RuntimeError as exc:
                click.echo(str(exc), err=True)
                sys.exit(1)
            pr_review = sarif_to_review(sarif_doc, diff_files)
            ok = post_review(target_repo, pr, pr_review)
            click.echo(
                f"{'Posted' if ok else 'Failed to post'} review on PR #{pr}: "
                f"{pr_review.event} ({len(pr_review.comments)} inline, "
                f"{len(pr_review.outside_diff)} outside diff)"
            )
            if not ok:
                sys.exit(1)
            return

        sarif_text = orjson.dumps(sarif_doc, option=orjson.OPT_INDENT_2).decode()
        if output:
            write_output(output, sarif_text)
            click.echo(f"SARIF written to {output}")
        else:
            click.echo(sarif_text)
        return

    if output_format == "json":
        from caliper.core.json_report import render_json

        json_text = render_json(results, repo=repo_name or str(repo), summary=summary)
        if output:
            write_output(output, json_text)
            click.echo(f"JSON written to {output}")
        else:
            click.echo(json_text)
        return

    if output_format == "vex":
        import orjson

        from caliper.core.vex import to_vex

        vex_text = orjson.dumps(to_vex(results), option=orjson.OPT_INDENT_2).decode()
        if output:
            write_output(output, vex_text)
            click.echo(f"VEX written to {output}")
        else:
            click.echo(vex_text)
        return

    from caliper.core.renderer import render_comment

    md = render_comment(
        results,
        repo=repo_name or str(repo),
        pr_num=pr_num,
        title=title,
        file_count=file_count,
        plugin_renderers=plugin_map,
        verdict=summary.verdict.value if summary else None,
    )
    if output:
        write_output(output, md)
        click.echo(f"Review written to {output} ({len(md)} chars)")
    else:
        click.echo(md)
