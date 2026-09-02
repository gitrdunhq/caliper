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
DEFAULT_OPT_IN_PLUGINS: frozenset[str] = frozenset({"scancode"})


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


def apply_include_tests(include_tests: bool) -> None:
    """Make ``--include-tests`` visible to every ignore-layer consumer this run.

    Settings are env-driven (``CaliperSettings``); the file source, manifest
    discovery and trivy each build their own pattern list from it.
    """
    import os

    if include_tests:
        os.environ["CALIPER_INCLUDE_TESTS"] = "1"
    else:
        os.environ.pop("CALIPER_INCLUDE_TESTS", None)


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


# --- task-022: `caliper review --runner auto|container|native` ---------------
#
# Container execution is a *presentation-tier* concern: the same review, run
# inside the pinned caliper image instead of the host interpreter. Every
# process spawn goes through the ToolRunnerPort seam so the whole flow is
# testable with a fake and no test ever spawns a real container.

RUNNER_CHOICES: tuple[str, ...] = ("auto", "container", "native")

#: Container engines probed, in preference order, by `--runner auto`.
CONTAINER_ENGINES: tuple[str, ...] = ("podman", "docker")

#: Image the container runner executes. Pinned by tag, not digest, so a local
#: `scripts/build.sh` result is usable.
CONTAINER_IMAGE: str = "caliper:latest"

#: The image's non-root user (Containerfile `USER caliper`). Never root.
CONTAINER_USER: str = "caliper"

#: Probes are cheap; keep them far below the scanner timeout.
_ENGINE_PROBE_TIMEOUT: int = 10

#: A containerized review is a full pipeline run — mirror pipeline_timeout.
_CONTAINER_RUN_TIMEOUT: int = 300


def detect_container_engine(runner) -> str | None:  # noqa: ANN001 - ToolRunnerPort
    """Return the first engine that is installed *and* has the image locally.

    Fail-open: any probe failure simply means "this engine is unusable", never
    an exception. Returns ``None`` when no engine qualifies.
    """
    from caliper.core.tool_runner import ToolInvocation

    for engine in CONTAINER_ENGINES:
        version = runner.run(
            ToolInvocation(cmd=[engine, "--version"], cwd=".", timeout=_ENGINE_PROBE_TIMEOUT)
        )
        if version.not_installed or version.exit_code != 0:
            continue
        image = runner.run(
            ToolInvocation(
                cmd=[engine, "image", "exists", CONTAINER_IMAGE],
                cwd=".",
                timeout=_ENGINE_PROBE_TIMEOUT,
            )
        )
        if image.not_installed or image.exit_code != 0:
            continue
        return engine
    return None


def resolve_runner_choice(runner_flag: str, runner) -> str:  # noqa: ANN001 - ToolRunnerPort
    """Resolve ``--runner`` into the concrete path to take: container|native.

    ``container`` and ``native`` are honoured verbatim (no probing). ``auto``
    probes for a usable engine and falls back to ``native`` with a single
    one-line stderr notice so a runner downgrade is never silent.
    """
    if runner_flag == "container":
        return "container"
    if runner_flag == "native":
        return "native"

    if detect_container_engine(runner) is not None:
        return "container"

    click.echo(
        "caliper: no container engine with " f"{CONTAINER_IMAGE} found; running native.",
        err=True,
    )
    return "native"


def forwarded_env(env: dict[str, str]) -> dict[str, str]:
    """Every ``CALIPER_*`` var, and nothing else.

    Host ``PATH``/credentials must not leak into the container: config is the
    only thing the containerized run needs from the caller's environment.
    """
    return {k: v for k, v in env.items() if k.startswith("CALIPER_")}


def build_container_invocation(
    *,
    repo_path: Path,
    temp_path: Path,
    env: dict[str, str],
    cli_args: list[str],
    engine: str = "podman",
    image: str = CONTAINER_IMAGE,
):
    """Assemble the container run command as a typed ToolInvocation.

    Pure: no filesystem or process access, so the mount/env/arg contract is
    assertable directly. The repo is mounted read-only — a review never writes
    to the tree under audit — while ``.temp`` is read-write for artifacts.
    ``cli_args`` are appended last, verbatim, after the image name.
    """
    from caliper.core.tool_runner import ToolInvocation

    cmd: list[str] = [engine, "run", "--rm"]
    cmd += ["--user", CONTAINER_USER]
    cmd += ["-v", f"{repo_path}:/workspace:ro"]
    cmd += ["-v", f"{temp_path}:/workspace/.temp:rw"]
    for key, value in sorted(forwarded_env(env).items()):
        cmd += ["-e", f"{key}={value}"]
    cmd.append(image)
    cmd += list(cli_args)

    return ToolInvocation(
        cmd=cmd,
        cwd=str(repo_path),
        timeout=_CONTAINER_RUN_TIMEOUT,
        env=None,
    )


def run_review_via_container(
    runner,  # noqa: ANN001 - ToolRunnerPort
    *,
    repo_path: Path,
    temp_path: Path,
    env: dict[str, str],
    cli_args: list[str],
    engine: str = "podman",
    image: str = CONTAINER_IMAGE,
):
    """Execute the containerized review and return its ToolResult unchanged.

    Exit code and stdout are passed through verbatim — the container process is
    the authority on the verdict, and re-deriving it here would let the host and
    container disagree.
    """
    invocation = build_container_invocation(
        repo_path=repo_path,
        temp_path=temp_path,
        env=env,
        cli_args=cli_args,
        engine=engine,
        image=image,
    )
    return runner.run(invocation)


def dispatch_review_to_container(runner_flag: str, repo_path: str) -> bool:
    """Run this review inside the caliper container when the runner resolves there.

    Returns True when the containerized run has completed (and this process has
    already emitted its output), so the caller must not also run natively.
    Exits with the container process's exit code verbatim.
    """
    import os
    import sys

    from caliper.core.subprocess_runner import SubprocessToolRunner

    if runner_flag == "native":
        return False

    tool_runner = SubprocessToolRunner()
    if resolve_runner_choice(runner_flag, tool_runner) != "container":
        return False

    # --runner container skips probing in resolve_runner_choice, so ask which
    # engine to drive here; fall back to the first preference if none qualifies
    # so an explicit --runner container still fails loudly rather than silently
    # dropping to native.
    engine = detect_container_engine(tool_runner) or CONTAINER_ENGINES[0]

    repo = Path(repo_path).resolve()
    temp = repo / ".temp"
    temp.mkdir(parents=True, exist_ok=True)

    # Strip --runner before forwarding (the inner process IS the container, so
    # re-resolving there would recurse) and repoint --repo-path at the mount:
    # the host path does not exist inside the container.
    cli_args: list[str] = []
    skip_next = False
    for arg in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "--runner":
            skip_next = True
            continue
        if arg.startswith("--runner="):
            continue
        if arg == "--repo-path":
            skip_next = True
            cli_args += ["--repo-path", "/workspace"]
            continue
        if arg.startswith("--repo-path="):
            cli_args.append("--repo-path=/workspace")
            continue
        cli_args.append(arg)

    result = run_review_via_container(
        tool_runner,
        repo_path=repo,
        temp_path=temp,
        env=dict(os.environ),
        cli_args=cli_args,
        engine=engine,
    )
    if result.stdout:
        click.echo(result.stdout, nl=False)
    if result.stderr:
        click.echo(result.stderr, nl=False, err=True)
    sys.exit(result.exit_code)
