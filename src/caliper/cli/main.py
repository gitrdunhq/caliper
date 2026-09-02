"""CLI entry point for the Review pipeline."""

# tested-by: tests/unit/test_cli.py

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import click
import structlog

from caliper.cli.cli_shared import (  # noqa: F401
    _REVIEW_SUFFIXES,
    _collect_repo_files,
    _read_diff,
    _write_output,
)
from caliper.cli.watch import _IGNORE_DIRS, _WATCH_EXTENSIONS, DebounceTimer  # noqa: F401
from caliper.core.models import OperatingMode
from caliper.plugins import get_default_registry

logger = structlog.get_logger()

_ALLOWED_TEAMS: frozenset[str] = frozenset(
    {"backend", "frontend", "platform", "infra", "security", "data", "unknown"}
)


def _validate_repo_path(ctx: click.Context, param: click.Parameter, value: str) -> str:
    """Validate that --repo-path exists and is a directory."""
    if value is None:
        return value  # type: ignore[return-value]
    path = Path(value)
    if not path.exists():
        raise click.BadParameter(f"Path '{value}' does not exist")
    if not path.is_dir():
        raise click.BadParameter(f"Path '{value}' is not a directory")
    return str(path.resolve())


def _validate_pr_url(ctx: click.Context, param: click.Parameter, value: str) -> str:
    """Validate that --pr-url is a GitHub pull request URL."""
    if value is None:
        return value  # type: ignore[return-value]
    if not re.match(r"https://github\.com/[^/]+/[^/]+/pull/\d+", value):
        raise click.BadParameter(
            f"Must be a valid GitHub PR URL "
            f"(e.g. https://github.com/owner/repo/pull/123), got: {value}"
        )
    return value


def _validate_team(ctx: click.Context, param: click.Parameter, value: str) -> str:
    """Validate that --team is in the allowed list."""
    if value is None:
        return value  # type: ignore[return-value]
    if value not in _ALLOWED_TEAMS:
        raise click.BadParameter(f"Team must be one of {sorted(_ALLOWED_TEAMS)}, got: {value}")
    return value


def _validate_gh_repo(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    """Validate --repo is in owner/name format."""
    if value is None:
        return value
    parts = value.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise click.BadParameter(
            f"Invalid GitHub repo format — expected owner/name (e.g. acme/my-repo), got: {value!r}"
        )
    return value


def _is_isolated_environment() -> bool:
    """Return True when running inside a venv, conda env, or container.

    Detection layers (#388 — avoid false negatives for uv-managed venvs):
    - stdlib venv / uv venv / pipx / uv tool: ``sys.prefix != sys.base_prefix``
    - venvs whose interpreter lost base-prefix detection (relocated or
      uv-managed pythons): ``pyvenv.cfg`` marker beside ``sys.prefix``
    - caller-activated venvs (``uv run`` / ``source activate`` set
      ``VIRTUAL_ENV``): accepted only if it points at a real venv
    - conda/mamba envs (full installs, prefix == base_prefix): ``CONDA_PREFIX``
    - containers: ``/.dockerenv`` or ``/run/.containerenv``
    """
    if sys.prefix != sys.base_prefix:
        return True
    if (Path(sys.prefix) / "pyvenv.cfg").is_file():
        return True
    virtual_env = os.environ.get("VIRTUAL_ENV", "")
    if virtual_env and (Path(virtual_env) / "pyvenv.cfg").is_file():
        return True
    if os.environ.get("CONDA_PREFIX"):
        return True
    return Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()


def _check_isolated_environment() -> None:
    """Abort if running outside a virtual environment or container."""
    bypass = "CALIPER_ALLOW_GLOBAL" in os.environ
    if not _is_isolated_environment() and not bypass:
        click.echo(
            "ERROR: caliper must run in an isolated environment.\n"
            "\n"
            "  uvx caliper review --all              # recommended\n"
            "  pipx install caliper                   # persistent CLI\n"
            "  pip install caliper  (inside a venv)   # manual venv\n"
            "  docker run caliper                     # container\n"
            "\n"
            "Set CALIPER_ALLOW_GLOBAL=1 to override (not recommended).",
            err=True,
        )
        raise SystemExit(1)


@click.group()
@click.version_option(package_name="caliper")
@click.option("-v", "--verbose", is_flag=True, help="Debug logging (or CALIPER_LOG_LEVEL=debug).")
def cli(verbose: bool) -> None:
    """Caliper — fully deterministic dependency and code review for CI."""
    import os

    from caliper.cli.logging_setup import configure_logging, resolve_log_level

    configure_logging(resolve_log_level(verbose=verbose, env=dict(os.environ)))
    _check_isolated_environment()


def _register_subcommands() -> None:
    from caliper.cli.baseline_cmd import baseline
    from caliper.cli.ground_cmd import ground
    from caliper.cli.init_cmd import init
    from caliper.cli.inspect_cmds import check_health, healthcheck, plugins, schema
    from caliper.cli.install_cmd import install_scanners
    from caliper.cli.part_cmd import part
    from caliper.cli.query_cmd import query
    from caliper.cli.supply_chain_diff_cmd import supply_chain_diff

    cli.add_command(healthcheck)
    cli.add_command(check_health)
    cli.add_command(plugins)
    cli.add_command(schema)
    cli.add_command(query)
    cli.add_command(part)
    cli.add_command(baseline)
    cli.add_command(supply_chain_diff)
    cli.add_command(ground)
    cli.add_command(install_scanners)
    cli.add_command(init)


_register_subcommands()


@cli.command()
@click.option(
    "--repo-path",
    required=True,
    type=click.Path(),
    callback=_validate_repo_path,
    help="Path to the repository root.",
)
@click.option("--diff", required=True, type=str, help="Path to diff file, or '-' for stdin.")
@click.option(
    "--pr-url",
    required=False,
    default=None,
    type=str,
    callback=_validate_pr_url,
    help="PR URL for context and comments. Optional; omit for local/non-PR runs.",
)
@click.option(
    "--team",
    required=False,
    default="unknown",
    type=str,
    callback=_validate_team,
    help='Team name submitting the request. Defaults to "unknown" when omitted.',
)
@click.option(
    "--operating-mode",
    required=True,
    type=click.Choice(["monitor", "advise"]),
    help="Operating mode.",
)
@click.option(
    "--output-json",
    type=str,
    default=None,
    help=(
        "Write machine-readable decision JSON to this path, or '-' to write "
        "to stdout (memo text is redirected to stderr in that mode so stdout "
        "stays clean, parseable JSON)."
    ),
)
def evaluate(
    repo_path: str,
    diff: str,
    pr_url: str | None,
    team: str,
    operating_mode: str,
    output_json: str | None,
) -> None:
    """Run the full review pipeline on dependency changes."""
    diff_text = _read_diff(diff)
    mode = OperatingMode(operating_mode)

    try:
        from caliper.core.config import CaliperSettings

        config = CaliperSettings()  # type: ignore[call-arg]
    except Exception:
        logger.warning(
            "config_load_failed", msg="Pipeline skipped — config unavailable (fail-open)"
        )
        click.echo("Pipeline skipped — configuration unavailable (fail-open).", err=True)
        sys.exit(0)

    try:
        import orjson

        from caliper.composition.bootstrap import bootstrap as _bootstrap
        from caliper.core.pipeline import ReviewPipeline

        _context = _bootstrap(config)
        pipeline = ReviewPipeline(config, context=_context)
        decisions = pipeline.evaluate(
            diff_text=diff_text,
            pr_url=pr_url,
            team=team,
            mode=mode,
            repo_path=Path(repo_path),
        )

        stdout_json = output_json == "-"

        if not decisions:
            click.echo("No dependency changes detected.", err=stdout_json)
            sys.exit(0)

        for decision in decisions:
            click.echo(decision.memo_text or "", err=stdout_json)

        if output_json and decisions:
            last = decisions[-1]
            payload = orjson.dumps(last.model_dump(mode="json"), option=orjson.OPT_INDENT_2)
            if stdout_json:
                sys.stdout.buffer.write(payload)
                sys.stdout.buffer.write(b"\n")
            else:
                p = Path(output_json)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(payload)

        sys.exit(0)

    except Exception:
        logger.error("pipeline_failed_unexpectedly", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--scope",
    type=click.Choice(["repo", "diff", "folder"]),
    default=None,
    help="Scan scope: repo (full), diff (changed files only), folder (single directory).",
)
@click.option("--diff", type=str, default=None, help="Path to diff file.")
@click.option("--repo-path", type=click.Path(exists=True), default=".", help="Repository root.")
@click.option("--scanners", type=str, default=None, help="Comma-separated plugin names.")
@click.option("--category", type=str, default=None, help="Comma-separated categories.")
@click.option(
    "--all",
    "run_all",
    is_flag=True,
    hidden=True,
    help="Deprecated no-op: a bare `caliper review` already runs every default plugin.",
)
@click.option("--output", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--include-tests",
    is_flag=True,
    help="Also scan test code (tests/, test_*.py, *.test.ts, ...); skipped by default.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "sarif", "json", "vex"]),
    default="markdown",
    help="Output format.",
)
@click.option(
    "--sarif-max-findings",
    type=int,
    default=1000,
    help="Max findings per plugin in SARIF output. 0 for no limit.",
)
@click.option("--pr-url", type=str, default="", help="PR URL for comment header.")
@click.option("--pr-num", type=int, default=0, help="PR number.")
@click.option("--title", type=str, default="PR Review", help="PR title.")
@click.option(
    "--watch",
    is_flag=True,
    help="Watch for file changes and re-run review (debounced 500 ms).",
)
@click.option(
    "--disable",
    type=str,
    default="",
    help="Comma-separated plugin names to disable.",
)
@click.option(
    "--enable",
    type=str,
    default="",
    help="Comma-separated plugin names to force-enable (overrides --disable).",
)
@click.option(
    "--package",
    type=click.Path(),
    default=None,
    help="Scan only this package directory.",
)
@click.option(
    "--pr",
    type=click.IntRange(min=1),
    default=None,
    help="Post findings as inline PR review comments via GitHub API. Requires gh CLI.",
)
@click.option(
    "--repo",
    "gh_repo",
    type=str,
    default=None,
    callback=_validate_gh_repo,
    is_eager=False,
    help="GitHub repo (owner/name) for --pr mode. Auto-detected if omitted.",
)
def review(
    scope: str | None,
    diff: str | None,
    repo_path: str,
    scanners: str | None,
    category: str | None,
    run_all: bool,
    output: str | None,
    include_tests: bool,
    output_format: str,
    sarif_max_findings: int,
    pr_url: str,
    pr_num: int,
    title: str,
    watch: bool,
    disable: str,
    enable: str,
    package: str | None,
    pr: int | None,
    gh_repo: str | None,
) -> None:
    """Run Caliper plugin review on a repo or diff."""
    from caliper.cli.review_cmd import (
        apply_include_tests,
        build_file_lists,
        render_review_output,
        resolve_plugin_selection,
    )
    from caliper.composition.bootstrap import bootstrap_review
    from caliper.core.plugin import PluginCategory
    from caliper.core.repo_config import RepoConfig, load_repo_config
    from caliper.core.use_cases import ScanScope

    if include_tests:
        apply_include_tests(True)
    resolved_scope = ScanScope(scope) if scope else None
    if resolved_scope == ScanScope.DIFF and not diff:
        raise click.UsageError("--scope diff requires --diff <path>")
    if resolved_scope == ScanScope.FOLDER and not package:
        raise click.UsageError("--scope folder requires --package <path>")

    _ctx = bootstrap_review(registry_factory=get_default_registry)
    registry = _ctx.analyzer_registry
    repo = Path(repo_path)
    names = scanners.split(",") if scanners else None
    cats = [PluginCategory(c.strip()) for c in category.split(",")] if category else None
    plugin_map = {p.name: p for p in registry.list()}
    repo_name = pr_url.split("github.com/")[-1].split("/pull")[0] if "github.com" in pr_url else ""

    repo_config = load_repo_config(repo) if (repo / ".caliper.yaml").exists() else RepoConfig()
    disabled_names, enabled_names = resolve_plugin_selection(
        repo_config, disable=disable, enable=enable
    )
    # Naming a plugin explicitly via --scanners is itself a request to run it —
    # it must win over a default-opt-out plugin (e.g. scancode) the same way
    # --enable does.
    if names:
        enabled_names |= set(names)

    def run_review() -> None:
        from caliper.core.use_cases import ReviewOptions, review_repository

        files, repo_file_list = build_file_lists(
            repo=repo,
            resolved_scope=resolved_scope,
            diff=diff,
            package=package,
            collect_repo_files=_collect_repo_files,
            read_diff=_read_diff,
            review_suffixes=_REVIEW_SUFFIXES,
        )

        options = ReviewOptions(
            scanners=names,
            categories=cats,
            disabled=disabled_names,
            enabled=enabled_names,
            scope=resolved_scope or ScanScope.REPO,
        )
        # Scope the *blocking* decision to the change under review when a diff was
        # supplied (the workflow passes --diff without --scope). A plain repo scan
        # leaves changed_files=None so the gate stays repo-wide.
        is_diff_scoped = diff is not None or resolved_scope == ScanScope.DIFF
        changed_files = set(files) if is_diff_scoped else None
        review_result = review_repository(
            _ctx, files, repo, options, repo_files=repo_file_list, changed_files=changed_files
        )

        render_review_output(
            results=review_result.results,
            summary=review_result.summary,
            output_format=output_format,
            output=output,
            pr=pr,
            gh_repo=gh_repo,
            sarif_max_findings=sarif_max_findings,
            repo=repo,
            repo_name=repo_name,
            pr_num=pr_num,
            title=title,
            file_count=len(files),
            plugin_map=plugin_map,
            write_output=_write_output,
        )
        if output_format == "markdown" and not output and not pr:
            from caliper.cli.install_cmd import offer_install
            from caliper.core.scanner_install import missing_binaries_from_results

            offer_install(missing_binaries_from_results(review_result.results))

    run_review()

    if watch:
        from caliper.cli.watch import watch_and_rerun

        watch_and_rerun(repo_path=repo, run_review=run_review)


if __name__ == "__main__":
    cli()
