"""CLI entry point for the Review pipeline."""

# tested-by: tests/unit/test_cli.py

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import click
import structlog

from eedom.cli.watch import _IGNORE_DIRS, _WATCH_EXTENSIONS, DebounceTimer  # noqa: F401
from eedom.core.models import OperatingMode
from eedom.plugins import get_default_registry

logger = structlog.get_logger()


def _write_output(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


_ALLOWED_TEAMS: frozenset[str] = frozenset(
    {"backend", "frontend", "platform", "infra", "security", "data"}
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
    bypass = "EEDOM_ALLOW_GLOBAL" in os.environ
    if not _is_isolated_environment() and not bypass:
        click.echo(
            "ERROR: eedom must run in an isolated environment.\n"
            "\n"
            "  uvx eedom review --all              # recommended\n"
            "  pipx install eedom                   # persistent CLI\n"
            "  pip install eedom  (inside a venv)   # manual venv\n"
            "  docker run eedom                     # container\n"
            "\n"
            "Set EEDOM_ALLOW_GLOBAL=1 to override (not recommended).",
            err=True,
        )
        raise SystemExit(1)


@click.group()
@click.version_option(package_name="eedom")
def cli() -> None:
    """Eagle Eyed Dom — fully deterministic dependency and code review for CI."""
    _check_isolated_environment()


def _register_subcommands() -> None:
    from eedom.cli.inspect_cmds import check_health, healthcheck, plugins
    from eedom.cli.query_cmd import query

    cli.add_command(healthcheck)
    cli.add_command(check_health)
    cli.add_command(plugins)
    cli.add_command(query)


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
    required=True,
    type=str,
    callback=_validate_pr_url,
    help="PR URL for context and comments.",
)
@click.option(
    "--team",
    required=True,
    type=str,
    callback=_validate_team,
    help="Team name submitting the request.",
)
@click.option(
    "--operating-mode",
    required=True,
    type=click.Choice(["monitor", "advise"]),
    help="Operating mode.",
)
@click.option(
    "--output-json",
    type=click.Path(),
    default=None,
    help="Write machine-readable decision JSON to this path.",
)
def evaluate(
    repo_path: str,
    diff: str,
    pr_url: str,
    team: str,
    operating_mode: str,
    output_json: str | None,
) -> None:
    """Run the full review pipeline on dependency changes."""
    diff_text = _read_diff(diff)
    mode = OperatingMode(operating_mode)

    try:
        from eedom.core.config import EedomSettings

        config = EedomSettings()  # type: ignore[call-arg]
    except Exception:
        logger.warning(
            "config_load_failed", msg="Pipeline skipped — config unavailable (fail-open)"
        )
        click.echo("Pipeline skipped — configuration unavailable (fail-open).", err=True)
        sys.exit(0)

    try:
        import orjson

        from eedom.core.bootstrap import bootstrap as _bootstrap
        from eedom.core.pipeline import ReviewPipeline

        _context = _bootstrap(config)
        pipeline = ReviewPipeline(config, context=_context)
        decisions = pipeline.evaluate(
            diff_text=diff_text,
            pr_url=pr_url,
            team=team,
            mode=mode,
            repo_path=Path(repo_path),
        )

        if not decisions:
            click.echo("No dependency changes detected.")
            sys.exit(0)

        for decision in decisions:
            click.echo(decision.memo_text or "")

        if output_json and decisions:
            last = decisions[-1]
            p = Path(output_json)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(orjson.dumps(last.model_dump(mode="json"), option=orjson.OPT_INDENT_2))

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
@click.option("--all", "run_all", is_flag=True, help="Run all plugins.")
@click.option("--output", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "sarif", "json"]),
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
    """Run Eagle Eyed Dom plugin review on a repo or diff."""
    from eedom.core.bootstrap import bootstrap_review
    from eedom.core.plugin import PluginCategory
    from eedom.core.renderer import render_comment
    from eedom.core.repo_config import RepoConfig, load_repo_config
    from eedom.core.use_cases import ScanScope

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

    repo_config = (
        load_repo_config(repo) if (repo / ".eagle-eyed-dom.yaml").exists() else RepoConfig()
    )
    disabled_names: set[str] = set(repo_config.plugins.disabled or [])
    if disable:
        for _d in disable.split(","):
            disabled_names.add(_d.strip())
    disabled_names.discard("")
    enabled_names: set[str] = set(repo_config.plugins.enabled or [])
    if enable:
        for _e in enable.split(","):
            enabled_names.add(_e.strip())
    enabled_names.discard("")

    def _all_repo_files() -> list[str]:
        from eedom.core.ignore import load_ignore_patterns, should_ignore

        ignore_patterns = load_ignore_patterns(repo)
        files: list[str] = []
        for ext in ("*.py", "*.ts", "*.js", "*.tf", "*.yaml", "*.yml", "*.json", "*.swift"):
            files.extend(
                str(p)
                for p in repo.rglob(ext)
                if not should_ignore(str(p.relative_to(repo)), ignore_patterns)
            )
        return files

    def _diff_files() -> list[str]:
        from eedom.core.ignore import load_ignore_patterns, should_ignore

        ignore_patterns = load_ignore_patterns(repo)
        diff_text = _read_diff(diff)  # type: ignore[arg-type]
        files: list[str] = []
        for line in diff_text.split("\n"):
            if line.startswith("diff --git"):
                parts = line.split(" b/")
                if len(parts) == 2:
                    fpath = parts[1].strip()
                    full = (repo / fpath).resolve()
                    if not full.is_relative_to(repo.resolve()):
                        continue
                    if (full.exists() or not fpath.startswith(".git")) and not should_ignore(
                        fpath, ignore_patterns
                    ):
                        files.append(str(full))
        return files

    def _build_file_lists() -> tuple[list[str], list[str] | None]:
        """Return (files, repo_files). repo_files is non-None only in diff scope."""
        if resolved_scope == ScanScope.DIFF:
            return _diff_files(), _all_repo_files()
        if resolved_scope == ScanScope.FOLDER:
            from eedom.core.ignore import load_ignore_patterns, should_ignore

            ignore_patterns = load_ignore_patterns(repo)
            folder = Path(package).resolve()  # type: ignore[arg-type]
            files: list[str] = []
            for ext in ("*.py", "*.ts", "*.js", "*.tf", "*.yaml", "*.yml", "*.json", "*.swift"):
                files.extend(
                    str(p)
                    for p in folder.rglob(ext)
                    if not should_ignore(str(p.relative_to(repo)), ignore_patterns)
                )
            return files, None
        if diff:
            return _diff_files(), None
        return _all_repo_files(), None

    def run_review() -> None:
        from eedom.core.use_cases import ReviewOptions, review_repository

        files, repo_file_list = _build_file_lists()

        options = ReviewOptions(
            scanners=names,
            categories=cats,
            disabled=disabled_names,
            enabled=enabled_names,
            scope=resolved_scope or ScanScope.REPO,
        )
        review_result = review_repository(_ctx, files, repo, options, repo_files=repo_file_list)
        results = review_result.results

        if output_format == "sarif" or pr is not None:
            import orjson

            from eedom.core.sarif import to_sarif

            sarif_doc = to_sarif(
                results, repo_path=str(repo), max_findings_per_run=sarif_max_findings
            )

            if pr is not None:
                from eedom.core.pr_review import (
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
                _write_output(output, sarif_text)
                click.echo(f"SARIF written to {output}")
            else:
                click.echo(sarif_text)
            return

        if output_format == "json":
            from eedom.core.json_report import render_json

            json_text = render_json(results, repo=repo_name or str(repo))
            if output:
                _write_output(output, json_text)
                click.echo(f"JSON written to {output}")
            else:
                click.echo(json_text)
            return

        md = render_comment(
            results,
            repo=repo_name or str(repo),
            pr_num=pr_num,
            title=title,
            file_count=len(files),
            plugin_renderers=plugin_map,
        )
        if output:
            _write_output(output, md)
            click.echo(f"Review written to {output} ({len(md)} chars)")
        else:
            click.echo(md)

    run_review()

    if watch:
        from eedom.cli.watch import watch_and_rerun

        watch_and_rerun(repo_path=repo, run_review=run_review)


@cli.command()
@click.option("--repo-path", type=click.Path(exists=True), default=".", help="Repository root.")
@click.option("--model", type=str, default="openai/gpt-oss-120b:free", help="LLM model ID.")
@click.option(
    "--api-key", type=str, default=None, help="API key (or OPENROUTER_EEDOM / ANTHROPIC_API_KEY)."
)
@click.option("--endpoint", type=str, default="https://openrouter.ai/api", help="LLM API base URL.")
@click.option("--output", type=click.Path(), default=None, help="Write markdown report to file.")
@click.option("--scanners", type=str, default=None, help="Comma-separated plugin names.")
@click.option("--disable", type=str, default="", help="Comma-separated plugins to disable.")
@click.option("--timeout", type=int, default=120, help="Per-concern API timeout in seconds.")
@click.option("--max-tokens", type=int, default=12_000, help="Max tokens per concern cluster.")
def audit(
    repo_path: str,
    model: str,
    api_key: str | None,
    endpoint: str,
    output: str | None,
    scanners: str | None,
    disable: str,
    timeout: int,
    max_tokens: int,
) -> None:
    """Run a holistic trust audit — concern by concern via LLM (Alley-Oop)."""
    import os as _os

    from eedom.core.bootstrap import bootstrap_review
    from eedom.core.concern_review import render_audit_markdown, run_audit
    from eedom.core.ignore import load_ignore_patterns, should_ignore
    from eedom.core.repo_config import RepoConfig, load_repo_config
    from eedom.core.use_cases import ReviewOptions, review_repository

    repo = Path(repo_path)
    api_key = api_key or _os.environ.get("OPENROUTER_EEDOM") or _os.environ.get("ANTHROPIC_API_KEY")
    _ctx = bootstrap_review(registry_factory=get_default_registry)
    repo_config = (
        load_repo_config(repo) if (repo / ".eagle-eyed-dom.yaml").exists() else RepoConfig()
    )
    disabled_names = set(repo_config.plugins.disabled or [])
    if disable:
        disabled_names.update(d.strip() for d in disable.split(",") if d.strip())

    ignore_patterns = load_ignore_patterns(repo)
    files: list[str] = []
    for ext in ("*.py", "*.ts", "*.js", "*.tf", "*.yaml", "*.yml", "*.json"):
        files.extend(
            str(p)
            for p in repo.rglob(ext)
            if not should_ignore(str(p.relative_to(repo)), ignore_patterns)
        )

    names = scanners.split(",") if scanners else None
    options = ReviewOptions(scanners=names, disabled=disabled_names)
    click.echo(f"Running dom scanners on {len(files)} files…", err=True)
    review_result = review_repository(_ctx, files, repo, options)

    click.echo(f"Clustering and fanning out to {model}…", err=True)
    report = run_audit(
        repo_path=repo,
        results=review_result.results,
        files=files,
        model=model,
        api_key=api_key,
        endpoint=endpoint,
        timeout=timeout,
        max_tokens_per_cluster=max_tokens,
    )

    md = render_audit_markdown(report)
    if output:
        _write_output(output, md)
        click.echo(f"Audit written to {output} ({report.concern_count} concerns)")
    else:
        click.echo(md)


def _read_diff(diff_path: str) -> str:
    if diff_path == "-":
        return (
            sys.stdin.read()
        )  # nosemgrep: file-read-all-python — diff content must be fully buffered for parsing
    path = Path(diff_path)
    if not path.exists():
        logger.warning("diff_file_not_found", path=diff_path)
        return ""
    return path.read_text()


if __name__ == "__main__":
    cli()
