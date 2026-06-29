"""CLI entry point for the Review pipeline."""

# tested-by: tests/unit/test_cli.py

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import click
import structlog

from caliper.cli.watch import _IGNORE_DIRS, _WATCH_EXTENSIONS, DebounceTimer  # noqa: F401
from caliper.core.models import OperatingMode
from caliper.plugins import get_default_registry

logger = structlog.get_logger()

# Source-file suffixes the review/audit commands enumerate. Centralised so the
# file source (git ls-files vs. walk) is the single place that decides *which*
# files exist, and these decide which extensions we care about.
_REVIEW_SUFFIXES: tuple[str, ...] = (
    ".py",
    ".ts",
    ".js",
    ".tf",
    ".yaml",
    ".yml",
    ".json",
    ".swift",
)
_AUDIT_SUFFIXES: tuple[str, ...] = tuple(s for s in _REVIEW_SUFFIXES if s != ".swift")


def _collect_repo_files(
    root: Path, suffixes: tuple[str, ...], *, prefer: str | None = None
) -> list[str]:
    """Enumerate scannable files under *root* via the resolved file source.

    Replaces the ad-hoc ``rglob(ext)`` + ``should_ignore`` loops; the source
    (git ls-files when *root* is a usable repo, else an ignore-aware walk)
    applies caliper's exclusion rules uniformly.
    """
    from caliper.core.file_source import select_file_source

    source = select_file_source(root, prefer=prefer)
    return [str(p) for p in source.list_files(root, suffixes=suffixes)]


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
def cli() -> None:
    """Caliper — fully deterministic dependency and code review for CI."""
    _check_isolated_environment()


def _register_subcommands() -> None:
    from caliper.cli.inspect_cmd import inspect
    from caliper.cli.inspect_cmds import check_health, healthcheck, plugins, schema
    from caliper.cli.part_cmd import part
    from caliper.cli.query_cmd import query

    cli.add_command(healthcheck)
    cli.add_command(check_health)
    cli.add_command(plugins)
    cli.add_command(schema)
    cli.add_command(query)
    cli.add_command(part)
    cli.add_command(inspect)


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
    """Run Caliper plugin review on a repo or diff."""
    from caliper.composition.bootstrap import bootstrap_review
    from caliper.core.plugin import PluginCategory
    from caliper.core.renderer import render_comment
    from caliper.core.repo_config import RepoConfig, load_repo_config
    from caliper.core.use_cases import ScanScope

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
        return _collect_repo_files(repo, _REVIEW_SUFFIXES)

    def _diff_files() -> list[str]:
        from caliper.core.ignore import load_ignore_patterns, should_ignore

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
                    if (
                        full.exists()
                        and not fpath.startswith(".git")
                        and not should_ignore(fpath, ignore_patterns)
                    ):
                        files.append(str(full))
        return files

    def _build_file_lists() -> tuple[list[str], list[str] | None]:
        """Return (files, repo_files). repo_files is non-None only in diff scope."""
        if resolved_scope == ScanScope.DIFF:
            return _diff_files(), _all_repo_files()
        if resolved_scope == ScanScope.FOLDER:
            folder = Path(package).resolve()  # type: ignore[arg-type]
            return _collect_repo_files(folder, _REVIEW_SUFFIXES), None
        if diff:
            return _diff_files(), None
        return _all_repo_files(), None

    def run_review() -> None:
        from caliper.core.use_cases import ReviewOptions, review_repository

        files, repo_file_list = _build_file_lists()

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
        results = review_result.results
        summary = review_result.summary

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
                _write_output(output, sarif_text)
                click.echo(f"SARIF written to {output}")
            else:
                click.echo(sarif_text)
            return

        if output_format == "json":
            from caliper.core.json_report import render_json

            json_text = render_json(results, repo=repo_name or str(repo), summary=summary)
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
            verdict=summary.verdict.value if summary else None,
        )
        if output:
            _write_output(output, md)
            click.echo(f"Review written to {output} ({len(md)} chars)")
        else:
            click.echo(md)

    run_review()

    if watch:
        from caliper.cli.watch import watch_and_rerun

        watch_and_rerun(repo_path=repo, run_review=run_review)


@cli.command()
@click.option("--repo-path", type=click.Path(exists=True), default=".", help="Repository root.")
@click.option("--model", type=str, default="openai/gpt-oss-120b:free", help="LLM model ID.")
@click.option(
    "--api-key", type=str, default=None, help="API key (or OPENROUTER_CALIPER / ANTHROPIC_API_KEY)."
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

    from caliper.composition.bootstrap import bootstrap_review
    from caliper.core.concern_review import render_audit_markdown, run_audit
    from caliper.core.repo_config import RepoConfig, load_repo_config
    from caliper.core.use_cases import ReviewOptions, review_repository

    repo = Path(repo_path)
    api_key = (
        api_key or _os.environ.get("OPENROUTER_CALIPER") or _os.environ.get("ANTHROPIC_API_KEY")
    )
    _ctx = bootstrap_review(registry_factory=get_default_registry)
    repo_config = load_repo_config(repo) if (repo / ".caliper.yaml").exists() else RepoConfig()
    disabled_names = set(repo_config.plugins.disabled or [])
    if disable:
        disabled_names.update(d.strip() for d in disable.split(",") if d.strip())

    files = _collect_repo_files(repo, _AUDIT_SUFFIXES)

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


def _render_supply_chain_markdown(findings: list[dict], decision: str, triggered: list[str]) -> str:
    """Concise markdown report for the supply-chain-diff step."""
    icon = {"reject": "🚫", "needs_review": "⚠️", "approve_with_constraints": "⚠️"}.get(
        decision, "✅"
    )
    lines = [
        "## Supply-chain version-bump analysis",
        "",
        f"**Gate decision:** {icon} `{decision}`",
        "",
    ]
    if not findings:
        lines.append("_No dependency version changes detected in the diff._")
        return "\n".join(lines)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda d: sev_order.get(d.get("severity", "info"), 9)):
        sev = f.get("severity", "info").upper()
        pkg = f"{f.get('package', '')}@{f.get('version', '')}"
        lines.append(f"### {sev} — {f.get('id', '')} · `{pkg}`")
        lines.append("")
        lines.append(f.get("message", ""))
        for ev in (f.get("evidence") or [])[:5]:
            lines.append(f"- `{ev}`")
        narrative = ((f.get("scribe") or {}).get("threat_analysis") or {}).get("narrative")
        if narrative:
            lines.append("")
            lines.append(f"> **Threat analysis (advisory):** {narrative}")
        lines.append("")
    if triggered:
        lines.append("---")
        lines.append("**Triggered policy rules:** " + ", ".join(triggered))
    return "\n".join(lines)


@cli.command(name="supply-chain-diff")
@click.option("--repo-path", type=click.Path(), default=".", help="Repository root (for context).")
@click.option("--diff", required=True, type=str, help="Path to diff file, or '-' for stdin.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json", "sarif"]),
    default="markdown",
    help="Output format.",
)
@click.option("--output", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--operating-mode",
    type=click.Choice(["monitor", "advise"]),
    default="monitor",
    help="advise: exit non-zero when the gate rejects.",
)
def supply_chain_diff(
    repo_path: str,
    diff: str,
    output_format: str,
    output: str | None,
    operating_mode: str,
) -> None:
    """Threat-analyze dependency version bumps (separate, feature-flag-gated step).

    Fetches the source of both versions of every upgraded dependency in the diff,
    diffs them, scores deterministic supply-chain signals (which gate the build via
    OPA), and — when the optional LLM scribe is enabled — attaches an advisory
    data-driven narrative. NOT part of the normal scan; requires
    CALIPER_SUPPLY_CHAIN_DIFF_ENABLED=1.
    """
    import orjson

    try:
        from caliper.core.config import CaliperSettings

        settings = CaliperSettings()  # type: ignore[call-arg]
    except Exception:
        click.echo("supply-chain-diff skipped — configuration unavailable (fail-open).", err=True)
        sys.exit(0)

    if not settings.supply_chain_diff_enabled:
        click.echo(
            "supply-chain-diff is gated off. Enable it with "
            "CALIPER_SUPPLY_CHAIN_DIFF_ENABLED=1 to run this step.",
            err=True,
        )
        sys.exit(0)

    from caliper.composition.bootstrap import run_supply_chain_scan
    from caliper.core.plugin import PluginResult
    from caliper.core.supply_chain_diff import evaluate_gate

    diff_text = _read_diff(diff)
    findings = run_supply_chain_scan(diff_text, settings)

    # Optional advisory LLM narrative (opt-in; never affects the verdict).
    if "supply_chain_threat" in settings.enabled_scribes and settings.llm_enabled:
        from caliper.core.llm_client import LlmClient
        from caliper.core.scribe import ScribeContext
        from caliper.core.scribe_pass import scribe_findings
        from caliper.plugins.scribes.supply_chain_threat import SupplyChainThreatScribe

        scribe = SupplyChainThreatScribe(LlmClient(settings))
        ctx = ScribeContext(repo_path=repo_path, scribe_timeout=settings.scribe_timeout)
        findings = scribe_findings(findings, [scribe], ctx)

    evaluation = evaluate_gate(findings, settings)
    decision = evaluation.decision.value
    result = PluginResult(
        plugin_name="supply-chain-diff",
        category="supply_chain",
        findings=[f.to_dict() for f in findings],
    )

    if output_format == "json":
        from caliper.core.json_report import render_json

        text = render_json([result], repo=repo_path)
    elif output_format == "sarif":
        from caliper.core.sarif import to_sarif

        text = orjson.dumps(
            to_sarif([result], repo_path=repo_path), option=orjson.OPT_INDENT_2
        ).decode()
    else:
        text = _render_supply_chain_markdown(result.findings, decision, evaluation.triggered_rules)

    if output:
        _write_output(output, text)
        click.echo(f"Supply-chain analysis written to {output} ({decision})")
    else:
        click.echo(text)

    if operating_mode == "advise" and decision in ("reject", "needs_review"):
        sys.exit(1)
    sys.exit(0)


def _render_grounding_markdown(bundle: dict) -> str:
    """Render a grounding bundle (fact sheet + type context) as markdown."""
    fact_sheet = bundle.get("fact_sheet") or []
    type_context = bundle.get("type_context") or []
    lines = [
        "# Grounding bundle",
        "",
        (
            f"_provider: {bundle.get('provider', 'null')}; "
            f"{len(fact_sheet)} in-file defs, {len(type_context)} referenced type defs._"
        ),
        "",
        "## Fact sheet — symbols defined in the files under review",
        "Trust these signatures over assumptions about the code's shape.",
        "",
    ]
    if fact_sheet:
        for s in fact_sheet:
            sig = f" {s['signature']}" if s.get("signature") else ""
            lines.append(
                f"- `{s.get('kind', '')}` **{s.get('name', '')}**{sig} — "
                f"{s.get('file', '')}:{s.get('line', 0)}"
            )
    else:
        lines.append("_(no symbols resolved — fact sheet empty)_")
    lines.append("")
    lines.append("## Type context — contracts referenced from elsewhere")
    lines.append(
        "Before flagging a 'raw string', 'missing timeout', 'wrong type', or "
        "'unvalidated value', check whether the contract below already constrains it."
    )
    lines.append("")
    if type_context:
        for s in type_context:
            sig = f" {s['signature']}" if s.get("signature") else ""
            lines.append(
                f"- `{s.get('kind', '')}` **{s.get('name', '')}**{sig} — "
                f"{s.get('file', '')}:{s.get('line', 0)}"
            )
    else:
        lines.append("_(no cross-file type contracts resolved)_")
    lines.append("")
    return "\n".join(lines)


@cli.command(name="ground")
@click.option(
    "--files",
    "files",
    multiple=True,
    required=True,
    help="File(s) under review to ground (repeatable).",
)
@click.option(
    "--out",
    type=click.Path(),
    default=None,
    help="Write the bundle JSON here; if omitted, print to stdout.",
)
def ground(files: tuple[str, ...], out: str | None) -> None:
    """Produce a deterministic grounding bundle (separate, feature-flag-gated step).

    Emits a fact sheet (symbols defined in the given files) plus type context
    (type-like contracts referenced from elsewhere) so a downstream consumer
    starts grounded. NOT part of the normal scan; requires
    CALIPER_GROUNDING_ENABLED=1.
    """
    import json

    from caliper.core.config import CaliperSettings

    settings = CaliperSettings()  # type: ignore[call-arg]

    if not settings.grounding_enabled:
        click.echo(
            "grounding is gated off. Enable with CALIPER_GROUNDING_ENABLED=1 to run this step.",
            err=True,
        )
        sys.exit(0)

    from caliper.composition.bootstrap import run_grounding

    bundle = run_grounding(list(files), settings)
    payload = json.dumps(bundle, indent=2)

    if out:
        _write_output(out, payload)
        if out.endswith(".json"):
            md_path = out[: -len(".json")] + ".md"
            _write_output(md_path, _render_grounding_markdown(bundle))
        click.echo(
            f"Grounding bundle written to {out} "
            f"({len(bundle.get('fact_sheet') or [])} defs, "
            f"{len(bundle.get('type_context') or [])} type contexts)"
        )
    else:
        click.echo(payload)
    sys.exit(0)


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
