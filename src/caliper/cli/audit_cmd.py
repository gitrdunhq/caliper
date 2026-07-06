"""``caliper audit`` — holistic trust audit, concern by concern via LLM (Alley-Oop)."""

# tested-by: tests/unit/test_cli.py

from __future__ import annotations

import click

from caliper.cli.cli_shared import _AUDIT_SUFFIXES, _collect_repo_files, _write_output
from caliper.plugins import get_default_registry


@click.command(name="audit")
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
    from pathlib import Path

    from caliper.composition.bootstrap import bootstrap_review
    from caliper.core.repo_config import RepoConfig, load_repo_config
    from caliper.core.use_cases import ReviewOptions, review_repository
    from caliper.data.concern_review import render_audit_markdown, run_audit

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
