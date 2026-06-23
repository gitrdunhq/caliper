"""Scanner inspection CLI commands — healthcheck, check-health, plugins, schema."""

from __future__ import annotations

import shutil

import click

from caliper.plugins import get_default_registry

_BINARY_MAP: dict[str, list[str] | None] = {
    "blast-radius": None,
    "cdk-nag": ["cdk"],
    "cfn-nag": ["cfn_nag_scan"],
    "clamav": ["clamscan"],
    "complexity": ["lizard"],
    "cpd": ["pmd"],
    "gitleaks": ["gitleaks"],
    "kube-linter": ["kube-linter"],
    "ls-lint": ["ls-lint"],
    "mypy": ["mypy", "pyright"],
    "opa": ["opa"],
    "osv-scanner": ["osv-scanner"],
    "scancode": ["scancode"],
    "semgrep": ["semgrep"],
    "supply-chain": None,
    "syft": ["syft"],
    "trivy": ["trivy"],
    "typos": ["typos"],
}


@click.command()
def healthcheck() -> None:
    """Check all registered scanners are available. Exits 1 if any are missing."""
    registry = get_default_registry()
    all_plugins = registry.list()
    ok = 0
    fail = 0
    for p in sorted(all_plugins, key=lambda x: x.name):
        binaries = _BINARY_MAP.get(p.name)
        if binaries is None:
            ok += 1
            click.echo(f"  ok       {p.name} (pure python)")
            continue
        found = any(shutil.which(b) for b in binaries)
        if found:
            ok += 1
            click.echo(f"  ok       {p.name}")
        else:
            fail += 1
            click.echo(f"  MISSING  {p.name} (needs: {', '.join(binaries)})")
    click.echo(f"\n{ok}/{ok + fail} scanners available")
    raise SystemExit(1 if fail else 0)


@click.command("check-health")
def check_health() -> None:
    """Verify scanner binaries and database connectivity."""
    tools = ["syft", "osv-scanner", "trivy", "scancode", "opa"]
    all_ok = True

    click.echo("Scanner Health Check")
    click.echo("=" * 40)
    for tool in tools:
        path = shutil.which(tool)
        if path:
            click.echo(f"  {tool:<15} OK  ({path})")
        else:
            click.echo(f"  {tool:<15} MISSING")
            all_ok = False

    click.echo()

    try:
        from caliper.core.config import CaliperSettings

        config = CaliperSettings()  # type: ignore[call-arg]
        from caliper.data.db import DecisionRepository

        db = DecisionRepository(dsn=config.db_dsn)
        if db.connect():
            click.echo("  Database        OK")
            db.close()
        else:
            click.echo("  Database        UNAVAILABLE")
            all_ok = False
    except Exception:
        click.echo("  Database        UNAVAILABLE (config error)")
        all_ok = False

    click.echo()
    if all_ok:
        click.echo("All checks passed.")
    else:
        click.echo("Some checks failed. See above.")


@click.command()
def plugins() -> None:
    """List all registered Caliper plugins."""
    registry = get_default_registry()
    all_plugins = registry.list()

    click.echo(f"{'Name':<20} {'Category':<15} {'Binary':<12} {'Depends On':<18} Description")
    click.echo("-" * 95)
    for p in sorted(all_plugins, key=lambda x: (x.category, x.name)):
        binary = p.name.replace("-", "")
        installed = "ok" if shutil.which(p.name) or shutil.which(binary) else "—"
        deps = ", ".join(p.depends_on) if p.depends_on else "—"
        click.echo(
            f"{p.name:<20} {p.category.value:<15} {installed:<12} {deps:<18} {p.description}"
        )
    click.echo(f"\n{len(all_plugins)} plugins registered")


@click.command("schema")
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the schema to a file instead of stdout.",
)
def schema(output_path: str | None) -> None:
    """Print the JSON Schema for `caliper review --format json` output."""
    import orjson

    from caliper.core.report_schema import report_json_schema

    rendered = orjson.dumps(report_json_schema(), option=orjson.OPT_INDENT_2).decode()
    if output_path:
        from pathlib import Path

        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(rendered + "\n")
        click.echo(f"Schema written to {output_path}")
    else:
        click.echo(rendered)
