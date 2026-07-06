"""``caliper supply-chain-diff`` — threat-analyze dependency version bumps."""

# tested-by: tests/unit/test_cli_supply_chain.py

from __future__ import annotations

import sys

import click

from caliper.cli.cli_shared import _read_diff, _write_output


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


@click.command(name="supply-chain-diff")
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
        from caliper.core.scribe import ScribeContext
        from caliper.core.scribe_pass import scribe_findings
        from caliper.data.llm_client import LlmClient
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
