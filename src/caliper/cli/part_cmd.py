"""``caliper part`` — propose how to cut a diff into an ordered cut list.

# tested-by: tests/integration/test_part_e2e.py

A thin CLI adapter (presentation tier): it parses args, runs the safety gate,
delegates the cut to the parting plugin (the producer/consumer consumer), and
formats the output. It performs no git surgery — it prints a cut list and writes
a jj ``restack.sh`` that hands the mechanics to jj.

Manual gate: this command is the ONLY entry point to parting. The parting plugin
lives in the dedicated PARTING registry, never in ANALYZERS, so it is never run
by ``caliper review`` / Foreman / the webhook and never gates a build.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import click

from caliper.cli.part_describe import describer_from_env
from caliper.cli.part_pipeline import run_part
from caliper.cli.part_suggest import suggester_from_env
from caliper.core.models import CutList, PartTarget
from caliper.core.part_gate import PartingGateError
from caliper.core.part_script import rollback_header
from caliper.core.parting import PartingError
from caliper.core.repo_config import OverrideRule, load_repo_config


def _render_cutlist(cut: CutList, *, backup_bookmark: str | None, rescue_op_id: str | None) -> str:
    """Human-readable cut list, opening with the rollback header (escape hatch)."""
    lines: list[str] = []
    if backup_bookmark and rescue_op_id:
        for h in rollback_header(backup_bookmark, rescue_op_id):
            lines.append(h)
    else:
        lines.append("ROLLBACK — the rollback header was emitted with the original restack.sh")
    lines.append("")
    p = cut.provenance
    bucket_count = len({part.bucket for part in cut.parts})
    cap_str = "none (1 part/bucket)" if cut.size_cap is None else str(cut.size_cap)
    lines.append(
        f"cut list — {cut.stats.part_count} parts across {bucket_count} buckets, "
        f"{cut.stats.file_count} files, cap {cap_str} "
        f"(size p50={cut.stats.size_p50} p90={cut.stats.size_p90})"
    )
    lines.append(
        f"provenance: caliper {p.caliper_version or '?'}  base={p.base_sha or '?'}  "
        f"head={p.head_sha or '?'}  rename={p.rename_threshold}%  cfg={p.config_digest[:12]}"
    )
    lines.append("(proposal, not a verdict — bottom of stack first)")
    lines.append("")
    for i, part in enumerate(cut.parts, start=1):
        flags = []
        if part.oversized:
            flags.append("OVERSIZED")
        if part.bucket.value == "delete":
            flags.append("DELETE-REVIEW")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        lines.append(
            f"  {i}. {part.bucket} ({len(part.files)} files, size {part.size}) "
            f"kerf={part.opened_by.fired_rule}{flag_str}"
        )
        for f in part.files:
            lines.append(f"       {f}")
    if cut.ambiguities:
        lines.append("")
        lines.append("ambiguities (emitted as logic, review classification):")
        for a in cut.ambiguities:
            lines.append(f"  - {a.file}: {a.reason}")
    return "\n".join(lines) + "\n"


def _overrides_yaml(rules: list[OverrideRule]) -> str:
    """Paste-ready ``parting.overrides`` block for the suggested rules (print mode)."""
    lines = ["parting:", "  overrides:"]
    for r in rules:
        lines.append(f"    - glob: {r.glob!r}")
        lines.append(f"      bucket: {r.bucket.value}")
        if r.note:
            lines.append(f"      note: {r.note!r}")
    return "\n".join(lines)


@click.command(name="part")
@click.option("--base", default=None, help="Base revision (stock = --base..--head).")
@click.option("--head", default=None, help="Head revision.")
@click.option(
    "--pr",
    "pr_url",
    default=None,
    help="GitHub PR URL or number; clones the PR into a centralized workdir "
    "(~/.config/caliper/state/part-pr, override via CALIPER_STATE_DIR) and parts "
    "base..head (mutually exclusive with --base/--head).",
)
@click.option("--repo", "repo", type=click.Path(exists=True), default=".", help="Repository root.")
@click.option(
    "--target",
    type=click.Choice(["stack", "series"]),
    default=None,
    help="Substrate handoff shape (default from config); affects only the script.",
)
@click.option("--size-cap", "size_cap", type=int, default=None, help="Override the size cap.")
@click.option(
    "--out", "out", type=click.Path(), default=None, help="Directory for restack.sh / cutlist.json."
)
@click.option(
    "--explain",
    "explain",
    type=click.Path(exists=True),
    default=None,
    help="Print a saved cut list and the rule fired at each kerf.",
)
@click.option(
    "--force", is_flag=True, default=False, help="Override the already-pushed safety check."
)
@click.option(
    "--serve",
    is_flag=True,
    default=False,
    help="Serve a live reclassify report on localhost instead of cutting.",
)
@click.option(
    "--port", type=int, default=None, help="Port for --serve (default 12700, loopback only)."
)
@click.option(
    "--lan",
    "lan_host",
    default=None,
    help="With --serve, also bind a read-only view server to this LAN IP (e.g. "
    "192.168.1.50) so another device can browse the cut list. Mutating routes "
    "(/apply, /reclassify, /repart, /restack, /pr, /range, /suggest/apply, "
    "/rollback) stay loopback-only regardless. Requires --cert/--key.",
)
@click.option(
    "--lan-port",
    type=int,
    default=None,
    help="Port for --lan (default 12701; always separate from --port).",
)
@click.option(
    "--cert",
    "tls_cert",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="TLS cert for --lan (e.g. `mkcert 192.168.1.50` output).",
)
@click.option(
    "--key",
    "tls_key",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="TLS key for --lan (e.g. `mkcert 192.168.1.50` output).",
)
@click.option(
    "--describe/--no-describe",
    "describe_flag",
    default=None,
    help="Advisory: name each commit with a local model (fail-soft to deterministic). "
    "Default follows env (CALIPER_DESCRIBER_MODEL + base URL).",
)
@click.option(
    "--describe-model",
    "describe_model",
    default=None,
    help="Model id for --describe (e.g. gemma4:e4b, llama3.2:3b); overrides env.",
)
@click.option(
    "--suggest/--no-suggest",
    "suggest_flag",
    default=None,
    help="Advisory: ask a local model to propose tier override globs for the untiered "
    "'logic' residual (fail-soft, off the decision path). Default follows env "
    "(CALIPER_SUGGESTER_MODEL + base URL).",
)
@click.option(
    "--suggest-model",
    "suggest_model",
    default=None,
    help="Model id for --suggest (e.g. llama3.1); overrides env. Falls back to --describe-model.",
)
@click.option(
    "--suggest-apply",
    is_flag=True,
    default=False,
    help="Write the suggested overrides into .caliper.yaml and re-part (default: print only).",
)
def part(
    base: str | None,
    head: str | None,
    pr_url: str | None,
    repo: str,
    target: str | None,
    size_cap: int | None,
    out: str | None,
    explain: str | None,
    force: bool,
    serve: bool,
    port: int | None,
    lan_host: str | None,
    lan_port: int | None,
    tls_cert: str | None,
    tls_key: str | None,
    describe_flag: bool | None,
    describe_model: str | None,
    suggest_flag: bool | None,
    suggest_model: str | None,
    suggest_apply: bool,
) -> None:
    """Propose an ordered cut list for a diff and emit a jj restack script."""
    if lan_host and not serve:
        raise click.UsageError("--lan only applies with --serve")
    if lan_host and not (tls_cert and tls_key):
        raise click.UsageError("--lan requires both --cert and --key (mkcert-issued)")
    if (tls_cert or tls_key) and not lan_host:
        raise click.UsageError("--cert/--key only apply with --lan")

    if explain:
        cut = CutList.model_validate_json(Path(explain).read_text())
        click.echo(_render_cutlist(cut, backup_bookmark=None, rescue_op_id=None))
        return

    # None unless --pr supplies a durable per-PR store; a normal repo's overrides
    # land in its own committed .caliper.yaml.
    pr_override_store: Path | None = None
    if pr_url:
        if base or head:
            raise click.UsageError("--pr is mutually exclusive with --base/--head")
        from caliper.cli.part_pr import (
            PrResolveError,
            default_part_workdir,
            detect_origin_slug,
            resolve_pr,
        )
        from caliper.core.pr_ref import parse_pr_ref

        repo_root = Path(repo).resolve()
        try:
            pr_ref = parse_pr_ref(pr_url, default_slug=detect_origin_slug(repo_root))
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        # Centralized, repo-independent workdir (XDG) — the throwaway clone and the
        # durable override sidecar live outside any checkout's .temp/, so they
        # survive git clean / re-clone and never collide across repos.
        workdir_root = default_part_workdir()
        try:
            resolved = resolve_pr(pr_ref, workdir_root=workdir_root)
        except PrResolveError as exc:
            raise click.ClickException(f"could not resolve PR: {exc}") from exc
        repo = str(resolved.repo_path)
        base, head = resolved.base, resolved.head
        # Reviewer reclassifications under --serve persist to this durable store
        # OUTSIDE the throwaway clone, so they survive the next run's clean-slate.
        pr_override_store = resolved.override_store
        if out is None:
            # Managed output dir, wiped + recreated each run by resolve_pr so a
            # re-run redoes from a clean slate (no stale restack.sh/cutlist.json).
            out = str(resolved.out_dir)
        click.echo(
            f">> {resolved.slug}#{resolved.number}  "
            f"base={base[:12]}  head={head[:12]}  (clone: {resolved.repo_path})"
        )

    if serve:
        # base/head are optional for --serve (P2 live targeting): with neither set
        # the SPA opens on the empty-state targeting prompt (POST /range or /pr).
        from caliper.cli.part_serve import DEFAULT_LAN_PORT, DEFAULT_PORT, serve_part

        suggest_env = dict(os.environ)
        if suggest_model:
            suggest_env["CALIPER_SUGGESTER_MODEL"] = suggest_model
        serve_part(
            Path(repo).resolve(),
            base,
            head,
            port=port or DEFAULT_PORT,
            size_cap=size_cap,
            override_store=pr_override_store,
            suggester=suggester_from_env(suggest_env, force=suggest_flag),
            out_dir=Path(out) if out else None,
            lan_host=lan_host,
            lan_port=lan_port or DEFAULT_LAN_PORT,
            tls_cert=Path(tls_cert) if tls_cert else None,
            tls_key=Path(tls_key) if tls_key else None,
        )
        return

    if not base or not head:
        raise click.UsageError("--base and --head are required (or use --explain <cutlist>)")

    repo_path = Path(repo).resolve()
    cfg = load_repo_config(repo_path).parting
    if size_cap is not None:
        cfg = cfg.model_copy(update={"size_cap": size_cap})
    if target is not None:
        cfg = cfg.model_copy(update={"target": PartTarget(target)})

    # Advisory local-model backends: env-driven, OUTSIDE config_digest — they only
    # author a subject line or propose override globs; the deterministic boundary
    # (cli/part_pipeline.run_part) decides what survives.
    suggest_env = dict(os.environ)
    if suggest_model:
        suggest_env["CALIPER_SUGGESTER_MODEL"] = suggest_model
    suggester = suggester_from_env(suggest_env, force=suggest_flag)

    describe_env = dict(os.environ)
    if describe_model:
        describe_env["CALIPER_DESCRIBER_MODEL"] = describe_model
    describer = describer_from_env(describe_env, force=describe_flag)

    # Microsecond precision so repeated runs in the same second never collide on
    # the backup bookmark name (jj bookmark create fails on a duplicate).
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    out_dir = Path(out) if out else repo_path
    try:
        result = run_part(
            repo_path,
            base,
            head,
            cfg,
            timestamp=timestamp,
            force=force,
            describer=describer,
            suggester=suggester,
            suggest_apply=suggest_apply,
            override_write_target=pr_override_store,
            out_dir=out_dir,
        )
    except PartingGateError as exc:
        raise click.ClickException(f"parting precondition failed [{exc.case}]: {exc}") from exc
    except PartingError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.proposed_overrides:
        click.echo(
            f"\ntier suggestions for the 'logic' residual ({len(result.proposed_overrides)}):"
        )
        click.echo(_overrides_yaml(result.proposed_overrides))
        if result.applied_overrides:
            write_target = pr_override_store or repo_path
            click.echo(
                f"applied {len(result.applied_overrides)} override(s) to "
                f"{write_target}/.caliper.yaml; re-parted"
            )
        else:
            click.echo("(re-run with --suggest-apply to write these and re-part)")
    elif suggest_flag is True or suggest_apply:
        click.echo("\nno tier suggestions (residual empty or model unavailable)")

    click.echo(
        _render_cutlist(
            result.cutlist,
            backup_bookmark=result.backup_bookmark,
            rescue_op_id=result.rescue_op_id,
        )
    )
    click.echo(f"restack script written to {result.restack_path}")
    if result.subjects:
        click.echo(
            f"described {len(result.subjects)}/{len(result.cutlist.parts)} commit subjects "
            "with a local model (advisory; deterministic fallback for the rest)"
        )
