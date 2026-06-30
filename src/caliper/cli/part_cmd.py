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
import orjson

from caliper.core.models import CutList, PartTarget
from caliper.core.part_gate import PartingGateError, run_gate
from caliper.core.part_script import probe_path_capability, render_restack_script, rollback_header
from caliper.core.parting import PartingError
from caliper.core.registries import PARTING
from caliper.core.repo_config import load_repo_config


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
    lines.append(
        f"cut list — {cut.stats.part_count} parts, {cut.stats.file_count} files, "
        f"cap {cut.size_cap} (size p50={cut.stats.size_p50} p90={cut.stats.size_p90})"
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


def _cutlist_json(cut: CutList) -> str:
    return orjson.dumps(cut.model_dump(mode="json"), option=orjson.OPT_INDENT_2).decode()


@click.command(name="part")
@click.option("--base", default=None, help="Base revision (stock = --base..--head).")
@click.option("--head", default=None, help="Head revision.")
@click.option(
    "--pr",
    "pr_url",
    default=None,
    help="GitHub PR URL or number; clones the PR into .temp/part-pr/ and parts "
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
    describe_flag: bool | None,
    describe_model: str | None,
) -> None:
    """Propose an ordered cut list for a diff and emit a jj restack script."""
    if explain:
        cut = CutList.model_validate_json(Path(explain).read_text())
        click.echo(_render_cutlist(cut, backup_bookmark=None, rescue_op_id=None))
        return

    if pr_url:
        if base or head:
            raise click.UsageError("--pr is mutually exclusive with --base/--head")
        from caliper.cli.part_pr import PrResolveError, detect_origin_slug, resolve_pr
        from caliper.core.pr_ref import parse_pr_ref

        repo_root = Path(repo).resolve()
        try:
            pr_ref = parse_pr_ref(pr_url, default_slug=detect_origin_slug(repo_root))
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        workdir_root = repo_root / ".temp" / "part-pr"
        try:
            resolved = resolve_pr(pr_ref, workdir_root=workdir_root)
        except PrResolveError as exc:
            raise click.ClickException(f"could not resolve PR: {exc}") from exc
        repo = str(resolved.repo_path)
        base, head = resolved.base, resolved.head
        if out is None:
            # Managed output dir, wiped + recreated each run by resolve_pr so a
            # re-run redoes from a clean slate (no stale restack.sh/cutlist.json).
            out = str(resolved.out_dir)
        click.echo(
            f">> {resolved.slug}#{resolved.number}  "
            f"base={base[:12]}  head={head[:12]}  (clone: {resolved.repo_path})"
        )

    if serve:
        if not base or not head:
            raise click.UsageError("--base and --head are required with --serve")
        from caliper.cli.part_serve import DEFAULT_PORT, serve_part

        serve_part(Path(repo).resolve(), base, head, port=port or DEFAULT_PORT, size_cap=size_cap)
        return

    if not base or not head:
        raise click.UsageError("--base and --head are required (or use --explain <cutlist>)")

    repo_path = Path(repo).resolve()
    cfg = load_repo_config(repo_path).parting
    if size_cap is not None:
        cfg = cfg.model_copy(update={"size_cap": size_cap})
    if target is not None:
        cfg = cfg.model_copy(update={"target": PartTarget(target)})

    # 1. Safety gate — runs before anything is touched; aborts hard on failure.
    # Microsecond precision so repeated runs in the same second never collide on
    # the backup bookmark name (jj bookmark create fails on a duplicate).
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    try:
        gate = run_gate(repo_path, base, head, timestamp=timestamp, force=force)
    except PartingGateError as exc:
        raise click.ClickException(f"parting precondition failed [{exc.case}]: {exc}") from exc
    except PartingError as exc:
        raise click.ClickException(str(exc)) from exc

    # 2. Cut: producer (build_stock) -> consumer (part()). Pin the gate's revsets.
    # Import triggers the parting plugin's @PARTING.register side effect — it is
    # underscore-prefixed so autodiscover never pulls it into the review pipeline.
    import caliper.plugins._parting  # noqa: F401

    try:
        outcome = PARTING.create("parting").cut(repo_path, base, head, cfg)
    except PartingError as exc:
        raise click.ClickException(str(exc)) from exc
    cut = outcome.cutlist.model_copy(
        update={
            "provenance": outcome.cutlist.provenance.model_copy(
                update={"resolved_revsets": gate.resolved_revsets}
            )
        }
    )

    # 3. Probe the installed jj for non-interactive path restore (do not assume).
    can_reconstruct, jj_version = probe_path_capability(str(repo_path))

    # 3b. Advisory describer (imperative shell): name each commit with a local model,
    # fail-soft to the deterministic subject. Env-driven and OUTSIDE config_digest, so
    # it never touches the cut — only the human-readable subject line.
    from caliper.cli.part_describe import describe_parts, describer_from_env

    describe_env = dict(os.environ)
    if describe_model:
        describe_env["CALIPER_DESCRIBER_MODEL"] = describe_model
    describer = describer_from_env(describe_env, force=describe_flag)
    subjects = describe_parts(cut, describer)

    # 4. Emit the restack script, pinning the gate's resolved base/head ids.
    script = render_restack_script(
        cut,
        base_rev=gate.resolved_revsets.get("base") or base,
        head_rev=gate.resolved_revsets.get("head") or head,
        old_paths=outcome.old_paths,
        backup_bookmark=gate.backup_bookmark,
        rescue_op_id=gate.rescue_op_id,
        jj_version=jj_version or gate.jj_version,
        target=cfg.target,
        validate_command=cfg.validate_command,
        can_reconstruct=can_reconstruct,
        subjects=subjects,
    )

    out_dir = Path(out) if out else repo_path
    out_dir.mkdir(parents=True, exist_ok=True)
    script_path = out_dir / "restack.sh"
    script_path.write_text(script)
    script_path.chmod(0o755)
    # JSON persistence is optional (a proposal, not a verdict) but useful for --explain.
    (out_dir / "cutlist.json").write_text(_cutlist_json(cut))

    click.echo(
        _render_cutlist(cut, backup_bookmark=gate.backup_bookmark, rescue_op_id=gate.rescue_op_id)
    )
    click.echo(f"restack script written to {script_path}")
    if subjects:
        click.echo(
            f"described {len(subjects)}/{len(cut.parts)} commit subjects with a local model "
            "(advisory; deterministic fallback for the rest)"
        )
