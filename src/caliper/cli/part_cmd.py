"""``caliper part`` — propose how to cut a diff into an ordered cut list.

# tested-by: tests/integration/test_part_e2e.py
# tested-by: tests/unit/test_part_cmd.py
# tested-by: tests/unit/test_part_push_cli.py

A thin CLI adapter (presentation tier): it parses args, runs the safety gate,
delegates the cut to the parting plugin (the producer/consumer consumer), and
formats the output. It performs no git surgery — it prints a cut list and writes
a jj ``restack.sh`` that hands the mechanics to jj.

Manual gate: this command is the ONLY entry point to parting. The parting plugin
lives in the dedicated PARTING registry, never in ANALYZERS, so it is never run
by ``caliper review`` / the webhook and never gates a build.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import click

from caliper.cli.part_describe import describer_from_env
from caliper.cli.part_doctor import render_doctor_report, run_doctor
from caliper.cli.part_pipeline import run_part
from caliper.cli.part_render import render_cutlist, render_cutlist_diff, render_overrides_yaml
from caliper.cli.part_suggest import suggester_from_env
from caliper.core.models import CutList, PartTarget
from caliper.core.part_gate import PartingGateError
from caliper.core.parting import PartingError
from caliper.core.repo_config import load_repo_config

if TYPE_CHECKING:
    from caliper.cli.part_pr import ResolvedPr


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
    "--doctor",
    "doctor",
    is_flag=True,
    default=False,
    help="Check jj/git/gh/mkcert and the state workdir, then exit (no cutting).",
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
@click.option(
    "--post-comment",
    "post_comment_flag",
    is_flag=True,
    default=False,
    help="Post the proposed cut as an advisory PR comment (foreman/CI mode; requires "
    "--pr). Never posts without this explicit flag; no restack instructions are "
    "included — informational only.",
)
@click.option(
    "--push",
    "push_flag",
    is_flag=True,
    default=False,
    help="Push each part as its own branch and open it as a sequential stacked PR "
    "(requires --pr). The original PR is left open and untouched — a linking "
    "comment is posted on it once the full stack is open. Never pushes or opens "
    "PRs without this explicit flag.",
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
    doctor: bool,
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
    post_comment_flag: bool,
    push_flag: bool,
) -> None:
    """Propose an ordered cut list for a diff and emit a jj restack script."""
    if lan_host and not serve:
        raise click.UsageError("--lan only applies with --serve")
    if lan_host and not (tls_cert and tls_key):
        raise click.UsageError("--lan requires both --cert and --key (mkcert-issued)")
    if (tls_cert or tls_key) and not lan_host:
        raise click.UsageError("--cert/--key only apply with --lan")
    if post_comment_flag and not pr_url:
        raise click.UsageError("--post-comment requires --pr")
    if post_comment_flag and serve:
        # --serve never reaches the posting code (it returns early to start the
        # sidecar) — without this guard the flag combination would silently no-op.
        raise click.UsageError("--post-comment is incompatible with --serve")
    if push_flag and not pr_url:
        raise click.UsageError("--push requires --pr")
    if push_flag and serve:
        raise click.UsageError("--push is incompatible with --serve")
    if push_flag and target == "series":
        # series renders one caliper-part-series ref for the whole cut — there is
        # nothing per-part to push.
        raise click.UsageError("--push is incompatible with --target series")

    if doctor:
        checks = run_doctor(Path(repo), check_lan=bool(lan_host))
        click.echo(render_doctor_report(checks))
        if any(not c.ok for c in checks):
            raise SystemExit(1)
        return

    if explain:
        cut = CutList.model_validate_json(Path(explain).read_text())
        click.echo(render_cutlist(cut, backup_bookmark=None, rescue_op_id=None))
        return

    # None unless --pr supplies a durable per-PR store; a normal repo's overrides
    # land in its own committed .caliper.yaml.
    pr_override_store: Path | None = None
    previous_cutlist: CutList | None = None
    resolved: ResolvedPr | None = None
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
        except PrResolveError as exc:  # noqa: CAL-002  # CLI-local, not exposed
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
            previous_cutlist = resolved.previous_cutlist
        else:
            # A custom --out isn't the dir resolve_pr wiped/read from — read the
            # prior cut from wherever this run will actually write, or a custom
            # --out would silently never show a diff (#524).
            from caliper.cli.part_pr import _read_previous_cutlist

            previous_cutlist = _read_previous_cutlist(Path(out))
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
    except PartingGateError as exc:  # noqa: CAL-002  # CLI-local, not exposed
        raise click.ClickException(f"parting precondition failed [{exc.case}]: {exc}") from exc
    except PartingError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.proposed_overrides:
        click.echo(
            f"\ntier suggestions for the 'logic' residual ({len(result.proposed_overrides)}):"
        )
        click.echo(render_overrides_yaml(result.proposed_overrides))
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
        render_cutlist(
            result.cutlist,
            backup_bookmark=result.backup_bookmark,
            rescue_op_id=result.rescue_op_id,
        )
    )
    if previous_cutlist is not None:
        click.echo(render_cutlist_diff(previous_cutlist, result.cutlist))
    click.echo(f"restack script written to {result.restack_path}")
    if result.subjects:
        click.echo(
            f"described {len(result.subjects)}/{len(result.cutlist.parts)} commit subjects "
            "with a local model (advisory; deterministic fallback for the rest)"
        )

    if post_comment_flag:
        from caliper.adapters.github_publisher import GitHubPublisher
        from caliper.cli.part_comment import render_part_comment

        # Guaranteed set: the early UsageError above requires --pr, whose branch
        # always assigns resolved before this point.
        assert resolved is not None
        body = render_part_comment(result.cutlist, slug=resolved.slug, pr_num=resolved.number)
        ok = GitHubPublisher().post_comment(resolved.slug, resolved.number, body)
        click.echo(
            f"{'posted' if ok else 'failed to post'} advisory comment on "
            f"{resolved.slug}#{resolved.number}"
        )
        if not ok:
            raise SystemExit(1)

    if push_flag:
        from caliper.adapters.github_publisher import GitHubPublisher
        from caliper.cli.part_push import run_push

        # Guaranteed set: the early UsageError above requires --pr, whose branch
        # always assigns resolved before this point.
        assert resolved is not None
        assert result.restack_path is not None  # out_dir is always set on this path
        push_result = run_push(
            restack_path=result.restack_path,
            cutlist=result.cutlist,
            pr_number=resolved.number,
            base_branch=resolved.base_branch,
            slug=resolved.slug,
            repo_path=repo_path,
            publisher=GitHubPublisher(),
        )
        if push_result is None:
            raise click.ClickException(
                "failed to materialize the stack's local branches "
                f"(restack.sh at {result.restack_path} exited non-zero)"
            )
        for url in push_result.opened_urls:
            click.echo(url)
        if push_result.failed_index is not None:
            click.echo(
                f"stack push stopped at part {push_result.failed_index}: {push_result.error}",
                err=True,
            )
            raise SystemExit(1)
        if not push_result.comment_posted:
            click.echo(
                f"warning: opened the full stack but failed to post the linking "
                f"comment on {resolved.slug}#{resolved.number}"
            )
