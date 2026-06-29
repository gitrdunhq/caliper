"""``caliper gauge`` — the flywheel: propose, backtest, promote, status.

# tested-by: tests/integration/test_gauge_cli.py

Maintainer-driven curation that turns recurring advisory claims into permanent
deterministic Screen gauges. ``propose`` is the only step that uses the LLM (it
drafts candidates); ``backtest`` and ``promote`` are LLM-free and deterministic.
``promote`` refuses without a passing backtest and an explicit ``--by``: the LLM
drafts, but a human promotes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import click
import orjson

# The CLI tier registers the isolated LLM drafting backends (core may not import
# the plugins tier). Never auto-discovered into the review pipeline.
import caliper.plugins._inspect_llm  # noqa: E402,F401
from caliper.core.backtest import RunOutput, backtest
from caliper.core.flywheel import cluster_key, top_candidates
from caliper.core.gauge import GaugeError
from caliper.core.gauge_engine import make_backtest_runner
from caliper.core.gauge_propose import propose, resolve_drafter
from caliper.core.gauge_status import convergence
from caliper.core.ledger import load as load_ledger
from caliper.core.models import CandidateGauge
from caliper.core.repo_config import load_repo_config
from caliper.core.tool_crib import active_cluster_keys, load_promotions
from caliper.core.tool_crib import promote as crib_promote
from caliper.plugins._runners.semgrep_runner import run_semgrep  # noqa: E402


def _paths(repo: str):
    repo_path = Path(repo).resolve()
    base = repo_path / ".caliper"
    return repo_path, base / "claims-ledger.jsonl", base / "tool-crib", base / "candidates"


def _null_runner(candidate: CandidateGauge, samples: list[str]) -> RunOutput:
    """Fallback runner used when no corpus is provided: flags nothing, so the candidate
    fails the recall floor and is not promotable. The real engine
    (``core.gauge_engine``) is wired via :func:`_resolve_backtest_runner` whenever a
    corpus is given; either way the deterministic backtest still gates promotion."""
    return RunOutput(hits=set(), runtime_ms=0)


def _resolve_backtest_runner(
    repo_path: Path, clean_corpus: str | None, historical_corpus: str | None
):
    """Return the real gauge runner when a corpus is available, else the null runner.

    Sample-id resolution: a clean sample id is a path relative to ``--clean-corpus``; a
    historical sample id is a content hash naming a snapshot under
    ``--historical-corpus``. With no corpus the gauge cannot execute, so the safe null
    runner is kept (flags nothing -> fails recall -> not promotable).
    """
    if not clean_corpus and not historical_corpus:
        return _null_runner

    def resolve(sid: str) -> list[str]:
        files: list[str] = []
        if clean_corpus and (Path(clean_corpus) / sid).is_file():
            files.append(str(Path(clean_corpus) / sid))
        if historical_corpus:
            files.extend(str(p) for p in Path(historical_corpus).glob(f"{sid}*") if p.is_file())
        return files

    return make_backtest_runner(repo_path, resolve, run_semgrep)


@click.group(name="gauge")
def gauge() -> None:
    """The flywheel: turn recurring advisory claims into deterministic gauges."""


@gauge.command("propose")
@click.option(
    "--ledger",
    "ledger_path",
    type=click.Path(),
    default=None,
    help="Claims ledger (default .caliper/claims-ledger.jsonl).",
)
@click.option("--top", type=int, default=None, help="Number of top clusters to draft.")
@click.option(
    "--out", "out", type=click.Path(), default=None, help="Directory for candidate gauges."
)
@click.option("--repo", "repo", type=click.Path(exists=True), default=".", help="Repository root.")
def propose_cmd(ledger_path: str | None, top: int | None, out: str | None, repo: str) -> None:
    """Cluster the ledger deterministically and have the LLM draft candidates (only LLM step)."""
    repo_path, default_ledger, crib_dir, default_out = _paths(repo)
    cfg = load_repo_config(repo_path).gauge
    entries = load_ledger(Path(ledger_path) if ledger_path else default_ledger)
    drafter = resolve_drafter(cfg)
    candidates = propose(
        entries,
        cfg,
        drafter,
        top=top or cfg.top_default,
        exclude_keys=active_cluster_keys(crib_dir),
    )
    out_dir = Path(out) if out else default_out
    out_dir.mkdir(parents=True, exist_ok=True)
    for cand in candidates:
        (out_dir / f"{cand.cluster_key}.json").write_bytes(
            orjson.dumps(cand.model_dump(mode="json"), option=orjson.OPT_INDENT_2)
        )
    considered = len(
        top_candidates(
            entries, cfg, top=top or cfg.top_default, exclude_keys=active_cluster_keys(crib_dir)
        )
    )
    click.echo(
        f"clusters considered: {considered}; candidates drafted: {len(candidates)} -> {out_dir}"
    )
    if considered and not candidates:
        click.echo("(no candidates: the LLM drafter is unavailable — fail-soft, nothing invented)")


@gauge.command("backtest")
@click.argument("candidate", type=click.Path(exists=True))
@click.option(
    "--ledger",
    "ledger_path",
    type=click.Path(),
    default=None,
    help="Claims ledger to locate the historical corpus.",
)
@click.option(
    "--clean-corpus",
    "clean_corpus",
    type=click.Path(),
    default=None,
    help="Directory of clean samples for the precision gate (sample id = relative path).",
)
@click.option(
    "--historical-corpus",
    "historical_corpus",
    type=click.Path(),
    default=None,
    help="Directory of historical snapshots named by content hash, for the recall gate.",
)
@click.option("--repo", "repo", type=click.Path(exists=True), default=".", help="Repository root.")
def backtest_cmd(
    candidate: str,
    ledger_path: str | None,
    clean_corpus: str | None,
    historical_corpus: str | None,
    repo: str,
) -> None:
    """Run the deterministic four-part backtest and write the result into the candidate."""
    repo_path, default_ledger, _crib, _out = _paths(repo)
    cfg = load_repo_config(repo_path).gauge
    cand = CandidateGauge.model_validate_json(Path(candidate).read_text())
    entries = load_ledger(Path(ledger_path) if ledger_path else default_ledger)

    # Historical corpus: the parts where the source claims fired (by content ref).
    historical = sorted(
        {
            e.content_hash
            for e in entries
            if cluster_key(e.claim.category.value, e.claim.assertion) == cand.cluster_key
        }
    )
    clean: list[str] = []
    if clean_corpus:
        clean = sorted(
            str(p.relative_to(clean_corpus)) for p in Path(clean_corpus).rglob("*") if p.is_file()
        )

    runner = _resolve_backtest_runner(repo_path, clean_corpus, historical_corpus)
    bt = backtest(cand, historical, clean, runner, cfg)
    cand = cand.model_copy(update={"backtest": bt})
    Path(candidate).write_bytes(
        orjson.dumps(cand.model_dump(mode="json"), option=orjson.OPT_INDENT_2)
    )
    click.echo(
        f"backtest: recall={bt.recall:.2f} precision={bt.precision:.2f} "
        f"deterministic={bt.deterministic} runtime={bt.runtime_ms}ms passed={bt.passed}"
    )
    if not bt.passed and runner is _null_runner:
        click.echo(
            "(not promotable; provide --historical-corpus / --clean-corpus so the "
            "gauge actually executes for the recall/precision gates)"
        )


@gauge.command("promote")
@click.argument("candidate", type=click.Path(exists=True))
@click.option("--by", "promoted_by", default=None, help="Promoter identity (required).")
@click.option("--repo", "repo", type=click.Path(exists=True), default=".", help="Repository root.")
def promote_cmd(candidate: str, promoted_by: str | None, repo: str) -> None:
    """Promote a candidate with a passing backtest into the tool crib (human-gated)."""
    _repo, _ledger, crib_dir, _out = _paths(repo)
    if not promoted_by:
        raise click.UsageError("--by <name> is required: promotion is a deliberate human act")
    cand = CandidateGauge.model_validate_json(Path(candidate).read_text())
    if cand.backtest is None or not cand.backtest.passed:
        raise click.ClickException(
            "refusing to promote: candidate has no passing backtest "
            "(run `caliper gauge backtest` first)"
        )
    try:
        promo = crib_promote(
            cand,
            cand.backtest,
            promoted_by=promoted_by,
            promoted_at=datetime.now(UTC),
            crib_dir=crib_dir,
        )
    except GaugeError as exc:
        raise click.ClickException(str(exc)) from exc
    cand_meta = f"model {promo.candidate.model_version}, prompt {promo.candidate.prompt_version}"
    click.echo(
        f"promoted {promo.candidate.cluster_key} by {promo.promoted_by} ({cand_meta}) -> {crib_dir}"
    )


@gauge.command("status")
@click.option("--ledger", "ledger_path", type=click.Path(), default=None, help="Claims ledger.")
@click.option("--repo", "repo", type=click.Path(exists=True), default=".", help="Repository root.")
def status_cmd(ledger_path: str | None, repo: str) -> None:
    """Print the convergence scorecard (the whole arc, made measurable)."""
    repo_path, default_ledger, crib_dir, _out = _paths(repo)
    cfg = load_repo_config(repo_path).gauge
    entries = load_ledger(Path(ledger_path) if ledger_path else default_ledger)
    stats = convergence(entries, cfg, len(load_promotions(crib_dir)))
    click.echo("=== caliper gauge — convergence scorecard ===")
    click.echo(f"  claims in ledger      : {stats.total_claims}")
    click.echo(f"  distinct clusters     : {stats.total_clusters}")
    click.echo(
        f"  substantiation rate   : {stats.substantiation_rate:.1%}  (claims with a Screen witness)"
    )
    click.echo(
        f"  advisory recurrence   : {stats.advisory_recurrence_rate:.1%}  (recurring = open gaps)"
    )
    click.echo(
        f"  LLM novelty           : {stats.llm_novelty_rate:.1%}  (seen once = genuinely new)"
    )
    click.echo(f"  promoted gauges       : {stats.gauge_coverage}")
