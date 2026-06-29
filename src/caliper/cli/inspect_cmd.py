"""``caliper inspect`` — per-part review of a cut list (advisory, manual).

# tested-by: tests/integration/test_inspect_cli.py

A thin CLI adapter. For each part of a ``caliper part`` cut list it runs Screen
gauges (deterministic), an optional Review LLM pass (advisory, behind a port), and
the pure Adjudicate filter, then writes a per-part inspection report. After the
parts it runs one integration pass over the assembled stock. Output is a report:
it never gates a build, never enters the decision audit lake, and is not in the
auto pipeline.

The decision path is deterministic; the review is not. No LLM output reaches this
report except through the pure adjudicator.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import click
import orjson

# The CLI tier wires the deterministic core to the plugins tier (core may not import
# plugins). Importing the isolated LLM backend module triggers its registration into
# INSPECT_BACKENDS; it is never auto-discovered into the review pipeline.
import caliper.plugins._inspect_llm  # noqa: E402,F401
from caliper.core import ledger as ledger_store
from caliper.core.inspect import adjudicate
from caliper.core.inspect_cache import InspectCache
from caliper.core.inspect_gauges import has_hard_failure, run_gauges, screen_findings
from caliper.core.inspect_runner import run_review
from caliper.core.inspect_view import PartView, build_view
from caliper.core.models import (
    ChangeType,
    Claim,
    CutList,
    InspectionReport,
    Kerf,
    LedgerEntry,
    Part,
)
from caliper.core.plugin import PluginResult
from caliper.core.repo_config import load_repo_config
from caliper.plugins import get_default_registry  # noqa: E402


def _analyze(files: list[str], repo_path: Path, categories: list[str]) -> list[PluginResult]:
    """Screen analyzer runner: the existing registry, scoped to a part's files."""
    return get_default_registry().run_all(files, repo_path, categories=categories)


def _render_report(rep: InspectionReport) -> str:
    lines = [f"=== inspection: {rep.part_id} ({rep.bucket}) [{rep.kind}] ==="]
    for g in rep.gauges:
        lines.append(f"  gauge {g.gauge}: {g.verdict} ({len(g.findings)} findings)")
    if rep.skipped_llm:
        lines.append("  LLM review: skipped")
    lines.append(f"  claims ({len(rep.claims)}):")
    for c in rep.claims:
        ev = f" <-{c.evidence_ref}" if c.evidence_ref else ""
        lines.append(
            f"    [{c.severity}] {c.category} {c.file}:{c.line_range[0]}-{c.line_range[1]}"
            f" {c.assertion}{ev}"
        )
    if rep.dropped:
        lines.append(f"  (dropped {len(rep.dropped)} claims; see report JSON)")
    return "\n".join(lines)


def _write_report(out_dir: Path, rep: InspectionReport) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{rep.part_id}.json"
    path.write_bytes(orjson.dumps(rep.model_dump(mode="json"), option=orjson.OPT_INDENT_2))
    return path


def _ledger_entries(
    rep: InspectionReport, view: PartView, repo_name: str, sha: str
) -> list[LedgerEntry]:
    """Build claims-ledger entries for a report: advisory survivors + valid dropped
    claims, each with a content reference (content hash of the part's changed bytes)."""
    content_hash = hashlib.sha256(view.changed_bytes).hexdigest()
    out: list[LedgerEntry] = []
    for c in rep.claims:
        out.append(
            LedgerEntry(
                claim=c, repo=repo_name, sha=sha, content_hash=content_hash, part_id=rep.part_id
            )
        )
    for d in rep.dropped:
        try:
            claim = Claim.model_validate(d.claim)
        except Exception:  # noqa: BLE001 - parse-drops are not ledgerable claims
            continue
        out.append(
            LedgerEntry(
                claim=claim, repo=repo_name, sha=sha, content_hash=content_hash, part_id=rep.part_id
            )
        )
    return out


def _lower_context(parts: list[Part], index: int) -> str:
    """Compact, read-only summary of the lower parts (``::part-``)."""
    lines = []
    for p in parts[:index]:
        lines.append(f"part {p.id} ({p.bucket.value}): {', '.join(p.files)}")
    return "\n".join(lines)


@click.command(name="inspect")
@click.option(
    "--cutlist",
    "cutlist_path",
    type=click.Path(exists=True),
    default=None,
    help="cutlist.json from `caliper part`.",
)
@click.option("--repo", "repo", type=click.Path(exists=True), default=".", help="Repository root.")
@click.option(
    "--out", "out", type=click.Path(), default=None, help="Directory for inspection reports."
)
@click.option(
    "--no-llm",
    "no_llm",
    is_flag=True,
    default=False,
    help="Screen + Adjudicate only (fully deterministic).",
)
@click.option(
    "--token-budget",
    "token_budget",
    type=int,
    default=None,
    help="Override the lower-parts context token budget.",
)
@click.option(
    "--explain",
    "explain",
    type=click.Path(exists=True),
    default=None,
    help="Print a saved inspection report.",
)
@click.option(
    "--ledger",
    "ledger_path",
    type=click.Path(),
    default=None,
    help="Claims ledger to append to (default .caliper/claims-ledger.jsonl).",
)
def inspect(
    cutlist_path: str | None,
    repo: str,
    out: str | None,
    no_llm: bool,
    token_budget: int | None,
    explain: str | None,
    ledger_path: str | None,
) -> None:
    """Review the parts of a cut list and write per-part + integration reports."""
    if explain:
        rep = InspectionReport.model_validate_json(Path(explain).read_text())
        click.echo(_render_report(rep))
        return

    if not cutlist_path:
        raise click.UsageError("--cutlist is required (or use --explain <report>)")

    repo_path = Path(repo).resolve()
    cfg = load_repo_config(repo_path).inspect
    if token_budget is not None:
        cfg = cfg.model_copy(update={"token_budget": token_budget})

    cutlist = CutList.model_validate_json(Path(cutlist_path).read_text())
    base = cutlist.provenance.base_sha
    head = cutlist.provenance.head_sha
    if not base or not head:
        raise click.ClickException(
            "cut list provenance lacks base/head SHAs; re-run `caliper part`"
        )

    out_dir = Path(out) if out else repo_path
    report_dir = out_dir / "inspect"
    cache = InspectCache(out_dir / ".inspect-cache")

    repo_name = repo_path.name
    ledger_entries: list[LedgerEntry] = []

    parts = cutlist.parts
    all_changed: dict[str, set[int]] = {}
    all_screen = []
    for i, part in enumerate(parts):
        view = build_view(repo_path, base, head, part.files)
        gauges = run_gauges(part, repo_path, cfg, analyze=_analyze)  # fail-closed
        screen = screen_findings(gauges)
        all_screen.extend(screen)
        for f, lines in view.changed_lines.items():
            all_changed.setdefault(f, set()).update(lines)

        # A hard gauge failure means the part is reported with its LLM review skipped.
        enabled = not no_llm and not has_hard_failure(gauges)
        review = run_review(part, view, _lower_context(parts, i), cfg, cache=cache, enabled=enabled)
        adj = adjudicate(
            review.raw_claims, part, screen, cfg, view.changed_lines, view.changed_text
        )

        rep = InspectionReport(
            part_id=part.id,
            bucket=part.bucket.value,
            kind="part",
            gauges=gauges,
            claims=adj.survivors,
            skipped_llm=review.skipped_llm,
            dropped=adj.dropped,
        )
        click.echo(_render_report(rep))
        _write_report(report_dir, rep)
        ledger_entries.extend(_ledger_entries(rep, view, repo_name, head))

    # Integration pass over the assembled stock (backup+::@) for cross-part defects
    # per-part isolation cannot see. Claims go through the same adjudicator with the
    # whole stock as scope.
    all_files = sorted({f for p in parts for f in p.files})
    integ_part = Part(
        id="integration",
        files=all_files,
        bucket=ChangeType.logic,  # full category set for cross-part review
        size=sum(p.size for p in parts),
        opened_by=Kerf(fired_rule="bucket-end"),
    )
    integ_view = build_view(repo_path, base, head, all_files)
    integ_review = run_review(integ_part, integ_view, "", cfg, cache=cache, enabled=not no_llm)
    integ_adj = adjudicate(
        integ_review.raw_claims,
        integ_part,
        all_screen,
        cfg,
        integ_view.changed_lines,
        integ_view.changed_text,
    )
    integ_rep = InspectionReport(
        part_id="integration",
        bucket="logic",
        kind="integration",
        gauges=[],
        claims=integ_adj.survivors,
        skipped_llm=integ_review.skipped_llm,
        dropped=integ_adj.dropped,
    )
    click.echo(_render_report(integ_rep))
    _write_report(report_dir, integ_rep)
    ledger_entries.extend(_ledger_entries(integ_rep, integ_view, repo_name, head))

    # Append advisory/dropped claims to the claims ledger (advisory data, not the
    # decision audit lake) so the gauge flywheel can find recurring patterns.
    ledger_file = (
        Path(ledger_path) if ledger_path else (repo_path / ".caliper" / "claims-ledger.jsonl")
    )
    ledger_store.append(ledger_file, ledger_entries)
    click.echo(
        f"inspection reports written to {report_dir}; {len(ledger_entries)} claims -> ledger"
    )
