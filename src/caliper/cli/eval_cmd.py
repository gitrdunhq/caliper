"""``caliper eval`` — review-quality eval over a seeded-bug corpus (advisory, manual).

# tested-by: tests/unit/test_inspect_eval.py

Runs each corpus case through the same pure Adjudicate filter the real pipeline uses
and reports precision / recall / F1 / nit-rate / SNR **pre- and post-Adjudicate**, plus
the per-rule drop rate. This is the trust gate: the feature is not trusted until this
runs, and it is what decides the model default. It never gates a build.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from caliper.core.inspect_eval import aggregate, evaluate_case, load_corpus


@click.command(name="eval")
@click.option(
    "--corpus",
    "corpus_dir",
    type=click.Path(exists=True),
    required=True,
    help="Directory of corpus case JSON files (see docs/llm-review/eval-corpus).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
def eval_cmd(corpus_dir: str, fmt: str) -> None:
    """Score the reviewer against a corpus and print pre/post-Adjudicate metrics."""
    cases = load_corpus(Path(corpus_dir))
    if not cases:
        raise click.ClickException(f"no corpus cases found under {corpus_dir}")
    results = [evaluate_case(c) for c in cases]
    report = aggregate(results)

    if fmt == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    pre, post = report["pre_adjudicate"], report["post_adjudicate"]
    click.echo(f"review eval over {report['cases']} case(s):")
    for label, m in (("pre-Adjudicate ", pre), ("post-Adjudicate", post)):
        click.echo(
            f"  {label}: precision={m['precision']:.2f} recall={m['recall']:.2f} "
            f"f1={m['f1']:.2f} nit_rate={m['nit_rate']:.2f} snr={m['snr']}"
        )
    if report["drop_rate_by_rule"]:
        rates = ", ".join(f"{k}={v:.2f}" for k, v in sorted(report["drop_rate_by_rule"].items()))
        click.echo(f"  Adjudicate drop rate by rule: {rates}")
