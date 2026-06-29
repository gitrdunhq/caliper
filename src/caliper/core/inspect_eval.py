"""Review-quality eval harness — score the reviewer against a seeded-bug corpus.

# tested-by: tests/unit/test_inspect_eval.py

This answers "is the review any good?" — the definition-of-trust gate the build spec
calls for, and what decides the model default. It runs each corpus case through the
**same** pure Adjudicate filter the real pipeline uses and scores the claims **both
pre- and post-Adjudicate**, so the value Adjudicate adds is measurable. It also
reports the per-rule drop rate (from ``DroppedClaim.rule``) so the "sealed by a
testable function" claim is quantified.

The scoring functions are pure (claims + ground truth -> metrics). A corpus case
carries *recorded* model claims (a deterministic stand-in for a live backend), so the
harness is fully deterministic and reproducible — the same role a recorded run plays
in BATTLEARENA, whose sweep over (model, context, sampling) feeds cases in here.

Ground truth is a set of (file, line) bug sites validated as "detectable via review".
A claim *hits* a truth when it is on that file and its line range covers the line.
"""

from __future__ import annotations

import contextlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import orjson

from caliper.core.inspect import adjudicate
from caliper.core.models import Claim, GaugeFinding, Kerf, Part, Severity
from caliper.core.repo_config import InspectConfig

# severities counted as "nits" for the nit-rate signal (severity <= minor).
_NIT_SEVERITIES = {Severity.nit, Severity.minor}


@dataclass(frozen=True)
class Metrics:
    """Review-quality metrics over one set of claims vs. the ground truth."""

    total_claims: int
    matched_claims: int
    total_truths: int
    matched_truths: int
    precision: float
    recall: float
    f1: float
    nit_rate: float
    snr: float  # signal-to-noise: matched claims / unmatched (noise) claims


def _covers(claim: Claim, file: str, line: int) -> bool:
    lo, hi = claim.line_range
    return claim.file == file and lo <= line <= hi


def score(claims: list[Claim], truths: set[tuple[str, int]]) -> Metrics:
    """Score *claims* against *truths*. Pure; no IO."""
    n = len(claims)
    matched_claims = sum(1 for c in claims if any(_covers(c, f, ln) for f, ln in truths))
    matched_truths = sum(1 for (f, ln) in truths if any(_covers(c, f, ln) for c in claims))
    precision = matched_claims / n if n else 0.0
    recall = matched_truths / len(truths) if truths else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    nits = sum(1 for c in claims if c.severity in _NIT_SEVERITIES)
    nit_rate = nits / n if n else 0.0
    noise = n - matched_claims
    snr = (matched_claims / noise) if noise else float(matched_claims)
    return Metrics(
        total_claims=n,
        matched_claims=matched_claims,
        total_truths=len(truths),
        matched_truths=matched_truths,
        precision=precision,
        recall=recall,
        f1=f1,
        nit_rate=nit_rate,
        snr=snr,
    )


@dataclass(frozen=True)
class CaseResult:
    """Per-case eval: metrics before and after Adjudicate + the drops by rule."""

    case_id: str
    pre: Metrics
    post: Metrics
    drops_by_rule: dict[str, int] = field(default_factory=dict)


def _parse(raw_claims: list) -> list[Claim]:
    out: list[Claim] = []
    for r in raw_claims:
        # Mirror the adjudicator's parse rule: drop anything that is not the schema.
        with contextlib.suppress(Exception):
            out.append(Claim.model_validate(r))
    return out


@dataclass(frozen=True)
class EvalCase:
    """One corpus case: a part, its review inputs, recorded claims, and ground truth."""

    case_id: str
    part: Part
    screen: list[GaugeFinding]
    raw_claims: list[dict]
    changed_lines: dict[str, set[int]]
    changed_text: dict[str, str]
    truths: set[tuple[str, int]]


def evaluate_case(case: EvalCase, cfg: InspectConfig | None = None) -> CaseResult:
    """Run a case through the real Adjudicate filter and score pre/post. Pure."""
    cfg = cfg or InspectConfig()
    pre_claims = _parse(case.raw_claims)
    adj = adjudicate(
        case.raw_claims,
        case.part,
        case.screen,
        cfg,
        case.changed_lines,
        case.changed_text,
    )
    drops = Counter(d.rule for d in adj.dropped)
    return CaseResult(
        case_id=case.case_id,
        pre=score(pre_claims, case.truths),
        post=score(adj.survivors, case.truths),
        drops_by_rule=dict(drops),
    )


def case_from_dict(case_id: str, data: dict) -> EvalCase:
    """Build an :class:`EvalCase` from a corpus JSON object (see docs for the schema)."""
    p = data["part"]
    part = Part(
        id=p.get("id", case_id),
        files=list(p["files"]),
        bucket=p["bucket"],
        size=int(p.get("size", 0)),
        opened_by=Kerf(fired_rule=p.get("opened_by", "eval")),
    )
    screen = [GaugeFinding.model_validate(g) for g in data.get("screen", [])]
    changed_lines = {f: set(lines) for f, lines in data.get("changed_lines", {}).items()}
    changed_text = dict(data.get("changed_text", {}))
    truths = {(t["file"], int(t["line"])) for t in data.get("truths", [])}
    return EvalCase(
        case_id=case_id,
        part=part,
        screen=screen,
        raw_claims=list(data.get("raw_claims", [])),
        changed_lines=changed_lines,
        changed_text=changed_text,
        truths=truths,
    )


def load_corpus(corpus_dir: Path) -> list[EvalCase]:
    """Load every ``*.json`` case under *corpus_dir* (sorted, deterministic)."""
    cases: list[EvalCase] = []
    for path in sorted(Path(corpus_dir).glob("*.json")):
        data = orjson.loads(path.read_bytes())
        cases.append(case_from_dict(path.stem, data))
    return cases


def aggregate(results: list[CaseResult]) -> dict:
    """Micro-average pre/post metrics across cases + summed drop counts. Pure."""

    def _micro(side: str) -> dict:
        tc = sum(getattr(r, side).total_claims for r in results)
        mc = sum(getattr(r, side).matched_claims for r in results)
        tt = sum(getattr(r, side).total_truths for r in results)
        mt = sum(getattr(r, side).matched_truths for r in results)
        nits = sum(
            round(getattr(r, side).nit_rate * getattr(r, side).total_claims) for r in results
        )
        precision = mc / tc if tc else 0.0
        recall = mt / tt if tt else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        noise = tc - mc
        return {
            "total_claims": tc,
            "matched_claims": mc,
            "total_truths": tt,
            "matched_truths": mt,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "nit_rate": round(nits / tc, 4) if tc else 0.0,
            "snr": round(mc / noise, 4) if noise else float(mc),
        }

    drops: Counter = Counter()
    for r in results:
        drops.update(r.drops_by_rule)
    total_raw = sum(r.pre.total_claims for r in results)
    drop_rate = {rule: round(n / total_raw, 4) for rule, n in drops.items()} if total_raw else {}
    return {
        "cases": len(results),
        "pre_adjudicate": _micro("pre"),
        "post_adjudicate": _micro("post"),
        "drops_by_rule": dict(drops),
        "drop_rate_by_rule": drop_rate,
    }
