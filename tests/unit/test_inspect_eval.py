"""Tests for the review-quality eval harness — ``core.inspect_eval``.

# tested-by: tests/unit/test_inspect_eval.py

Scoring is pure (claims + ground truth -> metrics); the harness runs the real pure
Adjudicate filter, so the whole thing is deterministic and needs no model.
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.inspect_eval import (
    EvalCase,
    aggregate,
    case_from_dict,
    evaluate_case,
    load_corpus,
    score,
)
from caliper.core.models import Claim, GaugeFinding


def _claim(file="a.py", lr=(1, 1), sev="major", cat="correctness") -> Claim:
    return Claim(file=file, line_range=lr, severity=sev, category=cat, assertion="x")


def test_score_precision_recall_f1() -> None:
    claims = [_claim(lr=(1, 1)), _claim(lr=(5, 5))]  # one hits, one misses
    m = score(claims, {("a.py", 1)})
    assert m.matched_claims == 1 and m.matched_truths == 1
    assert m.precision == 0.5 and m.recall == 1.0
    assert abs(m.f1 - (2 * 0.5 * 1.0 / 1.5)) < 1e-9


def test_score_empty_claims_is_zero_not_crash() -> None:
    m = score([], {("a.py", 1)})
    assert m.precision == 0.0 and m.recall == 0.0 and m.snr == 0.0


def _case(case_id: str, raw_claims, truths, changed_text=None) -> EvalCase:
    return EvalCase(
        case_id=case_id,
        part=case_from_dict(case_id, {"part": {"files": ["a.py"], "bucket": "logic"}}).part,
        screen=[],
        raw_claims=raw_claims,
        changed_lines={"a.py": {1, 2}},
        changed_text=changed_text or {"a.py": ""},
        truths=truths,
    )


def test_adjudicate_improves_precision_by_dropping_out_of_scope() -> None:
    raw = [
        {
            "file": "a.py",
            "line_range": [1, 1],
            "severity": "major",
            "category": "correctness",
            "assertion": "real",
        },
        {
            "file": "other.py",
            "line_range": [1, 1],
            "severity": "major",
            "category": "correctness",
            "assertion": "oos",
        },
    ]
    res = evaluate_case(_case("c", raw, {("a.py", 1)}))
    # pre: 2 claims, 1 hit -> precision 0.5; post: scope drops the out-of-file claim -> 1.0
    assert res.pre.precision == 0.5
    assert res.post.precision == 1.0
    assert res.drops_by_rule.get("scope") == 1


def test_substantiated_blocking_survives_in_eval() -> None:
    screen = [
        GaugeFinding(id="f1", file="a.py", line_range=(1, 1), category="security", severity="high")
    ]
    raw = [
        {
            "file": "a.py",
            "line_range": [1, 1],
            "severity": "blocking",
            "category": "security",
            "assertion": "sqli",
        }
    ]
    case = EvalCase(
        case_id="c2",
        part=case_from_dict("c2", {"part": {"files": ["a.py"], "bucket": "logic"}}).part,
        screen=screen,
        raw_claims=raw,
        changed_lines={"a.py": {1}},
        changed_text={"a.py": ""},
        truths={("a.py", 1)},
    )
    res = evaluate_case(case)
    assert res.post.matched_truths == 1 and res.post.recall == 1.0


def test_aggregate_micro_averages_and_drop_rate() -> None:
    raw = [
        {
            "file": "a.py",
            "line_range": [1, 1],
            "severity": "major",
            "category": "correctness",
            "assertion": "r",
        },
        {
            "file": "z.py",
            "line_range": [1, 1],
            "severity": "major",
            "category": "correctness",
            "assertion": "oos",
        },
    ]
    results = [evaluate_case(_case("c1", raw, {("a.py", 1)}))]
    agg = aggregate(results)
    assert agg["cases"] == 1
    assert agg["pre_adjudicate"]["total_claims"] == 2
    assert agg["post_adjudicate"]["precision"] == 1.0
    assert agg["drop_rate_by_rule"].get("scope") == 0.5  # 1 of 2 raw claims dropped by scope


def test_load_corpus_reads_shipped_examples() -> None:
    corpus = Path("docs/llm-review/eval-corpus")
    cases = load_corpus(corpus)
    assert {c.case_id for c in cases} >= {"case-divzero", "case-sqli"}
    # the sqli case's blocking claim is substantiated by its screen finding and survives
    sqli = next(c for c in cases if c.case_id == "case-sqli")
    res = evaluate_case(sqli)
    assert res.post.recall == 1.0
