"""Tests for the convergence scorecard — ``core.gauge_status``.

# tested-by: tests/unit/test_gauge_status.py
"""

from __future__ import annotations

from caliper.core.gauge_status import convergence
from caliper.core.models import Claim, LedgerEntry
from caliper.core.repo_config import GaugeConfig

CFG = GaugeConfig()


def _entry(assertion, sha, ch, evidence=None):
    return LedgerEntry(
        claim=Claim(
            file="a.py",
            line_range=(1, 2),
            severity="major",
            category="correctness",
            assertion=assertion,
            evidence_ref=evidence,
        ),
        repo="r",
        sha=sha,
        content_hash=ch,
        author=sha,
    )


def test_empty_ledger_zeroes() -> None:
    s = convergence([], CFG, 0)
    assert s.total_claims == 0
    assert s.substantiation_rate == 0.0


def test_substantiation_and_recurrence_rates() -> None:
    entries = [
        _entry("missing null check", "s1", "p1", evidence="f1"),  # substantiated, recurring
        _entry("missing null check", "s2", "p2"),  # recurring (same cluster)
        _entry("unique novel issue", "s3", "p3"),  # novel (one part)
    ]
    s = convergence(entries, CFG, promotions_count=2)
    assert s.total_claims == 3
    assert s.total_clusters == 2
    assert s.substantiation_rate == 1 / 3
    assert s.advisory_recurrence_rate == 0.5  # 1 of 2 clusters recurs
    assert s.llm_novelty_rate == 0.5  # 1 of 2 clusters seen once
    assert s.gauge_coverage == 2


def test_status_is_deterministic() -> None:
    entries = [_entry("a", "s1", "p1"), _entry("a", "s2", "p2"), _entry("b", "s3", "p3")]
    assert (
        convergence(entries, CFG, 1).model_dump()
        == convergence(list(reversed(entries)), CFG, 1).model_dump()
    )
