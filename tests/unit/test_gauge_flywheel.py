"""Tests for deterministic clustering/ranking + candidacy guards — ``core.flywheel``.

# tested-by: tests/unit/test_gauge_flywheel.py

Clustering and ranking are deterministic (only the downstream drafting step is not).
The candidacy guards stop one noisy run from minting a rule: nits/style are
ineligible and a cluster must recur across enough distinct parts and authors.

Property domains (DPS-12):
  Determinism INVARIANT same ledger -> identical clusters + ranking, any order
  Integrity   SAFETY    ineligible clusters never become candidates
"""

from __future__ import annotations

from caliper.core.flywheel import cluster, eligible, top_candidates
from caliper.core.models import Claim, LedgerEntry
from caliper.core.repo_config import GaugeConfig

CFG = GaugeConfig()


def _entry(
    assertion="off by one error", cat="correctness", sha="s1", ch="p1", author="a1", sev="major"
):
    return LedgerEntry(
        claim=Claim(
            file="a.py", line_range=(1, 2), severity=sev, category=cat, assertion=assertion
        ),
        repo="r",
        sha=sha,
        content_hash=ch,
        author=author,
    )


def _recurring(cat="correctness", n=3):
    """A cluster recurring across n distinct parts and authors."""
    return [
        _entry(
            assertion="missing null check before deref",
            cat=cat,
            sha=f"s{i}",
            ch=f"p{i}",
            author=f"a{i}",
        )
        for i in range(n)
    ]


def test_clustering_is_deterministic_independent_of_order() -> None:
    entries = _recurring("correctness", 3) + _recurring("security", 2)
    a = cluster(entries, CFG)
    b = cluster(list(reversed(entries)), CFG)
    assert [c.model_dump() for c in a] == [c.model_dump() for c in b]


def test_same_pattern_groups_together_distinct_counts() -> None:
    entries = _recurring("correctness", 3)
    clusters = cluster(entries, CFG)
    assert len(clusters) == 1
    c = clusters[0]
    assert c.distinct_parts == 3
    assert c.distinct_authors == 3
    assert c.category.value == "correctness"


def test_ranking_orders_by_recurrence_times_severity() -> None:
    big = _recurring("correctness", 4)  # 4 parts
    small = _recurring("security", 2)  # 2 parts, different pattern
    small = [
        _entry(assertion="weak hash used", cat="security", sha=f"x{i}", ch=f"q{i}", author=f"b{i}")
        for i in range(2)
    ]
    clusters = cluster(big + small, CFG)
    assert clusters[0].rank >= clusters[1].rank  # sorted by rank desc


def test_candidacy_style_and_nit_are_ineligible() -> None:
    style = cluster(
        [
            _entry(
                assertion="prefer f-string", cat="style", sha=f"s{i}", ch=f"p{i}", author=f"a{i}"
            )
            for i in range(4)
        ],
        CFG,
    )[0]
    assert eligible(style, CFG) is False  # style category not in candidacy floor

    nits = cluster(
        [
            _entry(
                assertion="trailing whitespace",
                cat="correctness",
                sha=f"s{i}",
                ch=f"p{i}",
                author=f"a{i}",
                sev="nit",
            )
            for i in range(4)
        ],
        CFG,
    )[0]
    assert eligible(nits, CFG) is False  # pure-nit cluster ineligible


def test_candidacy_below_recurrence_threshold_is_ineligible() -> None:
    one_part = cluster([_entry(sha="s1", ch="p1", author="a1")], CFG)[0]
    assert one_part.distinct_parts == 1
    assert eligible(one_part, CFG) is False  # below recurrence_min_parts (default 3)


def test_eligible_cluster_passes_all_guards() -> None:
    c = cluster(_recurring("correctness", 3), CFG)[0]
    assert eligible(c, CFG) is True


def test_top_candidates_filters_ineligible_and_ranks() -> None:
    entries = _recurring("correctness", 3) + [
        _entry(assertion="prefer f-string", cat="style", sha=f"z{i}", ch=f"z{i}", author=f"z{i}")
        for i in range(5)
    ]
    top = top_candidates(entries, CFG, top=10)
    assert all(c.category.value in CFG.eligible_categories for c in top)
    assert all(eligible(c, CFG) for c in top)
