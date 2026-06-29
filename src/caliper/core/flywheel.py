"""Deterministic clustering, ranking, and candidacy guards for the flywheel.

# tested-by: tests/unit/test_gauge_flywheel.py

The same ledger always produces the same clusters and the same ranking — only the
downstream drafting step is nondeterministic, and it is gated by the backtest and a
human. Clustering groups recurring advisory claims; ranking orders by recurrence x
severity; the candidacy guards (a pure predicate) keep one noisy run from minting a
rule: nits/style are ineligible and a cluster must recur across enough distinct
parts and authors.
"""

from __future__ import annotations

import hashlib
import re

from caliper.core.models import (
    SEVERITY_RANK,
    Category,
    ClaimCluster,
    LedgerEntry,
    Severity,
)
from caliper.core.repo_config import GaugeConfig

_NONWORD = re.compile(r"[^a-z0-9 ]+")
_NUMERIC = re.compile(r"\b\d+\b")
_SPACES = re.compile(r"\s+")


def normalize_assertion(text: str) -> str:
    """Normalize an assertion to a stable signature for clustering (deterministic)."""
    t = text.lower()
    t = _NONWORD.sub(" ", t)
    t = _NUMERIC.sub("", t)
    return _SPACES.sub(" ", t).strip()


def cluster_key(category: str, assertion: str) -> str:
    """Content-derived, deterministic cluster key for a (category, pattern)."""
    payload = f"{category}|{normalize_assertion(assertion)}".encode()
    return "g-" + hashlib.sha256(payload).hexdigest()[:16]


def _member_sort_key(e: LedgerEntry) -> tuple:
    return (e.content_hash, e.sha, e.claim.file, e.claim.line_range, e.inspected_at.isoformat())


def cluster(entries: list[LedgerEntry], cfg: GaugeConfig) -> list[ClaimCluster]:
    """Group ledger entries into deterministic clusters, ranked recurrence x severity."""
    grouped: dict[str, list[LedgerEntry]] = {}
    for e in entries:
        key = cluster_key(e.claim.category.value, e.claim.assertion)
        grouped.setdefault(key, []).append(e)

    clusters: list[ClaimCluster] = []
    for key, members in grouped.items():
        members = sorted(members, key=_member_sort_key)
        distinct_parts = len({m.content_hash for m in members})
        distinct_authors = len({(m.author or m.sha) for m in members})
        sev_weight = max(SEVERITY_RANK[m.claim.severity] for m in members) + 1
        rank = float(distinct_parts * sev_weight)
        clusters.append(
            ClaimCluster(
                key=key,
                category=members[0].claim.category,
                members=members,
                distinct_parts=distinct_parts,
                distinct_authors=distinct_authors,
                rank=rank,
            )
        )
    # Deterministic order: highest rank first, ties broken by the stable key.
    clusters.sort(key=lambda c: (-c.rank, c.key))
    return clusters


def eligible(c: ClaimCluster, cfg: GaugeConfig) -> bool:
    """Candidacy guards (all mandatory): category floor, recurrence, not pure-nit."""
    if c.category.value not in cfg.eligible_categories:
        return False  # candidacy floor: only correctness/security/behavioral-change
    if c.distinct_parts < cfg.recurrence_min_parts:
        return False  # recurrence threshold (distinct parts)
    if c.distinct_authors < cfg.recurrence_min_authors:
        return False  # recurrence threshold (distinct authors/PRs)
    max_sev = max((SEVERITY_RANK[m.claim.severity] for m in c.members), default=0)
    # a pure-nit cluster never mints a rule
    return max_sev > SEVERITY_RANK[Severity.nit]


def top_candidates(
    entries: list[LedgerEntry],
    cfg: GaugeConfig,
    *,
    top: int,
    exclude_keys: set[str] | None = None,
) -> list[ClaimCluster]:
    """Eligible clusters, ranked, minus any already-promoted keys, capped at *top*."""
    exclude = exclude_keys or set()
    ranked = [c for c in cluster(entries, cfg) if eligible(c, cfg) and c.key not in exclude]
    return ranked[:top]


__all__ = [
    "Category",
    "cluster",
    "cluster_key",
    "eligible",
    "normalize_assertion",
    "top_candidates",
]
