"""Convergence scorecard — the flywheel made measurable (``caliper gauge status``).

# tested-by: tests/unit/test_gauge_status.py

The point of the whole arc, measured: as recurring patterns become gauges, the
LLM's claims become substantiated (or never reach Tier 1), and its advisory output
trends toward only the genuinely novel. Pure and deterministic over the ledger.
"""

from __future__ import annotations

from pydantic import BaseModel

from caliper.core.flywheel import cluster
from caliper.core.models import LedgerEntry
from caliper.core.repo_config import GaugeConfig


class ConvergenceStats(BaseModel):
    """The convergence scorecard derived from the claims ledger + promotions."""

    total_claims: int
    total_clusters: int
    substantiation_rate: float  # claims carrying an evidence_ref (deterministic coverage)
    advisory_recurrence_rate: float  # clusters recurring across >1 part (open gaps)
    llm_novelty_rate: float  # clusters seen on exactly one part (genuinely new)
    gauge_coverage: int  # promoted gauges in the tool crib


def convergence(
    entries: list[LedgerEntry], cfg: GaugeConfig, promotions_count: int
) -> ConvergenceStats:
    """Compute the convergence scorecard. Deterministic over the ledger."""
    total = len(entries)
    substantiated = sum(1 for e in entries if e.claim.evidence_ref)
    clusters = cluster(entries, cfg)
    total_clusters = len(clusters)
    recurring = sum(1 for c in clusters if c.distinct_parts > 1)
    novel = sum(1 for c in clusters if c.distinct_parts == 1)
    return ConvergenceStats(
        total_claims=total,
        total_clusters=total_clusters,
        substantiation_rate=(substantiated / total) if total else 0.0,
        advisory_recurrence_rate=(recurring / total_clusters) if total_clusters else 0.0,
        llm_novelty_rate=(novel / total_clusters) if total_clusters else 0.0,
        gauge_coverage=promotions_count,
    )
