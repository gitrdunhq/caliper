"""Propose — the flywheel's only LLM step: draft candidate gauges from clusters.

# tested-by: tests/unit/test_gauge_propose.py

Deterministic clustering and ranking (``core.flywheel``) decide *which* clusters to
draft; the LLM (behind ``GaugeDraftPort``) drafts a candidate for each. Drafting is
the only nondeterministic step, and it is gated downstream by the deterministic
backtest and an explicit human promotion — a candidate here is a draft, never an
active gauge. Fail-soft: an unavailable drafter yields no candidates (never invents
one). Already-promoted clusters are excluded so the loop closes.
"""

from __future__ import annotations

from caliper.core.flywheel import top_candidates
from caliper.core.llm_port import DraftRequest, GaugeDraftPort
from caliper.core.models import CandidateGauge, LedgerEntry
from caliper.core.registries import GAUGE_DRAFTERS
from caliper.core.repo_config import GaugeConfig


def resolve_drafter(cfg: GaugeConfig) -> GaugeDraftPort:
    """Resolve the configured drafter from the registry (the CLI registers backends)."""
    return GAUGE_DRAFTERS.create(cfg.drafter)


def propose(
    entries: list[LedgerEntry],
    cfg: GaugeConfig,
    drafter: GaugeDraftPort,
    *,
    top: int,
    exclude_keys: set[str] | None = None,
) -> list[CandidateGauge]:
    """Draft candidate gauges for the top eligible, not-yet-promoted clusters."""
    candidates: list[CandidateGauge] = []
    for c in top_candidates(entries, cfg, top=top, exclude_keys=exclude_keys):
        req = DraftRequest(
            cluster_key=c.key,
            category=c.category.value,
            assertions=[m.claim.assertion for m in c.members[:5]],
            examples=[
                f"{m.claim.file}:{m.claim.line_range[0]}-{m.claim.line_range[1]}"
                for m in c.members[:5]
            ],
        )
        res = drafter.draft(req)
        if not res.available:
            continue  # fail-soft: no candidate invented
        candidates.append(
            CandidateGauge(
                cluster_key=c.key,
                kind=res.kind,  # type: ignore[arg-type]
                draft=res.draft,
                model_version=cfg.model_id,
                prompt_version=cfg.prompt_version,
            )
        )
    return candidates
