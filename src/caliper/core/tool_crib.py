"""The tool crib — the promotion gate and registry of promoted Tier 0 gauges.

# tested-by: tests/unit/test_gauge_promotion.py

This module holds the single load-bearing safety boundary of the flywheel: a gauge
is active in Tier 0 only if a ``Promotion`` exists for it, and the ONLY function
that writes a Promotion is :func:`promote`, which requires a passing backtest and an
explicit human promoter. There is no path from an LLM draft to an active gauge that
skips both — ``propose`` (the LLM step) and ``backtest`` never write here.

Each Promotion records full lineage (the cluster, the backtest stats at promotion,
the model/prompt versions that drafted it, and who promoted it when), so a gauge's
origin is auditable forever. The crib is a plain JSON-per-key directory, separate
from the decision audit lake.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import orjson

from caliper.core.gauge import GaugeError
from caliper.core.models import Backtest, CandidateGauge, Promotion


def _crib_path(crib_dir: Path, cluster_key: str) -> Path:
    safe = cluster_key.replace("/", "_")
    return Path(crib_dir) / f"{safe}.json"


def promote(
    candidate: CandidateGauge,
    backtest: Backtest,
    *,
    promoted_by: str,
    promoted_at: datetime,
    crib_dir: Path,
) -> Promotion:
    """Promote *candidate* into the tool crib — the only path that activates a gauge.

    Refuses (``GaugeError``) without a passing backtest or without a named promoter.
    Records full lineage and persists it.
    """
    if not backtest.passed:
        raise GaugeError("refusing to promote: backtest did not pass")
    if not promoted_by.strip():
        raise GaugeError("refusing to promote: an explicit --by promoter is required")

    promotion = Promotion(
        candidate=candidate.model_copy(update={"backtest": backtest}),
        backtest=backtest,
        promoted_by=promoted_by,
        promoted_at=promoted_at,
    )
    crib = Path(crib_dir)
    crib.mkdir(parents=True, exist_ok=True)
    _crib_path(crib, candidate.cluster_key).write_bytes(
        orjson.dumps(promotion.model_dump(mode="json"), option=orjson.OPT_INDENT_2)
    )
    return promotion


def load_promotions(crib_dir: Path) -> list[Promotion]:
    """Load all promotions (the active Tier 0 gauges derived via the flywheel)."""
    crib = Path(crib_dir)
    if not crib.exists():
        return []
    out: list[Promotion] = []
    for path in sorted(crib.glob("*.json")):
        out.append(Promotion.model_validate_json(path.read_bytes()))
    return out


def active_cluster_keys(crib_dir: Path) -> set[str]:
    """The cluster keys that have been promoted (so ``propose`` can exclude them)."""
    return {p.candidate.cluster_key for p in load_promotions(crib_dir)}


def is_active(cluster_key: str, crib_dir: Path) -> bool:
    """True iff a Promotion exists for *cluster_key* — the only definition of active."""
    return _crib_path(Path(crib_dir), cluster_key).exists()
