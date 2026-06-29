"""Tests for the promotion gate / tool crib — ``core.tool_crib`` (load-bearing).

# tested-by: tests/unit/test_gauge_promotion.py

The defining safety property: the LLM drafts but never promotes. A gauge is active
in Tier 0 only if a ``Promotion`` exists for it, and the only function that writes a
Promotion is ``promote()``, which requires a passing backtest and an explicit human.

Property domains (DPS-12):
  Non-repudiation INVARIANT proof of promotion (lineage) always exists once created
  Integrity       SAFETY    no gauge is active without a Promotion
"""

from __future__ import annotations

import pytest

from caliper.core.gauge import GaugeError
from caliper.core.models import Backtest, CandidateGauge
from caliper.core.tool_crib import active_cluster_keys, is_active, load_promotions, promote

_PASS = Backtest(recall=1.0, precision=1.0, deterministic=True, runtime_ms=10, passed=True)
_FAIL = Backtest(recall=0.1, precision=1.0, deterministic=True, runtime_ms=10, passed=False)
_CAND = CandidateGauge(
    cluster_key="cluster-abc",
    kind="semgrep",
    draft="rule text",
    model_version="m1",
    prompt_version="v0",
)

_WHEN = "2026-06-29T00:00:00+00:00"


def _ts():
    from datetime import datetime

    return datetime.fromisoformat(_WHEN)


def test_no_auto_promotion_until_promote_called(tmp_path) -> None:
    """A candidate, however high its backtest, is not active until a Promotion exists."""
    crib = tmp_path / "crib"
    assert is_active("cluster-abc", crib) is False  # passing backtest alone does nothing
    promote(_CAND, _PASS, promoted_by="maria", promoted_at=_ts(), crib_dir=crib)
    assert is_active("cluster-abc", crib) is True


def test_backtest_does_not_write_crib(tmp_path) -> None:
    """Structural: running a backtest never activates a gauge (only promote writes)."""
    from caliper.core.backtest import RunOutput, backtest
    from caliper.core.repo_config import GaugeConfig

    crib = tmp_path / "crib"
    backtest(
        _CAND,
        ["h1"],
        ["c1"],
        lambda c, s: RunOutput({"h1"} if "h1" in s else set(), 5),
        GaugeConfig(),
    )
    assert not crib.exists() or list(crib.glob("*.json")) == []
    assert active_cluster_keys(crib) == set()


def test_promote_refuses_without_passing_backtest(tmp_path) -> None:
    with pytest.raises(GaugeError):
        promote(_CAND, _FAIL, promoted_by="maria", promoted_at=_ts(), crib_dir=tmp_path / "crib")
    assert is_active("cluster-abc", tmp_path / "crib") is False


def test_promote_refuses_without_promoter(tmp_path) -> None:
    with pytest.raises(GaugeError):
        promote(_CAND, _PASS, promoted_by="", promoted_at=_ts(), crib_dir=tmp_path / "crib")
    assert is_active("cluster-abc", tmp_path / "crib") is False


def test_lineage_is_recorded_and_persisted(tmp_path) -> None:
    crib = tmp_path / "crib"
    promo = promote(_CAND, _PASS, promoted_by="maria", promoted_at=_ts(), crib_dir=crib)
    # the in-memory promotion carries full lineage
    assert promo.candidate.cluster_key == "cluster-abc"
    assert promo.candidate.model_version == "m1"
    assert promo.candidate.prompt_version == "v0"
    assert promo.backtest.passed is True
    assert promo.promoted_by == "maria"
    # and it round-trips from disk
    loaded = load_promotions(crib)
    assert len(loaded) == 1
    assert loaded[0].candidate.cluster_key == "cluster-abc"
    assert loaded[0].backtest.recall == 1.0
    assert loaded[0].promoted_by == "maria"
