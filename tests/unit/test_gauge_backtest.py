"""Tests for the deterministic backtest — ``core.backtest`` (the real gate).

# tested-by: tests/unit/test_gauge_backtest.py

The backtest, not the LLM, decides what is promotable. It is deterministic and
gates a candidate on all four measures: recall, precision, determinism, and
performance. The gauge runner is injected so the logic is testable without a real
semgrep/AST engine.

Property domains (DPS-12):
  Determinism INVARIANT  same inputs -> identical Backtest
  Integrity   SAFETY     a candidate failing any measure does not pass
"""

from __future__ import annotations

from caliper.core.backtest import RunOutput, backtest
from caliper.core.models import CandidateGauge
from caliper.core.repo_config import GaugeConfig

_CANDIDATE = CandidateGauge(
    cluster_key="k", kind="semgrep", draft="rule", model_version="m", prompt_version="v0"
)
_HIST = ["h1", "h2", "h3", "h4"]
_CLEAN = [f"c{i}" for i in range(20)]
CFG = GaugeConfig()


def _runner(hit: set[str], runtime_ms: int = 10):
    """A deterministic runner: flags exactly the samples in *hit* that are present."""

    def run(candidate: CandidateGauge, samples: list[str]) -> RunOutput:
        return RunOutput(hits={s for s in samples if s in hit}, runtime_ms=runtime_ms)

    return run


def test_all_measures_pass() -> None:
    bt = backtest(_CANDIDATE, _HIST, _CLEAN, _runner(set(_HIST)), CFG)
    assert bt.recall == 1.0
    assert bt.precision == 1.0
    assert bt.deterministic is True
    assert bt.passed is True


def test_recall_gate_rejects() -> None:
    bt = backtest(_CANDIDATE, _HIST, _CLEAN, _runner({"h1"}), CFG)  # catches 1/4 = 0.25
    assert bt.recall == 0.25
    assert bt.passed is False


def test_precision_gate_rejects_noise() -> None:
    """An over-broad candidate that fires across the clean corpus fails precision."""
    noisy = _runner(set(_HIST) | set(_CLEAN))  # fires on everything
    bt = backtest(_CANDIDATE, _HIST, _CLEAN, noisy, CFG)
    assert bt.recall == 1.0  # it does catch the historical hits...
    assert bt.precision < 1.0  # ...but its false-positive rate is too high
    assert bt.passed is False


def test_determinism_gate_rejects_order_dependent_candidate() -> None:
    def order_dependent(candidate: CandidateGauge, samples: list[str]) -> RunOutput:
        return RunOutput(hits={samples[0]} if samples else set(), runtime_ms=10)

    bt = backtest(_CANDIDATE, _HIST, _CLEAN, order_dependent, CFG)
    assert bt.deterministic is False
    assert bt.passed is False


def test_performance_gate_rejects_slow_candidate() -> None:
    bt = backtest(_CANDIDATE, _HIST, _CLEAN, _runner(set(_HIST), runtime_ms=999999), CFG)
    assert bt.runtime_ms > CFG.runtime_budget_ms
    assert bt.passed is False


def test_backtest_is_deterministic() -> None:
    """Determinism INVARIANT: same inputs -> identical Backtest."""
    runner = _runner(set(_HIST))
    a = backtest(_CANDIDATE, _HIST, _CLEAN, runner, CFG)
    b = backtest(_CANDIDATE, list(reversed(_HIST)), list(reversed(_CLEAN)), runner, CFG)
    assert a.model_dump() == b.model_dump()
