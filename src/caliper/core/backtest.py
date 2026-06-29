"""The backtest — deterministic validation that gates candidate gauges (no LLM).

# tested-by: tests/unit/test_gauge_backtest.py

This is the real filter of the flywheel: the LLM's draft gets no free pass:
deterministic validation decides what is even promotable. A candidate must pass all
four measures to become promotable:

- **recall** — catch at least ``recall_floor`` of the historical hits (the corpus
  where the source claims fired);
- **precision** — fire on the clean corpus below the ``precision_fp_ceiling`` false-
  positive rate (an over-broad nitpick fails here);
- **determinism** — same findings across two runs and across input ordering;
- **performance** — run within the Screen time budget.

The gauge runner is injected so this logic is testable without a real engine and so
``backtest`` itself stays free of the LLM. The PASS/FAIL is deterministic; only the
candidate's draft (upstream) was not.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from caliper.core.models import Backtest, CandidateGauge
from caliper.core.repo_config import GaugeConfig


@dataclass(frozen=True)
class RunOutput:
    """The result of running a candidate gauge over a corpus of samples."""

    hits: set[str] = field(default_factory=set)
    runtime_ms: int = 0


# (candidate, samples) -> which samples it flags + how long it took. Deterministic.
GaugeRunner = Callable[[CandidateGauge, list[str]], RunOutput]


def backtest(
    candidate: CandidateGauge,
    historical: list[str],
    clean: list[str],
    runner: GaugeRunner,
    cfg: GaugeConfig,
) -> Backtest:
    """Run the four-part backtest for *candidate*. Deterministic; LLM-free.

    ``historical`` are the sample ids where the source claims fired (located via the
    ledger's content references); ``clean`` are samples that should not fire.
    """
    hist_set = set(historical)
    clean_set = set(clean)

    out_h = runner(candidate, historical)
    out_h_rev = runner(candidate, list(reversed(historical)))
    out_c = runner(candidate, clean)
    out_c_rev = runner(candidate, list(reversed(clean)))

    deterministic = out_h.hits == out_h_rev.hits and out_c.hits == out_c_rev.hits

    caught = out_h.hits & hist_set
    recall = (len(caught) / len(hist_set)) if hist_set else 0.0

    false_positives = out_c.hits & clean_set
    fp_rate = (len(false_positives) / len(clean_set)) if clean_set else 0.0
    precision = 1.0 - fp_rate

    runtime_ms = max(out_h.runtime_ms, out_c.runtime_ms)

    passed = (
        recall >= cfg.recall_floor
        and fp_rate <= cfg.precision_fp_ceiling
        and deterministic
        and runtime_ms <= cfg.runtime_budget_ms
    )
    return Backtest(
        recall=recall,
        precision=precision,
        deterministic=deterministic,
        runtime_ms=runtime_ms,
        passed=passed,
    )
