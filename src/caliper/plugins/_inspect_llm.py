"""Review LLM backends — the isolated LLM path for ``caliper inspect``.

# tested-by: tests/unit/test_inspect_runner.py

This module is the ONLY place a model is invoked for inspection. It is
underscore-prefixed so ``autodiscover`` never pulls it into the review pipeline,
and it self-registers backends into the dedicated ``INSPECT_BACKENDS`` registry
(never ``ANALYZERS``). The deterministic tiers — Screen gauges and Adjudicate — are
structurally forbidden from importing this module (enforced by
``tests/unit/test_inspect_isolation.py``).

v0 ships the ``null`` backend (always unavailable -> Review fails soft). Real
backends (the local oMLX endpoint with a cloud fallback) are a research-fed
default: register them here behind the same ``LLMPort`` so the rest of the system
does not change. They must return only the raw claim schema; the adjudicator
rejects anything else.
"""

from __future__ import annotations

from caliper.core.llm_port import DraftRequest, DraftResult, LLMResult, LLMReview
from caliper.core.registries import GAUGE_DRAFTERS, INSPECT_BACKENDS


class NullLLM:
    """A backend that is always unavailable — Review is skipped (fail-soft).

    This is the safe default: with no model wired, inspection runs Screen + Adjudicate
    deterministically and the report records ``skipped_llm=True`` with no invented
    claims.
    """

    def review(self, review: LLMReview) -> LLMResult:
        return LLMResult(available=False, raw_claims=[], note="LLM backend 'null' is unavailable")


@INSPECT_BACKENDS.register("null")
def build_null_backend() -> NullLLM:
    return NullLLM()


class NullGaugeDrafter:
    """A gauge drafter that is always unavailable — propose drafts no candidates.

    The safe default: with no model wired, the flywheel surfaces ranked clusters but
    mints nothing. Real drafters (oMLX/cloud) register here behind the same port and
    must emit a candidate gauge spec; the backtest and human promotion gate it.
    """

    def draft(self, request: DraftRequest) -> DraftResult:
        return DraftResult(available=False, note="gauge drafter 'null' is unavailable")


@GAUGE_DRAFTERS.register("null")
def build_null_drafter() -> NullGaugeDrafter:
    return NullGaugeDrafter()
