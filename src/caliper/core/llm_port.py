"""LLMPort — the sealed seam for the Tier 1 LLM review.

# tested-by: tests/unit/test_inspect_runner.py

The LLM is isolated behind this port (the analog of ``ToolRunnerPort``): it sits
between ``part()`` upstream and the pure adjudicator downstream. Tier code never
calls a model directly — it resolves a backend from the ``INSPECT_BACKENDS``
registry and calls :meth:`LLMPort.review`. Backends are swappable and fakeable.

This module defines only the *interface* (no model call). The concrete backends
live in the isolated ``caliper.plugins._inspect_llm`` module; the deterministic
tiers (Tier 0 gauges, Tier 2 adjudicator) must not import that path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class LLMReview:
    """The input to a single part review — a fully rendered, read-only request."""

    part_id: str
    bucket: str
    prompt: str  # rendered: the part's changed hunks + compact lower-parts context
    model_id: str
    prompt_version: str


@dataclass(frozen=True)
class LLMResult:
    """The output of a review — raw claims (not yet adjudicated) or unavailability.

    ``raw_claims`` are the model's emissions as plain dicts; they are validated and
    filtered only by the pure adjudicator. ``available=False`` means Tier 1 was
    skipped (fail-soft): the report shows Tier 0 results and notes the skip; no
    claims are invented to fill the gap.
    """

    available: bool
    raw_claims: list[dict] = field(default_factory=list)
    note: str = ""


@runtime_checkable
class LLMPort(Protocol):
    """Structural contract for an LLM review backend."""

    def review(self, review: LLMReview) -> LLMResult: ...
