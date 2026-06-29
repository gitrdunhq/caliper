"""Review LLM backends — the isolated LLM path for ``caliper inspect``.

# tested-by: tests/unit/test_inspect_runner.py

This module is the ONLY place a model is invoked for inspection. It is
underscore-prefixed so ``autodiscover`` never pulls it into the review pipeline,
and it self-registers backends into the dedicated ``INSPECT_BACKENDS`` registry
(never ``ANALYZERS``). The deterministic tiers — Screen gauges and Adjudicate — are
structurally forbidden from importing this module (enforced by
``tests/unit/test_inspect_isolation.py``).

The ``null`` backend (always unavailable -> Review fails soft) is the safe default.
Real backends — ``openai`` (any OpenAI-compatible endpoint) and ``omlx`` (a local
oMLX server, also OpenAI-compatible) — register here behind the same ``LLMPort`` and
reuse the shared ``LlmClient`` transport, so endpoint/model/key come from the
``CALIPER_LLM_*`` settings and the rest of the system does not change. They return
only the raw claim schema; the adjudicator validates and filters everything.
"""

from __future__ import annotations

import json

from caliper.core.config import CaliperSettings
from caliper.core.llm_client import LlmClient
from caliper.core.llm_port import DraftRequest, DraftResult, LLMResult, LLMReview
from caliper.core.registries import GAUGE_DRAFTERS, INSPECT_BACKENDS

# Claims can be long; the transport's 200-token default would truncate them.
_REVIEW_MAX_TOKENS = 4000
_REVIEW_SYSTEM = (
    "You are a meticulous code reviewer. Reply with ONLY a JSON array of claim "
    "objects matching the schema in the prompt — no prose, no markdown."
)


def parse_claims_json(text: str) -> list[dict]:
    """Best-effort extraction of a JSON array of claim dicts from a model reply.

    Tolerates Markdown code fences and surrounding prose. Returns only dict items;
    the adjudicator's parse rule validates each against the Claim schema, so this is
    deliberately permissive — it never raises.
    """
    text = text.strip()
    if not text:
        return []
    if text.startswith("```"):
        text = text.strip("`")
        if text[:4].lower() == "json":
            text = text[4:]
        text = text.strip()
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(text[start : end + 1])
        except (ValueError, TypeError):
            return []
        return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return []
    if isinstance(obj, dict):
        return [obj]
    return [d for d in obj if isinstance(d, dict)] if isinstance(obj, list) else []


class OpenAICompatReviewer:
    """A Review backend over any OpenAI-compatible chat endpoint, via ``LlmClient``.

    Transport (endpoint, model, key, timeout, fail-open) is the shared ``LlmClient``;
    this class only renders the request and parses the JSON claims out of the reply.
    A disabled/misconfigured client or an empty reply yields ``available=False`` so
    Review fails soft (no invented claims). The client is injectable for testing.
    """

    def __init__(self, client: LlmClient | None = None, *, max_tokens: int = _REVIEW_MAX_TOKENS):
        self._client = client if client is not None else LlmClient(CaliperSettings())
        self._max_tokens = max_tokens

    def review(self, review: LLMReview) -> LLMResult:
        if not self._client.enabled:
            return LLMResult(available=False, note="LLM endpoint not configured (CALIPER_LLM_*)")
        messages = [
            {"role": "system", "content": _REVIEW_SYSTEM},
            {"role": "user", "content": review.prompt},
        ]
        text = self._client.complete(messages, max_tokens=self._max_tokens)
        if not text.strip():
            return LLMResult(available=False, note="LLM returned no content")
        claims = parse_claims_json(text)
        return LLMResult(available=True, raw_claims=claims, note=f"{len(claims)} claims parsed")


class OmlxReviewer(OpenAICompatReviewer):
    """Local oMLX Review backend (the research-fed default model host).

    oMLX serves an OpenAI-compatible API, so behavior is identical to
    ``OpenAICompatReviewer``; the distinct registry key documents intent and lets the
    endpoint be pointed at a local server via ``CALIPER_LLM_ENDPOINT``.
    """


@INSPECT_BACKENDS.register("openai")
def build_openai_backend() -> OpenAICompatReviewer:
    return OpenAICompatReviewer()


@INSPECT_BACKENDS.register("omlx")
def build_omlx_backend() -> OmlxReviewer:
    return OmlxReviewer()


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
