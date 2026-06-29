"""Tier 1 runner — drives the sealed LLM review and the cache.

# tested-by: tests/unit/test_inspect_runner.py

This is the LLM path: it resolves a backend from ``INSPECT_BACKENDS``, builds the
read-only review prompt (the part's changed hunks plus compact lower-parts context
within the token budget), consults the cache, and returns raw claims for the pure
adjudicator. It is fail-soft: if the backend is unavailable it returns no claims
and marks the review skipped — it never invents claims to fill a gap.

The deterministic tiers (Tier 0 gauges, Tier 2 adjudicator) must not import this
module (enforced by ``tests/unit/test_inspect_isolation.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from caliper.core.inspect_cache import InspectCache, content_key
from caliper.core.inspect_view import PartView
from caliper.core.llm_port import LLMPort, LLMReview
from caliper.core.models import Part
from caliper.core.registries import INSPECT_BACKENDS
from caliper.core.repo_config import InspectConfig

# Rough chars-per-token proxy for the lower-parts context budget (research-fed).
_CHARS_PER_TOKEN = 4


@dataclass(frozen=True)
class Tier1Output:
    """Raw (un-adjudicated) claims plus whether the LLM review ran."""

    raw_claims: list[dict] = field(default_factory=list)
    skipped_llm: bool = False
    note: str = ""


def resolve_backend(cfg: InspectConfig) -> LLMPort:
    """Resolve the configured LLM backend from the registry.

    The caller (the CLI tier) is responsible for importing the isolated backend
    module so its ``@INSPECT_BACKENDS.register`` side effect has run — core must not
    import the plugins tier (the tier-boundary guard enforces this).
    """
    return INSPECT_BACKENDS.create(cfg.backend)


def render_prompt(part: Part, view: PartView, lower_context: str, cfg: InspectConfig) -> str:
    """Render the read-only review prompt: full changed hunks + compact lower context.

    The lower-parts context is labeled read-only and truncated to the token budget;
    it is never to be reviewed, only used to understand the part under review.
    """
    budget_chars = max(0, cfg.token_budget * _CHARS_PER_TOKEN)
    lower = lower_context[:budget_chars]
    return (
        f"# Review part {part.id} (bucket: {part.bucket.value})\n"
        f"# Emit ONLY structured claims; no prose. Claims are advisory, never a verdict.\n\n"
        f"## Part under review (changed hunks)\n{view.diff_text}\n\n"
        f"## Lower parts (READ-ONLY context — do not review)\n{lower}\n"
    )


def run_tier1(
    part: Part,
    view: PartView,
    lower_context: str,
    cfg: InspectConfig,
    *,
    cache: InspectCache | None = None,
    backend: LLMPort | None = None,
    enabled: bool = True,
) -> Tier1Output:
    """Run the Tier 1 review for *part*. Cached on the part's content hash.

    Returns raw claims (validated only by the adjudicator). Skips (fail-soft) when
    disabled, when the bucket gets no LLM, or when the backend is unavailable.
    """
    if not enabled:
        return Tier1Output(skipped_llm=True, note="LLM review disabled (--no-llm)")
    if part.bucket.value not in cfg.llm_buckets:
        return Tier1Output(skipped_llm=True, note=f"bucket {part.bucket.value} gets no LLM review")

    key = content_key(part.files, view.changed_bytes, cfg.model_id, cfg.prompt_version)
    if cache is not None:
        cached = cache.get(key)
        if cached is not None:
            return Tier1Output(raw_claims=cached, skipped_llm=False, note="cache hit")

    backend = backend or resolve_backend(cfg)
    review = LLMReview(
        part_id=part.id,
        bucket=part.bucket.value,
        prompt=render_prompt(part, view, lower_context, cfg),
        model_id=cfg.model_id,
        prompt_version=cfg.prompt_version,
    )
    result = backend.review(review)
    if not result.available:
        # Fail-soft: no claims invented; the report notes the skip.
        return Tier1Output(skipped_llm=True, note=result.note or "LLM unavailable")
    if cache is not None:
        cache.put(key, result.raw_claims)
    return Tier1Output(raw_claims=result.raw_claims, skipped_llm=False, note=result.note)
