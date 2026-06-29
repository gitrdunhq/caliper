"""The inspection adjudicator — pure Adjudicate filter over LLM claims.

# tested-by: tests/unit/test_inspect_adjudicator.py

``adjudicate()`` is the deterministic gate between the LLM (Review) and a human:
no LLM output reaches an inspection report except through this function. It is a
**pure** function — a sibling of ``core.parting.part()`` — with no IO, clock, or
randomness, so it is property-tested.

This module is part of the deterministic decision path and MUST NOT import the LLM
path (``core.llm_port`` backends, ``core.inspect_runner``, ``plugins._inspect_llm``).
A structural test enforces that isolation, mirroring how the PARTING registry is
isolated from the auto pipeline.

Rules, applied in firing order (drops/changes are logged with the firing rule):
  0. parse           reject anything that is not the claim schema (never salvage)
  1. scope           drop claims whose file is outside the part's file set
  2. anchor          drop claims not on a real changed line; when ``anchor_quote`` is
                     given it must be a verbatim substring of the part's changed text
                     (checked before line numbers are trusted)
  3. substantiation  a blocking claim with no Screen evidence_ref is DOWNGRADED to
                     advisory (major), not deleted — keep the signal, deny gate power
  4. category        drop categories the bucket does not admit (config allow-list)
  5. floor           drop claims below the bucket's severity floor
  6. collapse        drop a non-blocking claim bound to a Screen finding (pure
                     corroboration the human already has); blocking + novel survive
  7. dedup           collapse {file, normalized_line, category}, keep highest severity
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from caliper.core.models import (
    SEVERITY_RANK,
    Claim,
    DroppedClaim,
    GaugeFinding,
    Part,
    Severity,
)
from caliper.core.repo_config import InspectConfig


class InspectError(ValueError):
    """Raised when the adjudicator's own output violates an invariant (a tool bug)."""


@dataclass(frozen=True)
class AdjudicationResult:
    """The adjudicator's output: surviving claims and the logged drops."""

    survivors: list[Claim] = field(default_factory=list)
    dropped: list[DroppedClaim] = field(default_factory=list)


def _as_dict(raw: object) -> dict:
    """Best-effort dict view of a raw claim for logging a drop."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, Claim):
        return raw.model_dump(mode="json")
    return {"_raw": repr(raw)}


def _overlap(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def _compatible(claim_category: str, finding_category: str, cfg: InspectConfig) -> bool:
    allowed = set(cfg.category_compat.get(claim_category, [])) | {claim_category}
    return finding_category in allowed


def bind_evidence(
    claims: list[Claim], screen: list[GaugeFinding], cfg: InspectConfig
) -> list[Claim]:
    """Post-hoc evidence binding: link a claim to a Screen finding by file, overlapping
    line range, and compatible category. Deterministic (findings scanned by id). The
    model is never asked to know rule ids — ``evidence_ref`` is set here.
    """
    by_id = sorted(screen, key=lambda f: f.id)
    out: list[Claim] = []
    for claim in claims:
        ref: str | None = claim.evidence_ref
        # Only auto-bind when the model did not already supply a real finding id.
        if ref is None or ref not in {f.id for f in screen}:
            ref = None
            for f in by_id:
                if f.file != claim.file:
                    continue
                if f.line_range is not None and not _overlap(claim.line_range, f.line_range):
                    continue
                if not _compatible(claim.category.value, f.category, cfg):
                    continue
                ref = f.id
                break
        out.append(claim.model_copy(update={"evidence_ref": ref}))
    return out


def adjudicate(
    raw_claims: list,
    part: Part,
    screen: list[GaugeFinding],
    cfg: InspectConfig,
    changed_lines: Mapping[str, set[int]],
    changed_text: Mapping[str, str] | None = None,
) -> AdjudicationResult:
    """Filter raw LLM claims down to the report's claims. Pure and deterministic.

    ``raw_claims`` are the model's emissions (dicts), validated by rule 0 here so
    malformed input is dropped, never salvaged. ``changed_lines`` is the hunk line
    map (file -> changed new-side line numbers) from the stock producer; ``changed_text``
    is the matching file -> joined added-line content used by the anchor rule to verify
    ``anchor_quote`` verbatim (optional for backward compatibility: when absent, the
    anchor rule falls back to the line-number check only).
    """
    changed_text = changed_text or {}
    dropped: list[DroppedClaim] = []

    # Rule 0 — parse. Validate each raw claim against the schema; drop unparsable.
    parsed: list[Claim] = []
    for raw in raw_claims:
        try:
            candidate = raw.model_dump() if isinstance(raw, Claim) else raw
            parsed.append(Claim.model_validate(candidate))
        except Exception as exc:  # noqa: BLE001 - any validation failure is a drop
            dropped.append(DroppedClaim(claim=_as_dict(raw), rule="parse", reason=str(exc)[:200]))

    # Evidence binding (deterministic) before the substantiation rule.
    parsed = bind_evidence(parsed, screen, cfg)

    bucket = part.bucket.value
    allowed = set(cfg.allowed_categories.get(bucket, []))
    floor_rank = SEVERITY_RANK[Severity(cfg.severity_floor.get(bucket, "nit"))]
    files = set(part.files)

    kept: list[Claim] = []
    for claim in parsed:
        # Rule 1 — scope.
        if claim.file not in files:
            dropped.append(DroppedClaim(claim=claim.model_dump(mode="json"), rule="scope"))
            continue
        # Rule 2 — anchor. When the model supplied a verbatim anchor_quote it must be a
        # literal substring of the part's changed text — the anti-hallucination keystone,
        # checked before line numbers are trusted. Then require the range to touch a
        # real changed line.
        if claim.anchor_quote and claim.anchor_quote.strip():
            haystack = changed_text.get(claim.file, "")
            if claim.anchor_quote.strip() not in haystack:
                dropped.append(
                    DroppedClaim(
                        claim=claim.model_dump(mode="json"),
                        rule="anchor",
                        reason="anchor_quote not a verbatim substring of changed text",
                    )
                )
                continue
        lines = changed_lines.get(claim.file, set())
        lo, hi = claim.line_range
        if not any(ln in lines for ln in range(lo, hi + 1)):
            dropped.append(DroppedClaim(claim=claim.model_dump(mode="json"), rule="anchor"))
            continue
        # Rule 3 — substantiation: downgrade unsubstantiated blocking to advisory.
        if claim.severity == Severity.blocking and not claim.evidence_ref:
            claim = claim.model_copy(update={"severity": Severity.major})
        # Rule 4 — category allow-list per bucket.
        if claim.category.value not in allowed:
            dropped.append(DroppedClaim(claim=claim.model_dump(mode="json"), rule="category"))
            continue
        # Rule 5 — floor.
        if SEVERITY_RANK[claim.severity] < floor_rank:
            dropped.append(DroppedClaim(claim=claim.model_dump(mode="json"), rule="floor"))
            continue
        # Rule 6 — collapse-into-Screen: a non-blocking claim bound to a Screen finding is
        # pure corroboration of a deterministic finding the human already has; drop it to
        # fight alert fatigue. Blocking (substantiated, gate-relevant) and unbound (novel)
        # claims survive.
        if claim.evidence_ref and claim.severity != Severity.blocking:
            dropped.append(DroppedClaim(claim=claim.model_dump(mode="json"), rule="collapse"))
            continue
        kept.append(claim)

    # Rule 7 — dedup on {file, normalized_line, category}; keep highest severity.
    best: dict[tuple[str, int, str], Claim] = {}
    for claim in kept:
        key = (claim.file, claim.line_range[0], claim.category.value)
        incumbent = best.get(key)
        if incumbent is None:
            best[key] = claim
        elif SEVERITY_RANK[claim.severity] > SEVERITY_RANK[incumbent.severity]:
            dropped.append(DroppedClaim(claim=incumbent.model_dump(mode="json"), rule="dedup"))
            best[key] = claim
        else:
            dropped.append(DroppedClaim(claim=claim.model_dump(mode="json"), rule="dedup"))

    survivors = sorted(
        best.values(), key=lambda c: (c.file, c.line_range, c.category.value, c.severity.value)
    )

    # Invariant: no surviving blocking claim lacks a deterministic witness.
    for c in survivors:
        if c.severity == Severity.blocking and not c.evidence_ref:
            raise InspectError("unsubstantiated blocking claim survived adjudication (tool bug)")

    return AdjudicationResult(survivors=survivors, dropped=dropped)
