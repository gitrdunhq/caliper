"""The parting decision — pure, deterministic cutting of a stock into a cut list.
# tested-by: tests/unit/test_parting.py

``part()`` is the whole decision and the consumer at the centre of the parting
producer/consumer flow: it consumes already-classified ``Record`` objects (the
stock, produced by ``core.part_stock`` from git) and emits an ordered ``CutList``.

It is **pure**: no IO, no clock, no randomness. The same stock yields a
byte-identical cut list regardless of input ordering. This is a deliberate
fail-closed island in caliper's otherwise fail-open design — a degraded input
must never silently change the cut, so callers hand ``part()`` a complete,
already-resolved stock and ``part()`` asserts its own output covers that stock
exactly before returning.

Ruleset, applied in this fixed order (the order is the product — do not reorder):
  R1  generated isolation        all ``generated`` -> one part; all ``binary`` -> one part;
                                 all ``documentation`` -> one cap-exempt part (oversized flagged)
  R2  move/logic separation      ``move`` never shares a part with ``logic``; moves to the bottom
  R4  size cap                   accrete within a bucket until the cap; oversized singles flagged

v0 has no dependency graph, so R3 (layer) and R5 (risk), and cycle-as-kerf, are
left as named seams for v1 (reusing the Blast Radius CodeGraph). Kerf rationale
is filled by the scribe pattern in v1; in v0 every ``Kerf.rationale`` is empty.
"""

from __future__ import annotations

import hashlib
import math

import orjson

from caliper.core.models import (
    Ambiguity,
    ChangeType,
    CutList,
    CutStats,
    Kerf,
    Part,
    Provenance,
    Record,
)
from caliper.core.repo_config import PartingConfig

# The canonical bucket order, bottom of stack first. Moves are the foundation
# (they land first); deletes land last; generated and binary are isolated. The
# architectural tiers land low (they tend to be the load-bearing change), then
# the non-code intent buckets, then the untiered ``logic`` residual, tests, and
# deletes. EVERY ``ChangeType`` must appear here exactly once — ``part()`` does
# ``by_bucket[eff]`` and a missing key is a KeyError, not a silent skip. v1's R3
# (layer) will reorder *within* a tier using the dependency graph.
_BUCKET_ORDER: tuple[ChangeType, ...] = (
    ChangeType.move,
    # Architectural tiers (code), foundation-first.
    ChangeType.infra,
    ChangeType.data,
    ChangeType.frontend,
    ChangeType.business,
    # Content intent (non-code).
    ChangeType.supply_chain,
    ChangeType.schema_contracts,
    ChangeType.ci_cd,
    ChangeType.security_policy,
    ChangeType.config,
    ChangeType.documentation,
    # Isolated structural/generated buckets.
    ChangeType.generated,
    ChangeType.binary,
    # Untiered residual, then tests, then deletes last.
    ChangeType.logic,
    ChangeType.test,
    ChangeType.delete,
)

# Buckets isolated into a single part by R1 and never subject to the size cap.
# They are always ``oversized=False`` — generated/binary noise carries no review
# cost the cap exists to bound, so flagging it would be dishonest.
_ISOLATED_BUCKETS: frozenset[ChangeType] = frozenset({ChangeType.generated, ChangeType.binary})

# Buckets grouped into a single part like the isolated ones, but cap-exempt
# rather than cap-ignorant: a reviewer reads docs top-to-bottom as one unit, so
# they are never size-split — yet when the group genuinely exceeds the cap it is
# flagged ``oversized=True`` (unlike _ISOLATED_BUCKETS), keeping the promise honest.
_GROUPED_BUCKETS: frozenset[ChangeType] = frozenset({ChangeType.documentation})


class PartingError(ValueError):
    """Raised when ``part()`` produces a partition that does not cover the stock.

    A completeness/disjointness violation is a tool bug, not a user error — it
    fails loudly rather than emitting a silently-wrong cut list.
    """


def config_digest(cfg: PartingConfig) -> str:
    """Deterministic digest of the effective parting config (for provenance)."""
    payload = orjson.dumps(cfg.model_dump(mode="json"), option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(payload).hexdigest()


def _part_id(bucket: ChangeType, files: list[str]) -> str:
    """Stable id derived from contents — same files+bucket always yield the same id."""
    payload = (str(bucket) + "\n" + "\n".join(files)).encode("utf-8")
    return "part-" + hashlib.sha256(payload).hexdigest()[:12]


def _effective_change_type(rec: Record, cfg: PartingConfig) -> ChangeType:
    """Apply the one confidence rule: an over-delta rename is not a confident move.

    A ``move`` whose content delta exceeds ``move_ambiguity_size`` cannot be
    classified confidently, so it is emitted as ``logic`` (and recorded in the
    cut list's ambiguities by the caller). Everything else keeps its class.
    """
    if rec.change_type == ChangeType.move and (rec.size or 0) > cfg.move_ambiguity_size:
        return ChangeType.logic
    return rec.change_type


def _percentile(sorted_vals: list[int], q: int) -> int:
    """Nearest-rank percentile over an ascending list (0 for empty)."""
    if not sorted_vals:
        return 0
    rank = max(1, min(len(sorted_vals), math.ceil(q / 100 * len(sorted_vals))))
    return sorted_vals[rank - 1]


def _build_part(bucket: ChangeType, recs: list[Record], rule: str, *, oversized: bool) -> Part:
    files = sorted(r.file for r in recs)
    size = sum((r.size or 0) for r in recs)
    return Part(
        id=_part_id(bucket, files),
        files=files,
        bucket=bucket,
        size=size,
        opened_by=Kerf(fired_rule=rule),
        oversized=oversized,
    )


def _part_bucket(bucket: ChangeType, recs: list[Record], cfg: PartingConfig) -> list[Part]:
    """Cut one bucket's records into parts per the ruleset.

    Isolated buckets (generated, binary) become a single R1 part, never flagged
    oversized. Grouped buckets (documentation) also become a single R1 part but
    are cap-exempt with an honest oversized flag when the group exceeds the cap.
    Every other bucket accretes by the size cap (R4): the first part fires R2 for
    moves and ``bucket-end`` otherwise; cap-induced and oversized continuations
    fire R4.
    """
    recs = sorted(recs, key=lambda r: r.file)
    if not recs:
        return []

    if bucket in _ISOLATED_BUCKETS:
        return [_build_part(bucket, recs, "R1", oversized=False)]

    if bucket in _GROUPED_BUCKETS:
        # Grouped into one part (never size-split), but cap-exempt with an honest
        # oversized flag when the group as a whole exceeds the cap.
        group_size = sum((r.size or 0) for r in recs)
        return [_build_part(bucket, recs, "R1", oversized=group_size > cfg.size_cap)]

    first_rule = "R2" if bucket == ChangeType.move else "bucket-end"
    cap = cfg.size_cap
    parts: list[Part] = []
    current: list[Record] = []
    current_size = 0

    def _rule_for_next() -> str:
        return first_rule if not parts else "R4"

    def _flush() -> None:
        nonlocal current, current_size
        if current:
            parts.append(_build_part(bucket, current, _rule_for_next(), oversized=False))
            current = []
            current_size = 0

    for rec in recs:
        rsize = rec.size or 0
        if rsize > cap:
            # A single record over the cap is its own part. The cap promise
            # cannot be kept for it and v0 has no within-file split to offer.
            _flush()
            parts.append(_build_part(bucket, [rec], _rule_for_next(), oversized=True))
            continue
        if current and current_size + rsize > cap:
            _flush()
        current.append(rec)
        current_size += rsize
    _flush()
    return parts


def part(
    records: list[Record],
    cfg: PartingConfig,
    provenance: Provenance | None = None,
) -> CutList:
    """Cut the stock (``records``) into an ordered cut list. Pure and deterministic.

    ``provenance`` is supplied by the producer/gate when the real git SHAs and
    resolved revset ids are known; when omitted a pure, config-derived provenance
    is stamped (empty SHAs) so ``part()`` stays callable with no repo and no git.
    """
    # R2/ambiguity: reclassify over-delta renames to logic and record them.
    ambiguities: list[Ambiguity] = []
    by_bucket: dict[ChangeType, list[Record]] = {bucket: [] for bucket in _BUCKET_ORDER}
    for rec in records:
        eff = _effective_change_type(rec, cfg)
        if eff != rec.change_type and rec.change_type == ChangeType.move:
            ambiguities.append(
                Ambiguity(
                    file=rec.file, reason="rename with content delta over cap; emitted as logic"
                )
            )
        by_bucket[eff].append(rec)

    parts: list[Part] = []
    for bucket in _BUCKET_ORDER:
        parts.extend(_part_bucket(bucket, by_bucket[bucket], cfg))

    if provenance is None:
        provenance = Provenance(
            caliper_version="",
            base_sha="",
            head_sha="",
            rename_threshold=cfg.rename_threshold,
            config_digest=config_digest(cfg),
        )

    cut = CutList(
        parts=parts,
        ambiguities=sorted(ambiguities, key=lambda a: a.file),
        size_cap=cfg.size_cap,
        provenance=provenance,
        stats=_stats(parts),
    )
    _assert_partition(records, cut)
    return cut


def _stats(parts: list[Part]) -> CutStats:
    sizes = sorted(p.size for p in parts)
    file_count = sum(len(p.files) for p in parts)
    move_files = {f for p in parts if p.bucket == ChangeType.move for f in p.files}
    logic_files = {f for p in parts if p.bucket == ChangeType.logic for f in p.files}
    return CutStats(
        part_count=len(parts),
        file_count=file_count,
        size_p50=_percentile(sizes, 50),
        size_p90=_percentile(sizes, 90),
        move_logic_pure=move_files.isdisjoint(logic_files),
    )


def _assert_partition(records: list[Record], cut: CutList) -> None:
    """Completeness + disjointness, asserted on ``part()``'s own output (fail loudly).

    The union of all parts' file sets must equal the stock's file set exactly and
    parts must be pairwise disjoint. A rename is counted once under its new path
    (the canonical key), so the comparison is well defined.
    """
    stock = {r.file for r in records}
    part_files = [f for p in cut.parts for f in p.files]
    seen = set(part_files)
    if len(part_files) != len(seen):
        raise PartingError("parting produced overlapping parts (disjointness violated)")
    if seen != stock:
        missing = stock - seen
        extra = seen - stock
        raise PartingError(
            f"parting did not cover the stock exactly (missing={sorted(missing)}, "
            f"extra={sorted(extra)})"
        )
