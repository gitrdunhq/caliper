"""Advisory tier suggester — port, request, and the deterministic boundary.

# tested-by: tests/unit/test_tier_suggester.py

The Sorting Hat seam. A small local model proposes ``OverrideRule`` globs for the
untiered ``logic`` residual so a reviewer stops hand-writing them. It is advisory and
off the decision path (``part()`` / ``_classify`` / ``config_digest`` never call a
model), and fail-soft: no backend, or any backend error, yields ``[]`` and the
residual simply stays ``logic``.

But the suggester's *output* is different from the describer's: accepted globs enter
``.caliper.yaml`` and therefore ``config_digest``. So ``validate_suggestions`` is a
hard boundary (DPS-102), and its load-bearing invariant is **Isolation/SAFETY**: a
surviving glob may only ever tier files that are currently ``logic``. Overrides sit
*above* the glob heuristics in ``_classify``, so a glob like ``**/*.ts`` would yank an
already-``infra`` file into ``business`` — the subset guard rejects exactly that.

Concrete network backends live in the data tier (``caliper.data.openai_suggester``);
this module stays pure and importable without them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from caliper.core.models import ChangeType
from caliper.core.part_stock import _match_globs
from caliper.core.repo_config import _STRUCTURAL_BUCKETS, OverrideRule

# The legal targets a suggestion may assign: every tier EXCEPT the structural facts
# (decided by git) and the ``logic`` residual (the thing we are draining, never a
# target). Order mirrors the dropdown: content intent, then architectural code tiers.
SELECTABLE_TIERS: tuple[str, ...] = tuple(
    ct.value for ct in ChangeType if ct not in _STRUCTURAL_BUCKETS and ct is not ChangeType.logic
)

# A runaway model cannot flood the committed override table.
_MAX_SUGGESTIONS = 25


@dataclass(frozen=True)
class ResidualFile:
    """One untiered (``logic``) file handed to the model as context. Read-only hint."""

    path: str
    size: int


@dataclass(frozen=True)
class SuggestRequest:
    """The advisory context for a suggestion run: the residual + the legal buckets.

    Sourced at the edge from a cut's ``logic`` part. The model never sees already-tiered
    files — it only proposes globs for the residual, and the boundary enforces that.
    """

    residual: list[ResidualFile]
    buckets: tuple[str, ...] = SELECTABLE_TIERS


@dataclass(frozen=True)
class SuggestedRule:
    """A raw, pre-validation model proposal: ``glob`` -> ``bucket`` with an optional note."""

    glob: str
    bucket: str
    note: str = ""


@runtime_checkable
class TierSuggesterPort(Protocol):
    """Structural contract for a tier-suggestion backend. Advisory; never raises."""

    def suggest(self, request: SuggestRequest) -> list[SuggestedRule]:
        """Return raw glob proposals (validated by ``validate_suggestions``), or ``[]``."""
        ...


class NullSuggester:
    """The fail-soft default: no backend configured, so no suggestions are produced."""

    def suggest(self, request: SuggestRequest) -> list[SuggestedRule]:  # noqa: ARG002
        return []


def validate_suggestions(
    raw: list[SuggestedRule],
    *,
    residual: list[str],
    tiered: list[str],
    existing_globs: set[str],
) -> list[OverrideRule]:
    """Turn raw model proposals into safe ``OverrideRule`` entries (pure, deterministic).

    A proposal survives only if every check passes:

    1. ``bucket`` is a legal selectable tier (never structural, never ``logic``);
    2. ``glob`` is non-empty;
    3. it matches at least one ``residual`` path (otherwise it is dead weight);
    4. **subset guard (Isolation/SAFETY):** it matches no already-``tiered`` path, so
       accepting it can never re-tier a file that is already classified;
    5. it is not a duplicate of an earlier surviving glob or an ``existing_globs`` entry.

    Survivors are capped at ``_MAX_SUGGESTIONS`` so a runaway backend cannot flood the
    committed ``.caliper.yaml``. Order is preserved (first occurrence wins), so the
    result is a function of the input alone — same raw in, same overrides out.
    """
    legal = set(SELECTABLE_TIERS)
    seen: set[str] = set(existing_globs)
    out: list[OverrideRule] = []
    for rule in raw:
        glob = rule.glob.strip()
        if rule.bucket not in legal or not glob or glob in seen:
            continue
        if not any(_match_globs(p, [glob]) for p in residual):
            continue  # matches nothing in the residual — useless
        if any(_match_globs(p, [glob]) for p in tiered):
            continue  # would steal an already-tiered file — unsafe
        try:
            out.append(OverrideRule(glob=glob, bucket=ChangeType(rule.bucket), note=rule.note))
        except (ValueError, TypeError):
            continue  # defense in depth: OverrideRule validators reject anything we missed
        seen.add(glob)
        if len(out) >= _MAX_SUGGESTIONS:
            break
    return out
