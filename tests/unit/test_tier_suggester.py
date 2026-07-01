"""Tests for the tier suggester core — port, request, and validation boundary.

# tested-by: tests/unit/test_tier_suggester.py

The suggester proposes ``OverrideRule`` globs for the untiered ``logic`` residual.
It is advisory and off the decision path, but its *output* enters ``.caliper.yaml``
(and thus ``config_digest``), so the boundary must be airtight: a suggested glob may
only ever tier files that are currently ``logic`` — never re-tier an already-classified
file (overrides sit above the glob heuristics in ``_classify``).

Property domains (DPS-12):
  Isolation     SAFETY      a suggestion never matches an already-tiered path
  Idempotency   INVARIANT   applying the same raw suggestions twice == once
"""

from __future__ import annotations

from caliper.core.models import ChangeType
from caliper.core.repo_config import OverrideRule
from caliper.core.tier_suggester import (
    SELECTABLE_TIERS,
    NullSuggester,
    ResidualFile,
    SuggestedRule,
    SuggestRequest,
    validate_suggestions,
)

# A small residual + a set of already-tiered paths to guard against.
_RESIDUAL = [
    "svc/lib/lambda/handler.ts",
    "svc/lib/lambda/service/sns.ts",
    "svc/cdk.json",
]
_TIERED = [
    "svc/lib/infra-utils/builder.ts",  # already infra
    "svc/package.json",  # already supply_chain
]


def _vs(raw: list[SuggestedRule], *, existing: set[str] | None = None) -> list[OverrideRule]:
    return validate_suggestions(
        raw, residual=_RESIDUAL, tiered=_TIERED, existing_globs=existing or set()
    )


class TestSelectableTiers:
    def test_excludes_structural_and_logic(self) -> None:
        for bad in ("move", "delete", "binary", "logic"):
            assert bad not in SELECTABLE_TIERS

    def test_includes_real_tiers(self) -> None:
        for good in ("infra", "business", "config", "documentation", "security_policy"):
            assert good in SELECTABLE_TIERS


class TestValidateSuggestions:
    def test_accepts_legal_residual_only_glob(self) -> None:
        out = _vs([SuggestedRule(glob="**/lib/lambda/**", bucket="business")])
        assert len(out) == 1
        rule = out[0]
        assert isinstance(rule, OverrideRule)
        assert rule.glob == "**/lib/lambda/**"
        assert rule.bucket == ChangeType.business

    def test_rejects_structural_bucket(self) -> None:
        for bad in ("delete", "move", "binary"):
            assert _vs([SuggestedRule(glob="**/lib/lambda/**", bucket=bad)]) == []

    def test_rejects_logic_bucket(self) -> None:
        assert _vs([SuggestedRule(glob="**/lib/lambda/**", bucket="logic")]) == []

    def test_rejects_unknown_bucket(self) -> None:
        assert _vs([SuggestedRule(glob="**/lib/lambda/**", bucket="wizard")]) == []

    def test_rejects_empty_glob(self) -> None:
        assert _vs([SuggestedRule(glob="   ", bucket="business")]) == []

    def test_rejects_glob_matching_nothing_in_residual(self) -> None:
        # Matches no residual path -> useless, dropped.
        assert _vs([SuggestedRule(glob="**/does-not-exist/**", bucket="business")]) == []

    def test_rejects_glob_that_steals_a_tiered_file(self) -> None:
        # `**/*.ts` matches residual *.ts AND the already-tiered infra builder.ts:
        # accepting it would yank an infra file into business. The subset guard
        # (Isolation SAFETY) must drop it.
        out = _vs([SuggestedRule(glob="**/*.ts", bucket="business")])
        assert out == []

    def test_dedupes_repeated_glob(self) -> None:
        raw = [
            SuggestedRule(glob="**/lib/lambda/**", bucket="business"),
            SuggestedRule(glob="**/lib/lambda/**", bucket="business"),
        ]
        assert len(_vs(raw)) == 1

    def test_drops_glob_already_in_config(self) -> None:
        out = _vs(
            [SuggestedRule(glob="**/lib/lambda/**", bucket="business")],
            existing={"**/lib/lambda/**"},
        )
        assert out == []

    def test_caps_runaway_output(self) -> None:
        # One distinct, valid glob per residual file, plus padding — capped.
        raw = [SuggestedRule(glob=p, bucket="business") for p in _RESIDUAL] * 50
        out = _vs(raw)
        from caliper.core.tier_suggester import _MAX_SUGGESTIONS

        assert len(out) <= _MAX_SUGGESTIONS


class TestNullSuggester:
    def test_returns_empty(self) -> None:
        req = SuggestRequest(
            residual=[ResidualFile(path="a.ts", size=10)], buckets=SELECTABLE_TIERS
        )
        assert NullSuggester().suggest(req) == []


class TestProperties:
    def test_isolation_no_suggestion_touches_tiered_file(self) -> None:
        # SAFETY: whatever survives validation, none of its globs may match a tiered path.
        from caliper.core.part_stock import _match_globs

        raw = [
            SuggestedRule(glob="**/lib/lambda/**", bucket="business"),
            SuggestedRule(glob="**/*.ts", bucket="business"),  # unsafe, must be dropped
            SuggestedRule(glob="**/cdk.json", bucket="config"),
        ]
        out = _vs(raw)
        for rule in out:
            for tiered_path in _TIERED:
                assert not _match_globs(tiered_path, [rule.glob])

    def test_idempotency_apply_twice_equals_once(self) -> None:
        raw = [SuggestedRule(glob="**/lib/lambda/**", bucket="business")]
        once = _vs(raw)
        twice = _vs(raw + raw)
        assert [r.glob for r in once] == [r.glob for r in twice]
