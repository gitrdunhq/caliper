"""Tests for the tier-suggester composition edge — ``cli.part_suggest``.

# tested-by: tests/unit/test_part_suggest.py

The edge resolves a backend from env (mirroring the describer) and runs it over a
cut's ``logic`` residual, validating every proposal through the core boundary. It is
fail-soft: no backend, or any backend failure, yields ``[]`` and the residual stays
``logic``.
"""

from __future__ import annotations

from caliper.cli.part_suggest import suggest_overrides, suggester_from_env
from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance
from caliper.core.repo_config import OverrideRule
from caliper.core.tier_suggester import (
    NullSuggester,
    SuggestedRule,
    SuggestRequest,
    TierSuggesterPort,
)
from caliper.data.openai_suggester import OpenAICompatSuggester


def _part(bucket: ChangeType, files: list[str]) -> Part:
    return Part(
        id=f"{bucket}-{len(files)}",
        files=sorted(files),
        bucket=bucket,
        size=len(files) * 10,
        opened_by=Kerf(fired_rule="bucket-end"),
    )


def _cutlist(parts: list[Part]) -> CutList:
    return CutList(
        parts=parts,
        size_cap=None,
        provenance=Provenance(
            caliper_version="0", base_sha="b", head_sha="h", rename_threshold=50, config_digest="d"
        ),
        stats=CutStats(
            part_count=len(parts),
            file_count=sum(len(p.files) for p in parts),
            size_p50=0,
            size_p90=0,
            move_logic_pure=True,
        ),
    )


def _cut() -> CutList:
    return _cutlist(
        [
            _part(ChangeType.infra, ["svc/lib/infra-utils/builder.ts"]),
            _part(
                ChangeType.logic,
                ["svc/lib/lambda/handler.ts", "svc/lib/lambda/sns.ts", "svc/cdk.json"],
            ),
        ]
    )


class _StubSuggester:
    """Returns canned proposals; records the request it received."""

    def __init__(self, rules: list[SuggestedRule]) -> None:
        self.rules = rules
        self.seen: SuggestRequest | None = None

    def suggest(self, request: SuggestRequest) -> list[SuggestedRule]:
        self.seen = request
        return self.rules


class TestSuggesterFromEnv:
    def test_no_model_returns_null(self) -> None:
        assert isinstance(suggester_from_env({}), NullSuggester)

    def test_force_false_returns_null(self) -> None:
        env = {"CALIPER_SUGGESTER_MODEL": "llama3.1", "OLLAMA_HOST": "http://h:11434"}
        assert isinstance(suggester_from_env(env, force=False), NullSuggester)

    def test_disabled_env_returns_null(self) -> None:
        env = {
            "CALIPER_SUGGESTER": "off",
            "CALIPER_SUGGESTER_MODEL": "llama3.1",
            "OLLAMA_HOST": "http://h:11434",
        }
        assert isinstance(suggester_from_env(env), NullSuggester)

    def test_model_and_ollama_host_builds_backend(self) -> None:
        env = {"CALIPER_SUGGESTER_MODEL": "llama3.1", "OLLAMA_HOST": "http://h:11434"}
        s = suggester_from_env(env)
        assert isinstance(s, OpenAICompatSuggester)

    def test_falls_back_to_describer_model(self) -> None:
        # One local config drives both describe and suggest.
        env = {"CALIPER_DESCRIBER_MODEL": "llama3.1", "OLLAMA_HOST": "http://h:11434"}
        s = suggester_from_env(env)
        assert isinstance(s, OpenAICompatSuggester)


class TestSuggestOverrides:
    def test_validates_proposals_against_residual(self) -> None:
        stub = _StubSuggester(
            [
                SuggestedRule(glob="**/lib/lambda/**", bucket="business"),
                SuggestedRule(glob="**/cdk.json", bucket="config"),
            ]
        )
        out = suggest_overrides(_cut(), stub, existing_overrides=[])
        assert {(r.glob, r.bucket) for r in out} == {
            ("**/lib/lambda/**", ChangeType.business),
            ("**/cdk.json", ChangeType.config),
        }

    def test_residual_only_passed_to_model(self) -> None:
        stub = _StubSuggester([])
        suggest_overrides(_cut(), stub, existing_overrides=[])
        assert stub.seen is not None
        paths = {f.path for f in stub.seen.residual}
        # Only the logic part's files; the already-infra file is never shown.
        assert "svc/lib/infra-utils/builder.ts" not in paths
        assert "svc/lib/lambda/handler.ts" in paths

    def test_subset_guard_drops_thieving_glob(self) -> None:
        # `**/*.ts` would also match the already-infra builder.ts -> dropped end-to-end.
        stub = _StubSuggester([SuggestedRule(glob="**/*.ts", bucket="business")])
        assert suggest_overrides(_cut(), stub, existing_overrides=[]) == []

    def test_drops_existing_globs(self) -> None:
        stub = _StubSuggester([SuggestedRule(glob="**/lib/lambda/**", bucket="business")])
        existing = [OverrideRule(glob="**/lib/lambda/**", bucket=ChangeType.business)]
        assert suggest_overrides(_cut(), stub, existing_overrides=existing) == []

    def test_null_suggester_returns_empty(self) -> None:
        assert suggest_overrides(_cut(), NullSuggester(), existing_overrides=[]) == []

    def test_no_residual_returns_empty(self) -> None:
        cut = _cutlist([_part(ChangeType.infra, ["a.ts"])])
        stub = _StubSuggester([SuggestedRule(glob="**/*", bucket="business")])
        assert suggest_overrides(cut, stub, existing_overrides=[]) == []

    def test_port_protocol_satisfied(self) -> None:
        assert isinstance(NullSuggester(), TierSuggesterPort)
