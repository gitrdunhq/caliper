"""Tests for the OpenAI-compatible tier-suggester backend (data tier).

# tested-by: tests/unit/test_openai_suggester.py

No network: an injected ``post`` returns canned ``/chat/completions`` bodies. Every
transport, status, or parse failure must fail-soft to ``[]`` so the residual stays
``logic`` and the cut is never broken (DPS-200/204).
"""

from __future__ import annotations

import json

from caliper.core.tier_suggester import ResidualFile, SuggestRequest
from caliper.data.openai_suggester import (
    OpenAICompatSuggester,
    SuggesterConfig,
    build_messages,
)

_CFG = SuggesterConfig(base_url="http://localhost:11434/v1", model="llama3.1")
_REQ = SuggestRequest(
    residual=[
        ResidualFile(path="svc/lib/lambda/handler.ts", size=40),
        ResidualFile(path="svc/cdk.json", size=12),
    ]
)


def _completion(content: str) -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


def _fake_post(content: str):
    def post(url: str, body: bytes, headers: dict, timeout: float) -> bytes:  # noqa: ARG001
        return _completion(content)

    return post


class TestBuildMessages:
    def test_lists_residual_paths_and_buckets(self) -> None:
        msgs = build_messages(_REQ)
        joined = "\n".join(m["content"] for m in msgs)
        assert "svc/lib/lambda/handler.ts" in joined
        assert "svc/cdk.json" in joined
        # The legal bucket enum is pinned into the prompt so the model can't invent one.
        assert "infra" in joined and "business" in joined


class TestSuggest:
    def test_parses_json_array(self) -> None:
        content = json.dumps(
            [
                {"glob": "**/lib/lambda/**", "bucket": "business"},
                {"glob": "**/cdk.json", "bucket": "config"},
            ]
        )
        s = OpenAICompatSuggester(_CFG, post=_fake_post(content))
        out = s.suggest(_REQ)
        assert [(r.glob, r.bucket) for r in out] == [
            ("**/lib/lambda/**", "business"),
            ("**/cdk.json", "config"),
        ]

    def test_tolerates_code_fences(self) -> None:
        content = '```json\n[{"glob": "**/lib/lambda/**", "bucket": "business"}]\n```'
        s = OpenAICompatSuggester(_CFG, post=_fake_post(content))
        out = s.suggest(_REQ)
        assert len(out) == 1
        assert out[0].glob == "**/lib/lambda/**"

    def test_malformed_json_fails_soft(self) -> None:
        s = OpenAICompatSuggester(_CFG, post=_fake_post("not json at all"))
        assert s.suggest(_REQ) == []

    def test_non_array_payload_fails_soft(self) -> None:
        s = OpenAICompatSuggester(_CFG, post=_fake_post('{"glob": "x", "bucket": "business"}'))
        assert s.suggest(_REQ) == []

    def test_skips_malformed_entries(self) -> None:
        # A list with one good and one junk entry yields only the good one.
        content = json.dumps(
            [{"glob": "**/lib/lambda/**", "bucket": "business"}, {"nope": 1}, "string"]
        )
        s = OpenAICompatSuggester(_CFG, post=_fake_post(content))
        out = s.suggest(_REQ)
        assert len(out) == 1
        assert out[0].bucket == "business"

    def test_transport_error_fails_soft(self) -> None:
        def boom(url: str, body: bytes, headers: dict, timeout: float) -> bytes:  # noqa: ARG001
            raise OSError("connection refused")

        s = OpenAICompatSuggester(_CFG, post=boom)
        assert s.suggest(_REQ) == []
