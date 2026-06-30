"""Tests for the OpenAI-compatible commit-subject backend — ``data.openai_describer``.

# tested-by: tests/unit/test_openai_describer.py

The adapter rides any OpenAI-compatible ``/chat/completions`` endpoint (OMLX, Ollama,
llama.cpp, hosted). It is advisory and fail-soft: every transport or parse failure
returns ``None`` so the caller keeps the deterministic subject. No test touches the
network — the HTTP post is injected.
"""

from __future__ import annotations

import json

from caliper.core.commit_describer import DescribeRequest
from caliper.data.openai_describer import (
    DescriberConfig,
    OpenAICompatDescriber,
    build_messages,
)

_REQ = DescribeRequest(
    prefix="feat(infra): ",
    bucket="infra",
    files=["bin/app.ts", "lib/stackset-definition/incident-stackset.ts"],
    context="AWS CDK StackSets and a canary workflow.",
)


def _completion(text: str) -> bytes:
    return json.dumps({"choices": [{"message": {"content": text}}]}).encode()


class TestBuildMessages:
    """Prompt construction is pure and asks for ONLY the prose tail."""

    def test_system_asks_for_a_summary_phrase_not_a_full_subject(self) -> None:
        sys_msg = build_messages(_REQ)[0]
        assert sys_msg["role"] == "system"
        content = sys_msg["content"].lower()
        # the model is told to emit ONLY the phrase, with no type/scope prefix
        assert "only" in content
        assert "prefix" in content

    def test_user_message_carries_files_and_context(self) -> None:
        user = build_messages(_REQ)[1]["content"]
        assert "bin/app.ts" in user
        assert "incident-stackset.ts" in user
        assert "canary workflow" in user


class TestDescribe:
    """describe() — happy path and the fail-soft contract."""

    def _describer(self, post) -> OpenAICompatDescriber:
        cfg = DescriberConfig(base_url="http://localhost:12999/v1", model="gemma4:e4b")
        return OpenAICompatDescriber(cfg, post=post)

    def test_returns_normalized_subject_on_success(self) -> None:
        captured: dict = {}

        def post(url, data, headers, timeout):
            captured["url"] = url
            captured["body"] = json.loads(data)
            captured["headers"] = headers
            return _completion("Add canary automation stacksets.")

        out = self._describer(post).describe(_REQ)
        assert out == "feat(infra): add canary automation stacksets"
        # hits the chat endpoint with a deterministic (temp 0) request
        assert captured["url"].endswith("/chat/completions")
        assert captured["body"]["temperature"] == 0
        assert captured["body"]["model"] == "gemma4:e4b"

    def test_api_key_sets_bearer_header(self) -> None:
        captured: dict = {}

        def post(url, data, headers, timeout):
            captured["headers"] = headers
            return _completion("add x")

        cfg = DescriberConfig(base_url="http://h/v1", model="m", api_key="secret")
        OpenAICompatDescriber(cfg, post=post).describe(_REQ)
        assert captured["headers"].get("Authorization") == "Bearer secret"

    def test_transport_failure_returns_none(self) -> None:
        def boom(url, data, headers, timeout):
            raise TimeoutError("no server")

        assert self._describer(boom).describe(_REQ) is None

    def test_garbage_response_returns_none(self) -> None:
        assert self._describer(lambda *a: b"not json").describe(_REQ) is None

    def test_empty_completion_returns_none(self) -> None:
        # model returned only whitespace -> normalizer empties it -> fall back
        assert self._describer(lambda *a: _completion("   ")).describe(_REQ) is None

    def test_no_bearer_header_when_api_key_blank(self) -> None:
        captured: dict = {}

        def post(url, data, headers, timeout):
            captured["headers"] = headers
            return _completion("add x")

        self._describer(post).describe(_REQ)
        assert "Authorization" not in captured["headers"]
