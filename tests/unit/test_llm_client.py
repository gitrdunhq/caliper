"""Tests for eedom.core.llm_client -- shared OpenAI-compatible LLM transport.

DPS-12 domains:
  Availability (LIVENESS): a valid, enabled, well-formed call eventually returns text.
  Confidentiality (SAFETY): the API key is sent as a Bearer header, never logged here.
  Integrity / fail-open (SAFETY): every failure path (disabled, misconfig, timeout,
    HTTP error, malformed payload) returns "" and never raises — the LLM can never
    break or block its caller (it is purely advisory, ADR-006).
"""

from __future__ import annotations

import os
from unittest.mock import Mock, patch

import httpx
import pytest
import respx

from eedom.core.config import EedomSettings
from eedom.core.llm_client import LlmClient

_ENDPOINT = "https://llm.example.com/v1"
_URL = f"{_ENDPOINT}/chat/completions"
_MESSAGES = [{"role": "user", "content": "hi"}]


def _make_config(
    *,
    llm_enabled: bool = True,
    llm_endpoint: str | None = _ENDPOINT,
    llm_model: str | None = "gpt-4o",
    llm_api_key: str | None = None,
    llm_timeout: int = 30,
) -> EedomSettings:
    env = {
        "EEDOM_DB_DSN": "postgresql://test:test@localhost/test",
        "EEDOM_LLM_ENABLED": str(llm_enabled).lower(),
        "EEDOM_LLM_TIMEOUT": str(llm_timeout),
    }
    if llm_endpoint:
        env["EEDOM_LLM_ENDPOINT"] = llm_endpoint
    if llm_model:
        env["EEDOM_LLM_MODEL"] = llm_model
    if llm_api_key:
        env["EEDOM_LLM_API_KEY"] = llm_api_key
    with patch.dict(os.environ, env, clear=True):
        return EedomSettings()


def _ok(text: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


class TestEnabled:
    def test_enabled_requires_flag_endpoint_and_model(self) -> None:
        assert LlmClient(_make_config()).enabled is True
        assert LlmClient(_make_config(llm_enabled=False)).enabled is False
        assert LlmClient(_make_config(llm_endpoint=None)).enabled is False
        assert LlmClient(_make_config(llm_model=None)).enabled is False


class TestComplete:
    @respx.mock
    def test_returns_content_on_success(self) -> None:  # Availability
        respx.post(_URL).mock(return_value=_ok("the story"))
        assert LlmClient(_make_config()).complete(_MESSAGES) == "the story"

    @respx.mock
    def test_sends_bearer_token(self) -> None:  # Confidentiality (transport)
        route = respx.post(_URL).mock(return_value=_ok("ok"))
        LlmClient(_make_config(llm_api_key="sk-secret")).complete(_MESSAGES)
        assert route.calls.last.request.headers["Authorization"] == "Bearer sk-secret"

    @respx.mock
    def test_passes_max_tokens(self) -> None:
        route = respx.post(_URL).mock(return_value=_ok("ok"))
        LlmClient(_make_config()).complete(_MESSAGES, max_tokens=1234)
        import json as _json

        assert _json.loads(route.calls.last.request.content)["max_tokens"] == 1234


class TestFailOpen:
    """Every failure path returns '' and never raises (Integrity / fail-open)."""

    def test_disabled_returns_empty_without_calling(self) -> None:
        assert LlmClient(_make_config(llm_enabled=False)).complete(_MESSAGES) == ""

    @respx.mock
    def test_timeout_returns_empty(self) -> None:
        respx.post(_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        assert LlmClient(_make_config()).complete(_MESSAGES) == ""

    @respx.mock
    def test_non_200_returns_empty(self) -> None:
        respx.post(_URL).mock(return_value=httpx.Response(500, text="boom"))
        assert LlmClient(_make_config()).complete(_MESSAGES) == ""

    @respx.mock
    def test_empty_choices_returns_empty(self) -> None:
        respx.post(_URL).mock(return_value=httpx.Response(200, json={"choices": []}))
        assert LlmClient(_make_config()).complete(_MESSAGES) == ""

    def test_non_string_content_returns_empty(self) -> None:
        client = LlmClient(_make_config())
        resp = Mock(status_code=200)
        resp.json.return_value = {"choices": [{"message": {"content": 123}}]}
        with patch.object(client._client, "post", return_value=resp):
            out = client.complete(_MESSAGES)
        assert out == ""

    def test_json_decode_error_returns_empty(self) -> None:
        client = LlmClient(_make_config())
        resp = Mock(status_code=200)
        resp.json.side_effect = ValueError("bad json")
        with patch.object(client._client, "post", return_value=resp):
            out = client.complete(_MESSAGES)
        assert out == ""


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
