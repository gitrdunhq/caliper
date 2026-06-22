"""Shared OpenAI-compatible LLM transport.
# tested-by: tests/unit/test_llm_client.py

A single, reusable HTTP client for the optional LLM features in eedom (task-fit
advisory, supply-chain version-bump narrative). It owns *only* transport: build
the request, POST to ``{endpoint}/chat/completions``, unwrap the response. Every
failure path (disabled, missing config, timeout, HTTP error, parse error) returns
an empty string — it never raises and never blocks the caller.

This is the single source of truth for the chat-completions call so the LLM
features do not each re-implement the same httpx/SecretStr/fail-open dance.
Critically, nothing here participates in the decision path: callers attach the
returned text as advisory metadata only (ADR-006).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from eedom.core.config import EedomSettings

logger = structlog.get_logger(__name__)

_DEFAULT_MAX_TOKENS = 200


class LlmClient:
    """Calls an OpenAI-compatible chat-completions endpoint. Never raises.

    Construct from :class:`EedomSettings` (reuses the ``llm_*`` settings). The
    ``enabled`` property reflects ``llm_enabled``; ``complete`` returns ``""`` when
    disabled, misconfigured, or on any transport/parse failure.
    """

    def __init__(self, config: EedomSettings) -> None:
        self._enabled = config.llm_enabled
        self._endpoint = config.llm_endpoint
        self._model = config.llm_model
        self._api_key = config.llm_api_key
        self._timeout = config.llm_timeout
        self._client = httpx.Client(timeout=config.llm_timeout)

    @property
    def enabled(self) -> bool:
        """True when the LLM is enabled *and* the minimum config is present."""
        return bool(self._enabled and self._endpoint and self._model)

    def complete(self, messages: list[dict], *, max_tokens: int = _DEFAULT_MAX_TOKENS) -> str:
        """Return the assistant message content, or ``""`` on any failure.

        Args:
            messages: OpenAI-style ``[{"role": ..., "content": ...}]`` list.
            max_tokens: Upper bound on the completion length.
        """
        if not self.enabled:
            return ""

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            # F-021: unwrap SecretStr before use so the key is never logged.
            secret = (
                self._api_key.get_secret_value()
                if hasattr(self._api_key, "get_secret_value")
                else self._api_key
            )
            headers["Authorization"] = f"Bearer {secret}"

        payload = {"model": self._model, "messages": messages, "max_tokens": max_tokens}

        try:
            response = self._client.post(
                f"{self._endpoint}/chat/completions",
                json=payload,
                headers=headers,
            )
        except httpx.TimeoutException:
            logger.warning("llm.timeout", timeout=self._timeout)
            return ""
        except httpx.HTTPError as exc:
            logger.warning("llm.http_error", error=str(exc))
            return ""

        if response.status_code != 200:
            logger.warning("llm.api_error", status=response.status_code)
            return ""

        try:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            logger.warning("llm.parse_error", error=str(exc))
            return ""

        if not isinstance(text, str):
            logger.warning("llm.parse_error", error="'content' field is not a string")
            return ""

        return text

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
