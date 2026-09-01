"""LLMTransportPort — the sealed seam for optional, advisory LLM calls.

# tested-by: tests/unit/plugins/test_supply_chain_threat_scribe.py

This module defines only the *interface* (no model call). The concrete adapter is
``caliper.data.llm_client.LlmClient`` (DPS-101: core stays free of the httpx
transport; callers construct the adapter and inject it through this port). The
only consumer today is the opt-in supply-chain-threat scribe.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMTransportPort(Protocol):
    """Structural contract for the shared chat-completions transport."""

    @property
    def enabled(self) -> bool: ...

    def complete(self, messages: list[dict], *, max_tokens: int = 200) -> str: ...

    def close(self) -> None: ...
