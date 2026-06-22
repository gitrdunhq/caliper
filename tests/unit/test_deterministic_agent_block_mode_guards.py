"""Deterministic guards for agent block mode — Issue #239 / Parent #205.

Bug: ForemanAgent block mode only fails if _decisions_have_reject is inferred
from response.value["decisions"]. If the LLM returns prose, skips a tool, or
returns a non-dict response, block mode exits successfully without a
deterministic decision payload — a security gate that can be bypassed by
LLM presentation behaviour.

These are xfail until block mode is driven by a typed pipeline decision that
exists independently of the LLM response shape. See issues #205 and #239.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #205 — "
        "ForemanAgent block mode is gated by _decisions_have_reject, "
        "a flag scraped from the LLM response; fix by persisting and reading "
        "a typed pipeline decision, then these go green"
    ),
    strict=False,
)


class TestAgentBlockModeIsNotLLMDependent:
    """ForemanAgent block mode must not be gated by LLM response shape."""

    def test_foreman_agent_does_not_use_decisions_have_reject_flag(self) -> None:
        """ForemanAgent must not use _decisions_have_reject as the block gate.

        The flag is populated by scraping response.value['decisions'] from the
        Copilot session. A malformed, prose-only, or tool-skipping LLM response
        leaves the flag False — making block mode a no-op for any run where
        the LLM response doesn't match the expected schema.

        Fix: run the deterministic pipeline first, persist the typed result,
        then enforce block/warn/log solely from that result. The LLM session
        outcome must not be able to bypass a deterministic reject verdict.
        """
        from caliper.agent.main import ForemanAgent

        source = inspect.getsource(ForemanAgent)
        assert "_decisions_have_reject" not in source, (
            "ForemanAgent still uses _decisions_have_reject flag. "
            "This flag is set by scraping the LLM response (response.value['decisions']). "
            "A non-conforming LLM response silently disables block mode. "
            "Fix: determine block/approve from a typed pipeline decision that "
            "exists before the LLM session starts. See issue #205."
        )

    def test_foreman_agent_does_not_scrape_decisions_from_response_value(self) -> None:
        """ForemanAgent must not read decisions from response.value.

        Scraping response.value['decisions'] couples a security enforcement
        gate to the presentation layer of the LLM output — fundamentally
        non-deterministic and bypassable.
        """
        from caliper.agent.main import ForemanAgent

        source = inspect.getsource(ForemanAgent)
        # The bug: _extract_reject_from_tool_results reads response.value
        assert "response.value" not in source or "_decisions_have_reject" not in source, (
            "ForemanAgent scrapes response.value to set _decisions_have_reject. "
            "Block enforcement must come from a typed, pre-computed pipeline decision. "
            "See issue #205."
        )
