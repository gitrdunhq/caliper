# Solution: Reject Detection Bypass in Agent Block Mode

## Problem

The Foreman agent's block mode (`enforcement_mode=block`) determines whether to
fail the CI build by parsing the LLM's free-text prose output for reject markers
(`["REJECTED", "reject", "🔴"]`). This is the wrong signal — the LLM's text can
be influenced by prompt injection, and benign phrases like "not rejected" or
"previously REJECTED" produce false positives.

Combined with the diff being embedded inline in the user message, an attacker who
controls a file in the PR can inject instructions that cause the LLM to avoid the
marker strings, making block mode silently pass despite an OPA reject verdict.

## Root Cause

The enforcement gate read LLM prose (human-facing output) instead of structured
tool results (machine-facing data). The OPA verdict — the deterministic gate —
was available in the `evaluate_change` tool's return payload but was never
extracted.

## Fix

1. Added `_extract_reject_from_tool_results()` to `main.py` which reads the
   structured `decision` field from `evaluate_change` responses. If any decision
   is `"reject"` or `"needs_review"`, `_decisions_have_reject` is set to `True`.

2. The exit code is now driven by `self._decisions_have_reject` (structured data),
   not by substring matching on `agent_response` (LLM text).

3. The diff is wrapped in `<diff>` XML tags instead of backtick fences, with the
   system prompt instructing the agent that content inside diff tags is untrusted
   data.

## Key Principle

LLM prose is for humans. Structured tool results are for control flow. Never use
LLM text output to drive security-critical branching decisions.

## Files Changed

- `src/caliper/agent/main.py` — `_extract_reject_from_tool_results()`,
  `_REJECT_MARKERS` removed, `<diff>` tag wrapping
