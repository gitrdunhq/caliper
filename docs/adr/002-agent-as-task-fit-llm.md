# ADR-002: Agent IS the Task-Fit LLM

## Status

Superseded (2026-09-01) — the Foreman Copilot agent this ADR designed was removed. See docs/decommission-log.md entry 15 ("Foreman Copilot agent") for the removal record.

## Context

The existing pipeline has an optional `TaskFitAdvisor` that makes a separate HTTP call to an OpenAI-compatible endpoint to assess package proportionality against 8 dimensions. The advisor is disabled by default and its output is purely informational.

For the Copilot Agent, we need the same 8-dimension reasoning. Two approaches:
1. Keep `TaskFitAdvisor` as a separate call — agent invokes it as part of the pipeline
2. Embed the 8-dimension rubric in the agent's system prompt — the agent reasons natively

## Decision

We will embed the 8-dimension rubric in the agent's system prompt. The agent IS the task-fit LLM. No separate HTTP call is made for task-fit assessment. The agent receives tool results (findings, OPA verdict, scanner data) and produces its own assessment inline.

## Consequences

- One LLM call instead of two per package — lower latency, simpler error handling
- The system prompt becomes a critical artifact — its quality directly determines agent output quality
- The agent produces task-fit reasoning as free-text PR comments, not the strict `validate_taskfit_response()` format. The validator is used only by the CLI path's `TaskFitAdvisor`. The agent's output is for human consumption, not machine parsing.
- `TaskFitAdvisor` remains in `core/taskfit.py` for the CLI path — the agent path does not use it
- The rubric text exists in two places: `core/taskfit.py:_SYSTEM_PROMPT` and `agent/prompt.py:_RUBRIC`. If the rubric changes, both must be updated. Future: extract to a shared constant.
