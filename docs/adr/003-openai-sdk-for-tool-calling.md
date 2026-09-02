# ADR-003: GitHub Copilot SDK for Agent Framework

## Status

Superseded (2026-09-01) — the Foreman Copilot agent this ADR designed was removed. See docs/decommission-log.md entry 15 ("Foreman Copilot agent") for the removal record.

## Context

The agent needs an LLM with tool-calling support. The whole point of choosing the agent path over a plain GitHub Action was to avoid writing our own LLM orchestration code. Three options were evaluated:

1. **GitHub Copilot SDK** (`copilot` / `agent-framework-github-copilot` Python package) — native Copilot integration, handles tool registration, message loop, and auth. Pre-release.
2. **OpenAI Python SDK** (`openai>=1.30`) — stable, but requires hand-writing the tool-calling loop
3. **Raw httpx** — the existing `TaskFitAdvisor` pattern, maximum control but maximum code

## Decision

We will use the GitHub Copilot SDK Python package. The framework handles tool registration, the agent message loop, and model access. We define tools with schemas and handlers — the framework does the rest. This is why we chose the agent path.

Pre-release risk is accepted for the PoC. Pin the exact version.

## Consequences

- New runtime dependency: `agent-framework-github-copilot>=1.0.0b260423` (pre-release, pinned). Pulls in `agent-framework-core` and `github-copilot-sdk`.
- No hand-rolled tool-calling loop — `GitHubCopilotAgent` from `agent_framework_github_copilot` owns the agent loop
- Tools are Python functions decorated with `@tool` from `agent_framework`. The decorator infers JSON Schema from type annotations and docstrings.
- Agent is created with `GitHubCopilotAgent(instructions=..., tools=[...])`, run with `await agent.run(message)`, response accessed via `response.text`
- If the SDK API changes, the adapter surface is small: `main.py:_run_agent_session()` is the only integration point
- The existing `httpx`-based LLM calling in `TaskFitAdvisor` remains unchanged for the CLI path
