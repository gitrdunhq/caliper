# ADR-001: Agent Module as Separate Entry Point

## Status

Accepted

## Context

The review pipeline currently has one entry point: the Click CLI at `cli/main.py`. We need to add a GitHub Copilot Agent that wraps the same pipeline for reactive PR review. The agent needs its own configuration (enforcement mode, GitHub token, LLM settings) and its own execution flow (LLM tool-calling loop, PR comment posting).

Two approaches were considered:
1. Extend the CLI with agent subcommands
2. Create a separate `agent/` module as a new presentation-tier entry point

## Decision

We will create `src/caliper/agent/` as a separate presentation-tier module, parallel to `cli/`. The agent imports from `core/` and `data/` — the same tiers the CLI uses. No shared code is duplicated; the agent calls `ReviewPipeline.evaluate()` directly.

## Consequences

- The CLI continues to work unmodified — zero risk of regression
- The agent has its own config (`AgentSettings` with `FOREMAN_` prefix) independent of `CaliperSettings`
- The agent must construct an `CaliperSettings` internally to pass to `ReviewPipeline`, mapping its own config fields
- Two entry points means two places to maintain environment documentation
- The three-tier architecture is preserved: `agent/` is presentation, `core/` is logic, `data/` is persistence
