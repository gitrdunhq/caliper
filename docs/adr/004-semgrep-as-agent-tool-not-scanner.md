# ADR-004: Semgrep as Agent Tool, Not Pipeline Scanner

## Status

Superseded (2026-09-01) — the Foreman Copilot agent this ADR designed was removed. See docs/decommission-log.md entry 15 ("Foreman Copilot agent") for the removal record.

## Context

Semgrep is being added for code pattern scanning on PR diffs. The existing pipeline has a well-defined `Scanner` ABC (`data/scanners/base.py`) with four implementations (Syft, OSV-Scanner, Trivy, ScanCode). All scanners run in parallel via `ScanOrchestrator` and produce `ScanResult` objects with `Finding` lists.

Semgrep serves a fundamentally different purpose: it scans *source code* for patterns (security footguns, policy violations, bad practices), not *packages* for vulnerabilities or licenses. Two approaches:

1. Implement Semgrep as a 6th `Scanner` subclass in the pipeline
2. Implement Semgrep as a separate agent tool (`scan_code`) outside the pipeline

## Decision

We will implement Semgrep as a separate agent tool (`scan_code`) in `agent/tools.py`, not as a `Scanner` subclass. The agent calls `scan_code` independently from `evaluate_change`.

## Consequences

- Semgrep findings are NOT `Finding` objects — they have a different schema (rule_id, category, file, line range vs. advisory_id, severity, package_name)
- Semgrep does not participate in OPA policy evaluation — it's informational only
- The existing pipeline, scanners, and `ScanOrchestrator` remain untouched
- PR comments clearly separate dependency findings from code pattern findings
- Semgrep runs only on changed files (extracted from diff), not the entire repo
- Future: if Semgrep findings should affect the policy decision (e.g., block on security findings), a new OPA rule category would be needed — but that's post-PoC
- The `Scanner` ABC is preserved for its intended purpose: package-level scanning tools that produce `Finding` objects
