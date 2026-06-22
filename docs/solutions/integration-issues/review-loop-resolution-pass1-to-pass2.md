---
title: "Review Loop Resolution — BLOCKED_CRITICAL to PASSED in One Fix Pass"
component: src/caliper/cli/main.py, src/caliper/core/pipeline.py
tags: review-loop, compound, multi-agent, wiring, parallel-agents, fail-open, security, performance, architecture
category: integration-issues
date: 2026-04-23
severity: high
status: resolved
root_cause: "Multi-agent parallel implementation produced 19 individually-correct modules with 15 integration-layer bugs. All bugs concentrated in the CLI wiring layer (main.py). Root causes: constructor signature mismatches across agent boundaries, missing data flow connections, unconditional exit codes, sequential execution of parallel-safe work, and three independent injection/leak vectors."
---

# Review Loop Resolution — BLOCKED_CRITICAL to PASSED in One Fix Pass

## Problem

**Pass 1 verdict**: BLOCKED_CRITICAL — 30 findings, 7 at severity 10, CS=10.00

The system had 246 passing tests but was entirely non-functional in production. The pipeline would crash with `TypeError` on every invocation, before a single package was ever evaluated. Three separate security vulnerabilities existed across three architectural layers. Two OPA policy rules were permanently disabled by missing data. The scanner phase would have consumed 80% of the timeout budget running sequentially.

## What Was Fixed (15 HIGH+ findings)

### Critical (severity 10) — 5 findings

| Fix | Before | After |
|---|---|---|
| F-001: _parse_changes | `parse_requirements_diff("", "")` — hardcoded empty strings | `extract_file_content_from_diff()` parses unified diff, forwards real content |
| F-002: ScanOrchestrator | `individual_timeout=` kwarg doesn't exist → TypeError | Removed kwarg, per-scanner timeouts are internal |
| F-003: OsvScanner | `evidence_dir=` kwarg doesn't exist → TypeError | `OsvScanner()` with no args |
| F-004: TrivyScanner | No `__init__` at all → TypeError | `TrivyScanner()` with no args |
| F-005: Per-package scanning | `orchestrator.run()` inside loop → N×180s | Hoisted above loop → 180s once |

### High (severity 7-9) — 10 findings

| Fix | Category | Change |
|---|---|---|
| F-006: sys.exit(0) unconditional | reliability | Exit 1 on unexpected crashes, 0 on fail-open degradation |
| F-007: No pipeline timeout | performance | Wall-clock check at top of per-package loop |
| F-008: Jenkins shell injection | security | `withEnv([...])` for all user-controlled values |
| F-009: DSN password logged | security | `_safe_dsn()` masks password in all log calls |
| F-010: CVSS fallback no-op | correctness | Score parsing + CVSS vector heuristic implemented |
| F-011: Sequential scanners | performance | `ThreadPoolExecutor` parallel execution |
| F-012: OPA rules bypassed | security | `first_published_date` from PyPI, `transitive_dep_count` from SBOM |
| F-013: LLM prompt injection | security | Structured system/user messages + `_sanitize_summary()` |
| F-014: str/Path mismatch | reliability | `Path()` coercion at config boundary |
| F-015: core→data import | maintainability | Factory methods moved to `ScanResult` class methods |

### Architecture extraction

`cli/main.py` (285 lines of business logic) → `core/pipeline.py` (ReviewPipeline class) + thin CLI adapter (150 lines). The presentation layer no longer owns business logic.

## Regressions Caught During Pass 2

Three regressions were caught by the pass-2 reviewers and fixed inline:

| Regression | Caught By | Root Cause |
|---|---|---|
| F-022 partial: `store_file()` missing path traversal guard | Security reviewer | Fix agent applied guard to `store()` but not `store_file()` — same method, same vulnerability, missed the second call site |
| F-017: Version comparison still string ordering | Correctness reviewer | Scanner fix agent was assigned this but didn't get to it before stalling |
| F-016: Config failure misleading message | Maintainability reviewer | CLI fix agent changed the log message but not the `click.echo` user-facing message |

**Pattern**: regression happens when a fix is applied to one call site but not all call sites of the same pattern. The fix agent saw `store()` and fixed it, but didn't grep for `store_file()` which had identical code. Prevention: after applying a fix, grep for the same pattern in the same file and adjacent files.

## Metrics

| Metric | Pass 1 | Pass 2 | Delta |
|---|---|---|---|
| Total findings | 30 | 10 | -20 |
| Critical (sev 9-10) | 7 | 0 | **-7** |
| High (sev 7-8) | 8 | 0 | **-8** |
| Moderate (sev 5-6) | 10 | 6 | -4 |
| Low (sev 3-4) | 5 | 4 | -1 |
| Tests | 246 | 280 | +34 |
| CS score | 10.00 | 3.60 | **-6.40** |
| Verdict | BLOCKED_CRITICAL | **PASSED** | ✅ |

## Key Learnings

### 1. Unit test coverage ≠ integration correctness

246 tests passed but the pipeline crashed on every real invocation. Unit tests verify module behavior in isolation. They don't verify that module A's constructor signature matches what module B thinks it is. The gap was closed by adding pipeline smoke tests that instantiate real objects without mocking constructors.

### 2. E2E tests that mock constructors are worse than no E2E tests

The E2E test passed by replacing `ScanOrchestrator` at the class level with a `MagicMock`. This hid 4 TypeErrors. An E2E test should mock at the system boundary (subprocess, network, DB), never at the application boundary (class constructors). If you have to mock a constructor to make an integration test pass, the integration is broken.

### 3. Multi-agent fix passes need grep-for-pattern discipline

When a fix agent patches one call site, it must grep for the same pattern in the same file and adjacent files. The `store_file()` regression happened because the agent fixed `store()` and stopped. `grep -n "dest_dir / artifact_name" evidence.py` would have caught both.

### 4. The wiring layer is the highest-risk module in multi-agent builds

19 modules were implemented by 4 parallel agents. All 19 work correctly in isolation. The 5th agent — the one that wires them together — produced 10 of the 15 HIGH+ bugs. This is structural: the wiring agent must read actual source files, not specifications. **The source file is the contract.**

### 5. Security vulnerabilities are independent of functional correctness

The 3 security findings (shell injection, credential leak, prompt injection) existed in fully-functional code. They would never cause a test failure. They require a security-specific reviewer perspective — functional correctness review alone would not have caught them.

### 6. Review → compound → fix → re-review works

The loop produced measurable improvement: CS dropped from 10.00 to 3.60, critical findings from 7 to 0. The compound documents from pass 1 directly informed the fix agents' work. The pass-2 reviewers caught 3 regressions that the fix agents introduced. Without the re-review, those regressions would have shipped.

## Prevention (Applied)

- `# tested-by:` annotations on all 19 source files
- `issues.jsonl` tracks all mocks, stubs, and workarounds
- Compound documents capture fix patterns for future agents
- Pipeline smoke test verifies real constructor signatures
- Security tests for DSN masking, path traversal, SecretStr, prompt structure
- Hypothesis property-based test for CVSS score→severity monotonicity

## Related

- `.wfc/reviews/REVIEW-main-001.md` — pass 1 (BLOCKED_CRITICAL)
- `.wfc/reviews/REVIEW-main-002.md` — pass 2 (PASSED)
- `docs/solutions/integration-issues/mock-masked-integration-wiring-failures.md` — compound 1
- `docs/solutions/security-issues/injection-and-secret-leaks-across-layers.md` — compound 2
- `docs/solutions/runtime-errors/silent-safety-rule-bypasses.md` — compound 3
- `docs/solutions/runtime-errors/missing-runtime-guards-fail-open-erosion.md` — compound 4
- `docs/solutions/performance-issues/architecture-violations-coupling-and-sequential-scanners.md` — compound 5
- `issues.jsonl` — 6 tracked issues from review
