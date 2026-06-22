---
title: "Mock-Masked Integration Wiring Failures"
component: src/caliper/cli/main.py
tags: integration, multi-agent, mocks, constructor-mismatch, type-error, e2e-testing, parallel-agents
category: integration-issues
date: 2026-04-23
severity: high
status: diagnosed
root_cause: "Multi-agent parallel implementation produced individually-correct components with incompatible constructor signatures. The CLI wiring layer called constructors with kwargs that don't exist. E2E tests passed by mocking around the real mismatches."
---

# Mock-Masked Integration Wiring Failures

## Problem

**Symptoms:** 246 unit and integration tests pass. The pipeline appears fully functional. But the CLI tool crashes with `TypeError` on every real invocation — no package is ever actually evaluated.

**Environment:** Multi-agent parallel implementation of a CLI pipeline. Each agent implemented 2-6 modules independently. All agents produced passing unit tests for their modules.

**Scale:** 5 critical bugs (severity 10), 4 of which are constructor signature mismatches, 1 is a hardcoded empty-string passthrough. All concentrated in a single file: `cli/main.py` — the wiring layer.

## Root Cause

The failure pattern has three layers:

### Layer 1: Agent boundary = integration boundary

When 4 parallel agents implement modules independently, each agent knows its own constructor signatures but not the signatures of modules built by other agents. The CLI wiring layer (`main.py`) was built by a 5th agent that had to guess how to instantiate objects from all other agents' modules. It guessed wrong 4 times.

Specific mismatches:
- `OsvScanner(evidence_dir=...)` — actual signature is `OsvScanner(sbom_path=...)`
- `TrivyScanner(evidence_dir=...)` — `TrivyScanner` has no `__init__` at all
- `ScanOrchestrator(individual_timeout=...)` — no such kwarg exists
- `_parse_changes("", "")` — hardcoded empty strings instead of forwarding diff content

### Layer 2: Unit tests don't catch cross-module wiring

Each module's unit tests verify that module's behavior in isolation. The scanner tests mock `subprocess.run`. The orchestrator tests mock the scanners. The CLI tests mock the orchestrator. No test ever instantiates a real `OsvScanner` inside a real `ScanOrchestrator` called from a real CLI.

### Layer 3: E2E tests mock at the wrong boundary

The E2E integration test (`test_e2e.py`) was supposed to catch these bugs. Instead, it mocked `ScanOrchestrator` at the class level (replacing it entirely), mocked `DependencyDiffDetector.parse_requirements_diff` to inject fake changes, and limited `CALIPER_ENABLED_SCANNERS` to only the two scanners whose constructors happened to work. The E2E test effectively rewired the pipeline to avoid the broken paths, then verified the non-broken subset worked.

**The test passed because it tested a different pipeline than the one the CLI actually runs.**

## Solution

### Fix 1: Constructor signature alignment

```python
# Before (main.py:119-134) — crashes with TypeError
scanners = []
for name in config.enabled_scanners:
    if name == "syft":
        scanners.append(SyftScanner(evidence_dir=config.evidence_path))
    elif name == "osv-scanner":
        scanners.append(OsvScanner(evidence_dir=config.evidence_path))  # WRONG kwarg
    elif name == "trivy":
        scanners.append(TrivyScanner(evidence_dir=config.evidence_path))  # No __init__
    elif name == "scancode":
        scanners.append(ScanCodeScanner(evidence_dir=config.evidence_path))

orchestrator = ScanOrchestrator(
    scanners=scanners,
    individual_timeout=config.scanner_timeout,  # WRONG kwarg
    combined_timeout=config.combined_scanner_timeout,
)

# After — matches actual constructor signatures
scanners = []
evidence_path = Path(config.evidence_path)
for name in config.enabled_scanners:
    if name == "syft":
        scanners.append(SyftScanner(evidence_dir=evidence_path))
    elif name == "osv-scanner":
        scanners.append(OsvScanner())  # no evidence_dir param
    elif name == "trivy":
        scanners.append(TrivyScanner())  # no __init__ at all
    elif name == "scancode":
        scanners.append(ScanCodeScanner(evidence_dir=evidence_path))

orchestrator = ScanOrchestrator(
    scanners=scanners,
    combined_timeout=config.combined_scanner_timeout,
)
```

### Fix 2: _parse_changes must forward diff content

```python
# Before (main.py:279) — always returns empty list
changes = detector.parse_requirements_diff("", "")

# After — extract before/after content from unified diff
before, after = detector.extract_file_content(diff_text, fpath)
changes = detector.parse_requirements_diff(before, after)
```

### Fix 3: Scanner loop hoisted above per-package loop

```python
# Before — scanners run N times for N packages
for req in requests:
    scan_results = orchestrator.run(Path(repo_path))  # INSIDE loop

# After — scanners run once for the repo
scan_results = orchestrator.run(Path(repo_path))  # OUTSIDE loop
for req in requests:
    # reuse scan_results for each package
```

### Fix 4: E2E test must exercise real constructors

```python
# Before — mocks hide the TypeError
with patch.object(ScanOrchestrator, '__init__', return_value=None):
    ...

# After — integration test instantiates real objects
# If a constructor call fails, the test fails — that IS the test
orchestrator = ScanOrchestrator(scanners=[...], combined_timeout=180)
```

## Prevention

- **Test case:** Add a smoke test that imports `cli/main.py` and calls `_run_evaluate` with a minimal valid config and a non-empty diff. No mocks on constructors — if the wiring is wrong, this test fails with `TypeError` before any scanning happens. Name it `test_wiring_smoke.py`.

- **Monitoring:** Track `issues.jsonl` entries of type `mock` — any mock that replaces a constructor or class wholesale is a red flag. The mock should target the *behavior* (subprocess call, HTTP response), not the *object instantiation*.

- **Best practice — Multi-agent integration rule:** When parallel agents implement independent modules, the LAST agent to run (the wiring agent) must READ the actual source files of all modules it's connecting — not just the TASKS.md specification. Constructor signatures in specs drift from implementation. The source file is the contract.

- **Best practice — E2E mock boundary rule:** E2E/integration tests should mock at the system boundary (subprocess, network, database), never at the application boundary (class constructors, module imports). If you have to mock a constructor to make an integration test pass, the integration is broken — the test is telling you something.

- **Best practice — issues.jsonl:** Every mock, stub, or workaround gets logged to `issues.jsonl` with the reason. If the reason is "constructor doesn't match," that's a bug, not a test strategy.

## Related

- `.wfc/reviews/REVIEW-main-001.md` — the 5-reviewer consensus review that surfaced these findings
- `issues.jsonl` — 6 entries seeded from this review, including the 3 mock-masked bugs
- `TASKS.md` — the task plan that drove the parallel agent implementation
