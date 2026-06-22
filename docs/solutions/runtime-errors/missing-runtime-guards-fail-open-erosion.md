---
title: "Missing Runtime Guards — Fail-Open Erosion"
component: src/caliper/cli/main.py, src/caliper/data/scanners/syft.py
tags: reliability, fail-open, timeout, sys-exit, type-coercion, runtime-guard
category: runtime-errors
date: 2026-04-23
severity: high
status: diagnosed
root_cause: "Three runtime guard failures: (1) unconditional sys.exit(0) hides all pipeline failures from Jenkins, (2) pipeline_timeout config loaded but never enforced end-to-end, (3) str/Path type mismatch causes AttributeError in scanners that bypasses the intended error handler."
---

# Missing Runtime Guards — Fail-Open Erosion

## Problem

**Symptoms:** The system's core promise is fail-open: no scanner failure blocks a build. But three bugs erode this guarantee in different ways — one hides failures entirely, one allows unbounded execution, and one triggers the wrong error path.

**Environment:** CLI pipeline running in Jenkins. The fail-open design is correct in principle (scanner timeouts, DB fallback to NullRepository, OPA fallback to needs_review). The bugs are in the gaps between the designed fail-open paths.

### Bug 1: Unconditional sys.exit(0) (F-006, severity 9)

```python
# Before — hides ALL failures including unexpected crashes
@cli.command()
def evaluate(...):
    try:
        _run_evaluate(...)
    except Exception:
        logger.exception("pipeline_failed_unexpectedly")
    sys.exit(0)  # Always 0, even after exception
```

This is too fail-open. The intent is "scanner failures shouldn't block builds." The reality is "nothing blocks builds, including crashes, config errors, and bugs." Jenkins has no way to distinguish "pipeline ran, found no issues" from "pipeline crashed before running."

```python
# After — fail-open for known degradations, fail-closed for unexpected crashes
@cli.command()
def evaluate(...):
    try:
        _run_evaluate(...)
    except SystemExit:
        raise  # Let Click handle exit codes
    except Exception:
        logger.exception("pipeline_failed_unexpectedly")
        # Unexpected crash = bug in our code, not a scanner failure
        # Exit 1 so Jenkins can distinguish crash from clean run
        raise SystemExit(1)
```

### Bug 2: Pipeline timeout not enforced (F-007, severity 9)

```python
# Before — config.pipeline_timeout=300 is loaded but never checked
pipeline_start = time.monotonic()
# ... 200 lines of pipeline code ...
# Nowhere is (time.monotonic() - pipeline_start) compared to config.pipeline_timeout

# After — check at top of per-package loop
for req in requests:
    elapsed = time.monotonic() - pipeline_start
    if elapsed >= config.pipeline_timeout:
        logger.warning("pipeline_timeout_exceeded",
                       elapsed=elapsed,
                       budget=config.pipeline_timeout,
                       packages_remaining=len(requests) - requests.index(req))
        break
```

### Bug 3: str/Path type mismatch (F-014, severity 7)

```python
# Before — config returns str, scanners expect Path
# config.py
evidence_path: str = "./evidence"

# syft.py — calls .mkdir() on a str
self._evidence_dir = evidence_dir  # str, not Path
self._evidence_dir.mkdir(parents=True, exist_ok=True)  # AttributeError!

# The except OSError handler doesn't catch AttributeError
# The orchestrator's broad except Exception catches it and marks the scanner as "failed"
# This is the WRONG error path — it looks like a scanner crash, not a type bug
```

```python
# After — coerce at the boundary
# config.py
evidence_path: Path = Path("./evidence")

# OR at the call site in main.py
SyftScanner(evidence_dir=Path(config.evidence_path))
```

## Root Cause Pattern

All three bugs share a pattern: **the fail-open design covers the happy degradation paths but not the meta-failures.**

- Scanner timeout → handled (skip with notation) ✓
- DB unavailable → handled (NullRepository fallback) ✓
- OPA crash → handled (needs_review) ✓
- Pipeline code itself crashes → NOT handled (sys.exit(0) hides it)
- Pipeline runs forever → NOT handled (no wall-clock guard)
- Type error in wiring → caught by wrong handler (looks like scanner failure, not a bug)

The lesson: fail-open must distinguish between **expected degradations** (scanner down, DB down) and **unexpected bugs** (TypeError, AttributeError). Expected degradations should log and continue. Unexpected bugs should fail loudly.

## Prevention

- **Test case — exit code on crash:** Inject an exception into `_run_evaluate` (e.g., `RuntimeError("test crash")`) and assert the CLI exit code is non-zero. This verifies that unexpected crashes are visible to Jenkins.

- **Test case — pipeline timeout:** Mock `time.monotonic()` to advance past `pipeline_timeout` and assert the loop breaks with a warning log. Verify that packages processed before the timeout still produce decisions.

- **Test case — type coercion:** Pass a `str` evidence_path to each scanner and assert no `AttributeError` is raised. Either the scanner should coerce it or the test should catch the type error explicitly.

- **Best practice — fail-open taxonomy:** Document three categories of failure with different responses:
  1. **Expected degradation** (scanner/DB/OPA down) → log, continue, exit 0
  2. **Config error** (missing env var, invalid value) → log, exit 1 with clear message
  3. **Bug in our code** (TypeError, AttributeError, unexpected exception) → log, exit 1

- **Best practice — type boundaries:** Use `Path` type in config (Pydantic coerces str→Path automatically). Never accept `str` when `Path` is the actual usage. The type annotation is the documentation.

## Related

- `.wfc/reviews/REVIEW-main-001.md` — findings F-006, F-007, F-014
- `docs/solutions/integration-issues/mock-masked-integration-wiring-failures.md` — str/Path is the same cross-agent boundary pattern
