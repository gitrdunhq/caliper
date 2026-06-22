---
title: "Architecture Violations — Coupling, Layer Inversion, and Sequential Scanners"
component: src/caliper/core/orchestrator.py, src/caliper/cli/main.py
tags: architecture, solid, srp, dip, coupling, three-tier, parallel, performance, maintainability
category: performance-issues
date: 2026-04-23
severity: high
status: diagnosed
root_cause: "Three architecture violations: (1) core/ imports private symbols from data/ (dependency inversion), (2) all pipeline logic lives in the presentation layer (SRP violation), (3) scanners run sequentially when they're independent (performance design flaw)."
---

# Architecture Violations — Coupling, Layer Inversion, and Sequential Scanners

## Problem

**Symptoms:**
1. Changing a scanner's internal helper function breaks the orchestrator — modules that shouldn't know about each other are coupled.
2. The CLI can't be tested without mocking everything — all business logic lives in the `evaluate` command handler, not in a testable service layer.
3. The scanner phase consumes 240s worst-case of a 300s budget — 80% of the timeout on work that's embarrassingly parallel.

### Violation 1: core → data import inversion (F-015, severity 7)

```python
# orchestrator.py (core layer) imports from scanners/base.py (data layer)
from caliper.data.scanners.base import _make_failed_result

# The underscore prefix means this is module-private
# core/ should not know about data/ internals
```

This violates the Dependency Inversion Principle (DIP). The three-tier rule: presentation → core → data. Core should never import from data. And definitely not private symbols.

```python
# After — move factory functions to the domain models (core layer)
# core/models.py
class ScanResult(BaseModel):
    ...
    @classmethod
    def timeout(cls, tool_name: str, timeout: int) -> "ScanResult":
        return cls(tool_name=tool_name, status=ScanResultStatus.timeout,
                   message=f"Scanner timed out after {timeout}s", duration_seconds=float(timeout))

    @classmethod
    def failed(cls, tool_name: str, message: str) -> "ScanResult":
        return cls(tool_name=tool_name, status=ScanResultStatus.failed,
                   message=message, duration_seconds=0.0)

# orchestrator.py — imports from core/models.py (same layer)
from caliper.core.models import ScanResult
result = ScanResult.failed(scanner.name, str(e))
```

### Violation 2: Pipeline logic in presentation layer (F-024, severity 8)

`cli/main.py:_run_evaluate` is 150 lines that:
- Instantiates scanners
- Builds the orchestrator
- Runs scans
- Normalizes findings
- Evaluates OPA policy
- Assembles decisions
- Generates memos
- Persists to DB
- Stores evidence
- Writes output JSON

This is ALL business logic. The CLI should be a thin adapter: parse args → call service → format output.

```python
# After — extract to core/pipeline.py
# core/pipeline.py
class ReviewPipeline:
    def __init__(self, config: CaliperSettings):
        self._config = config
        self._orchestrator = self._build_orchestrator()
        self._opa = OpaEvaluator(...)
        self._evidence = EvidenceStore(...)
        self._db = self._connect_db()

    def evaluate(self, diff_text: str, pr_url: str, team: str, mode: OperatingMode) -> list[ReviewDecision]:
        """Run the full pipeline. Returns decisions for all changed packages."""
        ...

# cli/main.py — thin adapter
@cli.command()
def evaluate(repo_path, diff, pr_url, team, operating_mode, output_json):
    config = CaliperSettings()
    pipeline = ReviewPipeline(config)
    diff_text = _read_diff(diff)
    decisions = pipeline.evaluate(diff_text, pr_url, team, OperatingMode(operating_mode))
    for d in decisions:
        click.echo(generate_memo(d))
```

### Violation 3: Sequential scanners (F-011, severity 8)

```python
# Before — sequential, worst case 4 × 60s = 240s
for scanner in self._scanners:
    result = scanner.scan(target_path)
    results.append(result)

# After — parallel, worst case max(60s) = 60s
from concurrent.futures import ThreadPoolExecutor, as_completed

with ThreadPoolExecutor(max_workers=len(self._scanners)) as executor:
    futures = {
        executor.submit(scanner.scan, target_path): scanner
        for scanner in self._scanners
    }
    for future in as_completed(futures, timeout=self._combined_timeout):
        results.append(future.result())
```

Scanners are independent: they each invoke a different CLI tool on the same directory. No shared state, no ordering dependency (Syft SBOM is consumed by OSV only in SBOM mode, which isn't the default path).

## Root Cause Pattern

These three violations share a root cause: **the architecture was specified correctly in CLAUDE.md and TASKS.md, but the agents that implemented the code didn't enforce the tier boundaries.**

- CLAUDE.md says "three-tier: cli/ → core/ → data/". The orchestrator violates this.
- TASKS.md says "CLI is the main interface called by Jenkins." The agent interpreted this as "CLI contains all logic."
- The architecture doc says "run scanners in parallel where practical." The agent implemented sequential because it's simpler.

## Prevention

- **Test case — import direction:** Add a test that scans all `import` statements in `core/` and asserts none reference `data/`. This is a static architecture test — no runtime required.

  ```python
  def test_core_does_not_import_data():
      import ast, pathlib
      core_files = pathlib.Path("src/caliper/core").glob("*.py")
      for f in core_files:
          tree = ast.parse(f.read_text())
          for node in ast.walk(tree):
              if isinstance(node, (ast.Import, ast.ImportFrom)):
                  module = getattr(node, "module", "") or ""
                  assert "caliper.data" not in module, f"{f.name} imports from data layer"
  ```

- **Test case — CLI is thin:** Assert that `cli/main.py` has fewer than 100 lines of non-import, non-decorator code. If it grows past this, logic is leaking into the presentation layer.

- **Best practice — SOLID in multi-agent:** When multiple agents build a project, the TASKS.md should explicitly assign the "wiring" to the same agent that builds the core service layer — not the CLI agent. The CLI agent should receive a `Pipeline` class interface to call, not a list of modules to compose.

- **Best practice — parallel by default:** If operations are independent, the implementation should be parallel unless there's a documented reason for sequencing. "Simpler to implement" is not a valid reason when it consumes 80% of the timeout budget.

## Related

- `.wfc/reviews/REVIEW-main-001.md` — findings F-011, F-015, F-024
- `CLAUDE.md` — three-tier architecture rules
- `docs/solutions/integration-issues/mock-masked-integration-wiring-failures.md` — same agent-boundary problem from a different angle
