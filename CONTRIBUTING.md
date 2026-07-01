# Contributing to Dependency Review

## Prerequisites

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) — the only package/run toolchain used here
- Docker or Podman — for the PostgreSQL dev instance
- Scanner binaries are **optional** for unit tests (mocked); required for integration tests:
  - `osv-scanner`, `trivy`, `syft`, `scancode-toolkit`
  - `opa` — for policy unit tests

## Development Setup

```bash
uv sync --group dev           # install all deps including dev
docker-compose up -d          # start PostgreSQL on port 12432
make test                     # run full test suite
make quality-check            # black + ruff
opa test policies/ --ignore '*.yaml' --ignore '*.yml'  # OPA policy unit tests
```

First-run sanity check:

```bash
uv run python -c "from caliper.core.pipeline import ReviewPipeline; print('ok')"
```

## Project Structure

Three-tier layout — presentation → logic → data. No skipping tiers.

```
src/caliper/
  cli/          # Presentation: CLI entry points, Jenkins interface
                # Thin adapters only — no business logic here
  core/         # Logic: pipeline, orchestration, policy, decisions, config
                # Zero knowledge of HTTP frameworks or subprocess details
  data/         # Data: scanners, DB, PyPI client, evidence store, Parquet
                # No business rules — fetch, store, return

policies/       # OPA Rego rules + tests + INPUT_SCHEMA.md
tests/
  unit/         # Fast, no I/O, no subprocesses
  integration/  # Real DB + real scanners (CI only)
```

## Testing Standards

**TDD red-green is mandatory.** Write the failing test before writing source.

1. Write the test. Run it. See it fail (RED).
2. Write minimum source to make it pass.
3. Run the test. See it pass (GREEN).
4. Commit test + source together.

Post-hoc tests are forbidden — a test written after the source cannot prove it would have caught the bug.

**`# tested-by:` annotations** — add a comment in every source file pointing to its primary test file:

```python
# tested-by: tests/unit/test_normalizer.py
```

**Property-based tests** — use `hypothesis` for any function that processes external strings (diff parsing, version comparison, path handling). See `tests/unit/test_diff.py` for examples.

**Assertion quality** — never use `toBeDefined()` / `assert result` as the only assertion. Assert concrete values. If you delete the function body, the test must fail.

Run tests:

```bash
uv run pytest tests/ -v
uv run pytest tests/unit/ -v          # unit only (no scanner binaries needed)
uv run pytest tests/integration/ -v   # requires Docker + scanner binaries
```

## Code Standards

**Logging** — `structlog` only. No `print()`. Bind `correlation_id` and `package_name` at the top of each pipeline entry point.

**State fields** — use `Enum`, never raw strings. If a field can be one of N values, it must be an `Enum`.

**Typed contracts at boundaries** — all functions that cross tier boundaries must have typed signatures. No `dict[str, Any]` payloads crossing from `data` into `core`.

**Fail-open** — scanner timeouts skip with a notation in the evidence bundle; OPA failures route to `needs_review`; DB failures log and continue. Nothing blocks the build.

**Timeouts** — every external call must have an explicit timeout. Read it from `ReviewConfig`, never hardcode it. Default values live in the config model.

**Secrets** — `pydantic.SecretStr` for all credential fields. Never log DSNs or API keys.

**Path handling** — always coerce `str` to `Path` at construction time in classes that work with the filesystem. Never call `.mkdir()` on a bare string.

## Adding a Scanner

1. Create `src/caliper/data/scanners/<name>.py`
2. Subclass `BaseScanner` from `scanners/base.py`
3. Set `_TIMEOUT: int` as a class constant (seconds)
4. Implement `scan(self, target: Path) -> ScanResult` — use `ScanResult.ok()` / `ScanResult.failed()` factory methods
5. Return `ScanResult.timed_out()` on `subprocess.TimeoutExpired`; never let scanner exceptions propagate
6. Add to `ScanOrchestrator` scanner list in `core/orchestrator.py`
7. Write unit tests in `tests/unit/test_scanners.py` with a mocked subprocess; write integration test in `tests/integration/`
8. Add `# tested-by:` annotation in your new file

Scanner output must be normalized via `FindingNormalizer` before reaching `core`. Do not add scanner-specific logic to the orchestrator.

## Adding an OPA Rule

1. Add the new rule to `policies/policy.rego`
2. Add a test case in `policies/policy_test.rego` — both passing and failing inputs
3. Update `policies/INPUT_SCHEMA.md` with any new input fields the rule reads
4. Populate the new field in `ReviewPipeline._build_package_metadata()` in `core/pipeline.py`
5. Run `opa test policies/ --ignore '*.yaml' --ignore '*.yml'` — all tests must pass

Rules must be written defensively: `input.pkg.field` with `default` assignments so that missing fields produce `needs_review`, not `deny` or silent bypass.

## Review Process

This project uses a compound review loop:

1. `wfc-review` — 5-agent review (Security, Correctness, Performance, Maintainability, Reliability)
2. `wfc-compound` — aggregates findings into a structured remediation plan
3. Fix findings, re-run `wfc-review` targeting the same base
4. Pass 2 verdict must be PASSED before merge

Review reports live in `.wfc/reviews/`. Do not commit them.

When a finding is fixed, the scanner in the next pass verifies it. Regressions caught mid-pass are fixed inline and noted in the pass 2 report.

## Commit Conventions

Prefix commits with `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, or `chore:`.

```
feat: add ScanCode license scanner with ThreadPoolExecutor integration
fix: path traversal guard on EvidenceStore artifact_name
```

One logical change per commit. Squash before pushing:

```bash
wfc git squash main    # or: git rebase -i origin/main
```

One commit per PR — no squash exemptions.

## Issues and Tech Debt

- Stubs, fakes, and shims must carry a `# TODO:` or `# FIXME:` comment with: what is stubbed, why, what the real implementation is, and what removes it.
- If you notice a bug or smell outside your current scope (severity >= 4), open a GitHub issue:

```bash
unset GITHUB_TOKEN && gh issue create \
  --title "[see-something] category: brief description (file:line)" \
  --label "see-something" \
  --body "What's wrong, why it matters, suggested fix"
```

Known non-blocking findings are tracked in `.wfc/reviews/`. Check there before opening a duplicate.
