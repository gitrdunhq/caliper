# Deterministic Bug Detector Test Plan

This plan covers the detector subtasks for bugs #201 through #234 under the
`next` parent. The goal is to make each bug mechanically detectable from
repository state or controlled fixtures before product-code remediation.

## Scope

- Add detector tests only; do not fix product behavior in this pass.
- Keep tests deterministic: no network calls, no unbounded sleeps, no reliance
  on live GitHub state.
- Prefer static parsing, AST checks, fake adapters, temporary directories, and
  controlled executor fixtures.
- Preserve repo standards: container-first validation, explicit timeouts,
  typed boundaries, `SecretStr` for secrets, `# tested-by` annotations, and
  fail-open behavior represented as typed degraded results.

## Detector Slices

| Slice | File | Bugs |
| --- | --- | --- |
| Workflow, container, release guards | `tests/unit/test_deterministic_workflow_guards.py` | #201, #203, #213, #214, #215, #216, #229, #233 |
| Source architecture guards | `tests/unit/test_deterministic_source_guards.py` | #219, #224, #226, #227, #231 |
| Runtime contract guards | `tests/unit/test_deterministic_runtime_contracts.py` | #202, #204, #205, #206, #208, #209, #210, #211, #217, #218, #221, #222, #223, #228, #230, #232, #234 |
| Coverage, timeout, concurrency guards | `tests/unit/test_deterministic_coverage_guards.py` | #207, #212, #220, #225 |

## Test Strategy

### Workflow, Container, Release

- Parse GitHub workflow YAML and composite action YAML.
- Assert pull request workflows do not execute checked-out code on
  self-hosted runners with write-scoped tokens.
- Assert required workflows run container tests and quality gates.
- Assert `foreman` dispatch inputs are wired into runtime behavior.
- Assert release publishing fails closed when the release key is absent.
- Assert `make test` does not hide image-built dependencies with an unsafe bind
  mount.
- Assert Docker runtime and test dependency pins agree with `pyproject.toml`
  and `uv.lock`.
- Assert composite action multiline output delimiters are generated uniquely
  before writing untrusted memo text.

### Source Architecture

- Parse Python source with `ast`.
- Assert core ports do not expose `Any`, bare containers, or raw string state
  fields.
- Assert source files have current `# tested-by` annotations pointing at real
  tests.
- Assert GitHub publisher and repo snapshot subprocess calls have explicit
  `timeout=`.
- Assert secret-bearing settings and trust-boundary constructor arguments use
  `pydantic.SecretStr`.
- Assert agent and core orchestration imports stay behind use-case and port
  boundaries instead of importing concrete lower-tier modules.

### Runtime Contracts

- Use fake adapters, fake repositories, fake scanners, and `tmp_path`.
- Assert bootstrapped OPA input matches the bundled policy schema.
- Assert production bootstrap does not wire fake or null adapters into the real
  evaluation path.
- Assert agent block mode consumes typed decisions, not LLM response shape.
- Assert base SBOM generation does not mutate the active checkout.
- Assert evidence stores create parent directories for package artifacts and
  reject traversal safely.
- Assert scanner and OPA timeout settings propagate from config into runtime
  adapters.
- Assert every detected dependency manifest type has parser coverage.
- Assert degraded plugin failures do not become blocking PR review changes.
- Assert SBOM evaluation appends audit data, seals evidence, redacts full SBOM
  payloads from JSON reports, preserves telemetry config during merge, and
  detects unexpected files during seal verification.

### Coverage, Timeout, Concurrency

- Use fake futures/executors instead of wall-clock sleeps for combined timeout
  checks.
- Use a barrier plugin pair to prove independent analyzers are started
  concurrently.
- Inspect `# tested-by` targets to ensure optional copilot, webhook, and
  parquet surfaces are covered by default tests that do not module-skip.
- Inspect Hypothesis-decorated tests to ensure property coverage exists for
  diff parsing, path traversal/normalization, and manifest parsing boundaries.

## GitHub Issue Mapping

Each parent bug has a native detector sub-issue:

| Parent bug | Detector subtask |
| --- | --- |
| #201 | #235 |
| #202 | #236 |
| #203 | #237 |
| #204 | #238 |
| #205 | #239 |
| #206 | #240 |
| #207 | #241 |
| #208 | #242 |
| #209 | #243 |
| #210 | #244 |
| #211 | #245 |
| #212 | #246 |
| #213 | #247 |
| #214 | #248 |
| #215 | #249 |
| #216 | #250 |
| #217 | #251 |
| #218 | #252 |
| #219 | #253 |
| #220 | #254 |
| #221 | #255 |
| #222 | #256 |
| #223 | #257 |
| #224 | #258 |
| #225 | #259 |
| #226 | #260 |
| #227 | #261 |
| #228 | #262 |
| #229 | #263 |
| #230 | #264 |
| #231 | #265 |
| #232 | #266 |
| #233 | #267 |
| #234 | #268 |

## Validation Gates

Run these focused checks after adding or editing detector tests:

```bash
python3 -m py_compile \
  tests/unit/test_deterministic_workflow_guards.py \
  tests/unit/test_deterministic_source_guards.py \
  tests/unit/test_deterministic_runtime_contracts.py \
  tests/unit/test_deterministic_coverage_guards.py

UV_CACHE_DIR=/tmp/uv-cache uv run ruff check \
  tests/unit/test_deterministic_workflow_guards.py \
  tests/unit/test_deterministic_source_guards.py \
  tests/unit/test_deterministic_runtime_contracts.py \
  tests/unit/test_deterministic_coverage_guards.py

UV_CACHE_DIR=/tmp/uv-cache uv run black --check \
  tests/unit/test_deterministic_workflow_guards.py \
  tests/unit/test_deterministic_source_guards.py \
  tests/unit/test_deterministic_runtime_contracts.py \
  tests/unit/test_deterministic_coverage_guards.py
```

Acceptance still requires the repo container gate:

```bash
make test
```

The previous blocker was fixed by making `Dockerfile.test` install dependency
layers with `uv sync --frozen --group dev --no-install-project`, then copying
the complete repository context before the final project sync. `make test` now
uses the self-contained image instead of bind-mounting over `/workspace`.

## Current Execution Status

- `python3 -m py_compile` passes for all four detector files.
- `ruff check` passes for all four detector files.
- `black --check` passes for all four detector files.
- `Dockerfile.test` builds successfully and installs the project after copying
  `LICENSE`, `README.md`, source, tests, policies, workflows, scripts, docs,
  and other repository test surfaces.
- `Dockerfile.test` and `Makefile` now default to `linux/amd64` for container
  test builds and runs. Docker builds use BuildKit `RUN --security=insecure`
  for the two `uv sync` layers because Docker's deprecated build-level
  `--security-opt apparmor=unconfined` does not relax BuildKit `RUN`
  confinement; test container runs still pass
  `--security-opt apparmor=unconfined`.
- The production `Dockerfile` now has amd64 hashes for syft, trivy,
  osv-scanner, opa, gitleaks, jq, kube-linter, and ls-lint, pins the Python
  base image by digest, and records dereferenced upstream source commits in
  `/opt/caliper/scripts/release-revisions.txt`.
- Focused post-fix container sanity checks passed for the Dockerfile/Makefile
  guards and non-root evidence-store behavior. The only selected failure was
  the existing `test_rejects_global_install` assertion, which conflicts with
  the runtime treating a container as an isolated environment.
- `make test` now reaches pytest inside the completed test image and no longer
  fails during the Docker build. Current full-suite result: `42 failed,
  1470 passed, 28 skipped in 30.99s`.
- Focused in-container detector run was intentionally RED on the current
  snapshot before the Dockerfile fix: `40 failed in 1.29s`.
- Remote amd64 validation on `sambou@192.168.0.210`:
  - `make prod-build` completed and produced `caliper:amd64`.
  - `make prod-smoke` completed with `--security-opt apparmor=unconfined`.
  - `docker run --rm --platform linux/amd64 --security-opt apparmor=unconfined
    --entrypoint sh caliper:amd64 -c "cat
    /opt/caliper/scripts/release-revisions.txt &&
    /opt/caliper/scripts/verify-checksums.sh"` passed and reported all binary
    checksums verified.
  - `make test-build` completed and produced `caliper-test:amd64`.
  - Focused test-image smoke passed:
    `2 passed in 0.77s`.
  - Image metadata inspection reports `amd64` for both `caliper:amd64` and
    `caliper-test:amd64`; the prod image carries Python base revision
    `3362634339580d3232e65a66dd5a36c47ae7ff14`, and the test image carries uv
    revision `0e961dd9a2bb6f73493d9e8398b725ad2d3b3837`.

The focused RED run used the existing `caliper-test:latest` image and streamed
the current repo files into the ephemeral container while `Dockerfile.test` was
still blocked. After the Dockerfile fix, those failures remain detector signals
for the parent bugs, not acceptance failures for the detector files.
