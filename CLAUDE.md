# CLAUDE.md

This file provides guidance to Claude Code when working with the eedom scanner.

## What This Is

Eagle Eyed Dom — fully deterministic dependency and code review for CI. 19 scanner plugins (+ OPA policy plugin), 21 deterministic detectors, 61 custom semgrep rules, 12 code graph checks, 8 OPA policy rules, 600+ tests, zero LLM in the decision path.

## Commands

```bash
uv sync --group dev                    # Install all deps
make test                              # Run tests in container (podman/docker)
make test-host                         # Run tests on host (escape hatch)
uv run ruff check src/ tests/          # Lint
uv run black src/ tests/               # Format
make quality-check                     # Format + lint
make dogfood                           # Self-scan with eedom review
make preflight                         # Format + lint + test + dogfood
opa test policies/                     # OPA Rego policy tests
```

**Tests MUST run in a container.** `make test` handles this automatically. Never use `EEDOM_ALLOW_HOST_TESTS=1`.

## Container Builds

**NEVER run `podman build` or `docker build` directly.** Use the build scripts — they handle the podman vs docker differences automatically.

```bash
bash scripts/build.sh              # production image (auto-detects engine)
bash scripts/build.sh arm64        # explicit architecture
bash scripts/build.sh amd64 --no-cache  # force clean rebuild
bash scripts/build-test.sh         # test image + run all tests
bash scripts/build-test.sh -- tests/unit/ -x  # specific tests
bash scripts/build-push.sh         # build + push to GHCR (SHA tag only, latest via release workflow)
```

**Why scripts, not raw commands:**
- Podman (Mac) does NOT support `--security=insecure` in RUN directives — the scripts strip it via sed
- Docker (Linux) NEEDS `--security=insecure` for uv's tokio runtime (AppArmor blocks socketpair)
- Docker also needs a buildx builder with `--allow-insecure-entitlement` — the scripts create it automatically
- Getting this wrong wastes tokens every time

**Running eedom from the container:**
```bash
dom                          # scan current directory (alias in .zshrc)
dom ../openoats              # scan another repo
dom ../openoats sarif        # SARIF output format

# Or manually:
podman run --rm --platform linux/amd64 \
  -v /path/to/repo:/workspace:ro \
  -v /path/to/repo/.temp:/workspace/.temp \
  eedom:latest review --repo-path /workspace --all
```

**Key paths inside container:**

| Path | Purpose |
|------|---------|
| `/opt/eedom/.venv/bin/python` | Python with all deps |
| `/opt/test-venv/bin/python` | Test image Python (use for pytest) |
| `/workspace/` | Repo mount point |
| `/usr/local/bin/entrypoint.sh` | Verifies binary checksums before running |

**Rebuilding after code changes:** Always use `bash scripts/build.sh`. The old `podman build -t eedom:latest .` command will fail on Mac.

**x86 build host (sambou@192.168.0.210):** For Docker builds, GHCR pushes, and CI runner. Has the buildx builder pre-configured.

## Architecture

Three-tier — imports flow downward only (cli -> core -> data):

- `src/eedom/cli/` — thin CLI adapter. Parses args, delegates to core, formats output.
- `src/eedom/core/` — all business logic. Pipeline, policy, plugin registry, renderer, SARIF, config, enrichment seam.
- `src/eedom/data/` — persistence and external calls. Scanners, DB, evidence, parquet, PyPI client.
- `src/eedom/plugins/` — 19 scanner plugins (+ OPA policy plugin) with auto-discovery via `PluginRegistry`.
- `src/eedom/plugins/enrichers/` — code-graph + opt-in semgrep finding enrichers (ADR-006).
- `src/eedom/detectors/` — 21 deterministic AST bug detectors (EED-001..021), exposed as a `DeterministicScanner`. See `docs/detectors.md`.
- `src/eedom/composition/` — composition root: `bootstrap()` wires adapters/enrichers into an `ApplicationContext` (NullRepository fallback when no DB).
- `src/eedom/webhook/` — Starlette ASGI webhook server (GitHub PR events, HMAC-SHA256, port 12800).
- `src/eedom/agent/` — GATEKEEPER Copilot Agent (second presentation-tier entry point).
- `src/eedom/templates/` — Jinja2 templates for PR comment rendering.

**Detect-then-enrich (ADR-006)**: a post-detection, pre-policy pass decorates every finding's `metadata['enrichment']` with deterministic context (enclosing symbol, blast-radius callers, nearby semgrep matches). Sequential, fail-open, time-bounded (`enrichment_timeout`), verdict-independent. Registry: `ENRICHERS` in `core/registries.py`.

## Critical Design Rules

**Fail-open**: No scanner failure blocks a build. Every external call has a timeout. Every failure returns a typed result.

**Timeouts**: scanner=60s, combined=180s, OPA=10s, LLM=30s, enrichment=30s, pipeline=300s. All from config.

**OPA input uses `input.pkg` not `input.package`**: `package` is reserved in Rego v1.

**Evidence keyed by commit SHA + timestamp**: sealed with SHA-256 chain.

**Operating modes**: `monitor` (log only) and `advise` (PR comment + build UNSTABLE on reject).

**Scanner disagreement**: highest severity wins during dedup in `core/normalizer.py`.

**Plugin dependency graph**: plugins declare `depends_on` for topological execution order.

## Scanner Exclusions — Fixture Dirs

`tests/e2e/fixtures/` contains intentionally pinned old dependencies used as scan-target inputs for e2e tests. These are **not** eedom's own deps — never update them via Dependabot or fix their CVEs.

**Centralized exclusion source of truth:** `config/scan-exclusions.toml`

All scanner exclusion configs are generated from this file:

```bash
uv run scripts/sync_scan_exclusions.py   # regenerate after editing
```

What the script manages:
- `tests/e2e/fixtures/*/osv-scanner.toml` — `[[PackageOverrides]] ignore = true` for standalone CLI runs
- Validates `dependabot.yml` `exclude-paths` covers all fixture roots

**Runtime exclusion:** `OsvScanner` passes `--experimental-exclude=<path>` per entry in `EedomSettings.osv_exclude_paths` (default: `["tests/e2e/fixtures"]`). Override via `EEDOM_OSV_EXCLUDE_PATHS` env var.

**Rule:** If you add a new fixture directory, add it to `config/scan-exclusions.toml` and run the sync script. Do NOT manually edit the generated `osv-scanner.toml` files.

## File Enumeration

**One seam decides which files get scanned:** `core/file_source.py` (`FileSourcePort`, registry `FILE_SOURCES`). Two adapters back it:

- `GitLsFilesSource` (`"git"`) — `git ls-files --cached --others --exclude-standard` (tracked + untracked-not-`.gitignore`d), with `-c safe.directory=<root>` so git engages on read-only CI mounts owned by another uid.
- `WalkFileSource` (`"walk"`) — `os.walk` + `core/ignore.py`, the fail-open fallback for non-git targets.

`select_file_source(root, prefer=...)` picks git when the root is a usable repo and falls back to walk; override with `EEDOM_FILE_SOURCE=auto|git|walk` (or `EedomSettings.file_source`). Both adapters apply the eedom exclusion layer (`core/ignore.py`) on top, so tracked-but-not-ours paths (fixtures) are skipped regardless of source.

**Rule:** Consumers (CLI, scanner, plugins) enumerate via the resolved source — never call `rglob`/`os.walk`/`git` directly. `core/ignore.py` `DEFAULT_PATTERNS` and `file_source._ALWAYS_SKIP_DIRS` are the shared exclusion constants (`manifest_discovery` imports the latter).

## OPA Policy

8 rules in `policies/policy.rego`. Critical/high vulns deny. Forbidden licenses deny. Package age < 30 days denies. Malicious packages deny. Critical/high supply-chain version-bump signals deny. Medium vulns warn. High transitive dep count warns. Medium supply-chain signals warn.

## Dev Ports

Port range 12000-13000 only. Never use common ports.
- PostgreSQL: 12432

## Testing

Every source file has a `# tested-by: tests/unit/test_X.py` comment. TDD red-green is mandatory. Hypothesis property-based tests cover boundary invariants.

**Tests run in containers only.** Use `make test`. Never use `EEDOM_ALLOW_HOST_TESTS=1` — host environment can't guarantee parity with CI or other contributors.

### Split TDD Across Agents (Context Poisoning Prevention)

When using subagents for implementation, split RED and GREEN across two separate agents:

1. **Agent 1 (RED):** writes failing tests from the acceptance criteria. Commits. Confirms tests fail.
2. **Agent 2 (GREEN):** reads the failing tests, implements the minimum code to pass them. Runs full suite.

The test agent never sees the implementation. The code agent never writes its own tests. This prevents context poisoning — where an agent writes tests that match its planned implementation rather than tests that verify behavior.

### Property-Based Testing (DPS-12)

Code at security, cryptographic, state, or trust boundaries requires formal property domain mapping. Each test maps to a named domain and formal property type: SAFETY (bad thing never happens), LIVENESS (good thing eventually happens), INVARIANT (always true), PERFORMANCE (within bounds).

**Core domains** (security/crypto):

| Domain | Type | Property |
|--------|------|----------|
| Integrity | SAFETY | Tampering never succeeds |
| Confidentiality | SAFETY | Secrets never leak to output |
| Determinism | INVARIANT | Same inputs → same output |
| Uniqueness | INVARIANT | Different inputs → different outputs |
| Availability | LIVENESS | Valid operations eventually succeed |

**Stateful domains** (state machines, workflows, pipelines):

| Domain | Type | Property |
|--------|------|----------|
| Non-repudiation | INVARIANT | Proof of action always exists once created |
| Idempotency | INVARIANT | Repeat always produces same result |
| Atomicity | SAFETY | Partial state never visible |
| Monotonicity | SAFETY | State never moves backward |

**System domains** (concurrency, resources, lifecycle):

| Domain | Type | Property |
|--------|------|----------|
| Ordering | SAFETY | Out-of-sequence never happens |
| Isolation | SAFETY | Parallel ops never interfere |
| Boundedness | PERFORMANCE | Resources stay within finite limits |
| Linearity | SAFETY | Token/resource never consumed twice |
| Reversibility | LIVENESS | Failed operations eventually clean up |

Not every module needs all 14. Pick the domains that match your boundary. Group property tests in a `TestProperties` class. If you can't state the domain and property type, the test is incomplete.

## Capability Matrix

`docs/CAPABILITIES.md` is the canonical feature inventory — optimized for LLM ingestion and human comparison. **Update it whenever you add, remove, or modify**: a plugin, semgrep rule, code graph check, OPA policy rule, CLI command, output format, or integration. Keep counts accurate. Update the LAST VERIFIED date.

## Commit Message Discipline

release-please uses conventional commit prefixes for semver bumps. Be conservative:

- `feat:` → **minor** bump (0.x.0) — new user-facing capabilities only
- `fix:` → **patch** bump (0.0.x) — bug fixes, config fixes, CI fixes, behavior corrections
- `chore:` → **no bump** — docs, refactors, test-only changes, housekeeping, dependency updates

Do NOT use `feat:` for config tweaks, CI fixes, or internal refactors. If it doesn't change what a user sees or does, it's `fix:` or `chore:`.

## Code Conventions

- structlog for logging, never print()
- Enums for all state fields, never raw strings
- Typed Pydantic models at every boundary
- `# tested-by:` annotation on every source file

## GATEKEEPER Copilot Agent

The `agent/` module is a presentation-tier entry point parallel to `cli/`. It wraps the same pipeline as a GitHub Copilot Extension for reactive PR review.

- Entry point: `python -m eedom.agent.main`
- Config: `GATEKEEPER_*` env vars
- Tools: `evaluate_change`, `check_package`, `scan_code`
- ADRs: `docs/adr/001-004`
