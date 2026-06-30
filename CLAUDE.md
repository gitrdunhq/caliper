# CLAUDE.md

This file provides guidance to Claude Code when working with the caliper scanner.

## What This Is

Caliper — fully deterministic dependency and code review for CI. 19 scanner plugins (+ OPA policy plugin), 21 deterministic detectors, 61 custom semgrep rules, 12 code graph checks, 8 OPA policy rules, 600+ tests, zero LLM in the decision path.

## Commands

```bash
uv sync --group dev                    # Install all deps
make test                              # Run tests in container (podman/docker)
make test-host                         # Run tests on host (escape hatch)
uv run ruff check src/ tests/          # Lint
uv run black src/ tests/               # Format
make quality-check                     # Format + lint
make dogfood                           # Self-scan with caliper review
make preflight                         # Format + lint + test + dogfood
opa test policies/                     # OPA Rego policy tests
```

**Tests MUST run in a container.** `make test` handles this automatically. Never use `CALIPER_ALLOW_HOST_TESTS=1`.

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

**Running caliper from the container:**
```bash
cal                          # scan current directory (alias in .zshrc)
cal ../openoats              # scan another repo
cal ../openoats sarif        # SARIF output format

# Or manually:
podman run --rm --platform linux/amd64 \
  -v /path/to/repo:/workspace:ro \
  -v /path/to/repo/.temp:/workspace/.temp \
  caliper:latest review --repo-path /workspace --all
```

**Key paths inside container:**

| Path | Purpose |
|------|---------|
| `/opt/caliper/.venv/bin/python` | Python with all deps |
| `/opt/test-venv/bin/python` | Test image Python (use for pytest) |
| `/workspace/` | Repo mount point |
| `/usr/local/bin/entrypoint.sh` | Verifies binary checksums before running |

**Rebuilding after code changes:** Always use `bash scripts/build.sh`. The old `podman build -t caliper:latest .` command will fail on Mac.

**x86 build host (sambou@192.168.0.210):** For Docker builds, GHCR pushes, and CI runner. Has the buildx builder pre-configured.

## Architecture

Three-tier — imports flow downward only (cli -> core -> data):

- `src/caliper/cli/` — thin CLI adapter. Parses args, delegates to core, formats output.
- `src/caliper/core/` — all business logic. Pipeline, policy, plugin registry, renderer, SARIF, config, scribe seam.
- `src/caliper/data/` — persistence and external calls. Scanners, DB, evidence, parquet, PyPI client.
- `src/caliper/plugins/` — 19 scanner plugins (+ OPA policy plugin) with auto-discovery via `PluginRegistry`.
- `src/caliper/plugins/scribes/` — code-graph + opt-in semgrep finding scribes (ADR-006).
- `src/caliper/detectors/` — 21 deterministic AST bug detectors (CAL-001..021), exposed as a `DeterministicScanner`. See `docs/detectors.md`.
- `src/caliper/composition/` — composition root: `bootstrap()` wires adapters/scribes into an `ApplicationContext` (NullRepository fallback when no DB).
- `src/caliper/webhook/` — Starlette ASGI webhook server (GitHub PR events, HMAC-SHA256, port 12800).
- `src/caliper/agent/` — Foreman Copilot Agent (second presentation-tier entry point).
- `src/caliper/templates/` — Jinja2 templates for PR comment rendering.

**Detect-then-scribe (ADR-006)**: a post-detection, pre-policy pass decorates every finding's `metadata['scribe']` with deterministic context (enclosing symbol, blast-radius callers, nearby semgrep matches). Sequential, fail-open, time-bounded (`scribe_timeout`), verdict-independent. Registry: `SCRIBES` in `core/registries.py`.

## Critical Design Rules

**Fail-open**: No scanner failure blocks a build. Every external call has a timeout. Every failure returns a typed result.

**Timeouts**: scanner=60s, combined=180s, OPA=10s, LLM=30s, scribe=30s, pipeline=300s. All from config.

**OPA input uses `input.pkg` not `input.package`**: `package` is reserved in Rego v1.

**Evidence keyed by commit SHA + timestamp**: sealed with SHA-256 chain.

**Operating modes**: `monitor` (log only) and `advise` (PR comment + build UNSTABLE on reject).

**Scanner disagreement**: highest severity wins during dedup in `core/normalizer.py`.

**Plugin dependency graph**: plugins declare `depends_on` for topological execution order.

## Scanner Exclusions — Fixture Dirs

`tests/e2e/fixtures/` contains intentionally pinned old dependencies used as scan-target inputs for e2e tests. These are **not** caliper's own deps — never update them via Dependabot or fix their CVEs.

**Centralized exclusion source of truth:** `config/scan-exclusions.toml`

All scanner exclusion configs are generated from this file:

```bash
uv run scripts/sync_scan_exclusions.py   # regenerate after editing
```

What the script manages:
- `tests/e2e/fixtures/*/osv-scanner.toml` — `[[PackageOverrides]] ignore = true` for standalone CLI runs
- Validates `dependabot.yml` `exclude-paths` covers all fixture roots

**Runtime exclusion:** `OsvScanner` passes `--experimental-exclude=<path>` per entry in `CaliperSettings.osv_exclude_paths` (default: `["tests/e2e/fixtures"]`). Override via `CALIPER_OSV_EXCLUDE_PATHS` env var.

**Rule:** If you add a new fixture directory, add it to `config/scan-exclusions.toml` and run the sync script. Do NOT manually edit the generated `osv-scanner.toml` files.

## File Enumeration

**One seam decides which files get scanned:** `core/file_source.py` (`FileSourcePort`, registry `FILE_SOURCES`). Two adapters back it:

- `GitLsFilesSource` (`"git"`) — `git ls-files --cached --others --exclude-standard` (tracked + untracked-not-`.gitignore`d), with `-c safe.directory=<root>` so git engages on read-only CI mounts owned by another uid.
- `WalkFileSource` (`"walk"`) — `os.walk` + `core/ignore.py`, the fail-open fallback for non-git targets.

`select_file_source(root, prefer=...)` picks git when the root is a usable repo and falls back to walk; override with `CALIPER_FILE_SOURCE=auto|git|walk` (or `CaliperSettings.file_source`). Both adapters apply the caliper exclusion layer (`core/ignore.py`) on top, so tracked-but-not-ours paths (fixtures) are skipped regardless of source.

**Rule:** Consumers (CLI, scanner, plugins) enumerate via the resolved source — never call `rglob`/`os.walk`/`git` directly. `core/ignore.py` `DEFAULT_PATTERNS` and `file_source._ALWAYS_SKIP_DIRS` are the shared exclusion constants (`manifest_discovery` imports the latter).

## OPA Policy

8 rules in `policies/policy.rego`. Critical/high vulns deny. Forbidden licenses deny. Package age < 30 days denies. Malicious packages deny. Critical/high supply-chain version-bump signals deny. Medium vulns warn. High transitive dep count warns. Medium supply-chain signals warn.

## Parting Taxonomy & Reclassify Sidecar

`caliper part` classifies each file into a two-axis taxonomy: architectural code
tiers (`frontend`/`business`/`data`/`infra`) + non-code intent buckets
(`documentation`/`supply_chain`/`ci_cd`/`security_policy`/`config`/`schema_contracts`/`test`),
with `logic` as the honest **untiered residual** (code we couldn't tier — a human
should label it), plus the structural facts `move`/`delete`/`binary`/`generated`.
`_classify` precedence (`core/part_stock.py`): structural facts first (never
overridable) → **override table** → ordered glob heuristics (`_GLOB_PRECEDENCE`,
most-specific-first) → `logic`. `_BUCKET_ORDER` in `core/parting.py` MUST contain
every `ChangeType` or `part()` KeyErrors.

**Bucket grouping rules** (`core/parting.py` `_part_bucket`): `generated`/`binary`
(`_ISOLATED_BUCKETS`) collapse into one part and are never cap-checked (always
`oversized=False`). `documentation` (`_GROUPED_BUCKETS`) also collapses into one
part — a reviewer reads docs as a single unit — but stays cap-exempt with an honest
`oversized=True` when the grouped size exceeds the cap. Every other bucket accretes
by the size cap (R4).

**Override table** (`parting.overrides` in `.caliper.yaml`): a version-controlled
`OverrideRule {glob, bucket, note}` list. First matching glob wins; duplicate globs
and structural buckets are rejected at load. It is hashed into `config_digest`, so
an override is provenance-tracked. This is the one human decision point in the
otherwise deterministic classifier — no ML.

**`caliper part --serve [--port N]`** (`cli/part_serve.py`): a loopback sidecar
(127.0.0.1:12700) serving the live cut report. A reviewer reclassifies a file from
the browser → `write_override` appends/updates a `parting.overrides` entry and
re-parts. starlette is imported lazily (caliper[copilot] extra) so the pure
`write_override` stays importable/tested without it. Browser gate: `scripts/screenshots.ts`.

**PR input** (`caliper part --pr <url|number>`, `cli/part_pr.py`): feed a GitHub PR
URL or bare number instead of `--base/--head`. Pure parse in the functional core
(`core/pr_ref.py` `parse_pr_ref` → typed `PrRef`); the imperative shell
(`cli/part_pr.py` `resolve_pr`, all git/gh/jj IO through the `ToolRunnerPort` seam)
always clones the PR into `.temp/part-pr/<repo>-pr<N>/` — never the user's repo —
neutralizes jj immutability in that throwaway clone (a pushed PR's commits are
immutable; the gate would otherwise refuse), and resolves `base = merge-base(base,
head)`. Self-healing: a stale clone is wiped to a clean slate at the start of every
run and a partial clone is removed on failure (`_safe_rmtree`, containment-checked),
so a crashed run never poisons the next. Mutually exclusive with `--base/--head`.

**Advisory commit describer** (`--describe/--no-describe`, `--describe-model`): an
optional pass that names each commit subject with a local OpenAI-compatible model
(Ollama/OMLX/llama.cpp, resolved from `CALIPER_DESCRIBER_MODEL` + a base URL via
`cli/part_describe.py`). The model writes ONLY the prose tail; caliper prepends the
deterministic `type(scope): ` prefix (`core/part_script.py:_peel_prefix`, the half
release-please reads for semver), so format-leakage is structurally impossible.
Functional-core/imperative-shell: the network call lives in the shell
(`data/openai_describer.py`, the only network code, fail-soft → `None` → deterministic
fallback), and the pure `render_restack_script` takes a plain `{part.id: subject}`
map. Describer config is env/CLI-driven and deliberately OUTSIDE `PartingConfig`, so
it never enters `config_digest` — the cut, classification, and provenance stay 100%
deterministic and LLM-free. `core/commit_describer.py` `normalize_subject` strips any
echoed prefix/quotes and enforces the 72-char cap at the boundary (DPS-102).

## Dev Ports

Port range 12000-13000 only. Never use common ports.
- PostgreSQL: 12432
- `caliper part --serve` sidecar: 12700 (loopback only)
- Webhook server: 12800

## Testing

Every source file has a `# tested-by: tests/unit/test_X.py` comment. TDD red-green is mandatory. Hypothesis property-based tests cover boundary invariants.

**Tests run in containers only.** Use `make test`. Never use `CALIPER_ALLOW_HOST_TESTS=1` — host environment can't guarantee parity with CI or other contributors.

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

## Foreman Copilot Agent

The `agent/` module is a presentation-tier entry point parallel to `cli/`. It wraps the same pipeline as a GitHub Copilot Extension for reactive PR review.

- Entry point: `python -m caliper.agent.main`
- Config: `FOREMAN_*` env vars
- Tools: `evaluate_change`, `check_package`, `scan_code`
- ADRs: `docs/adr/001-004`
