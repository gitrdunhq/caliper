# CLAUDE.md

This file provides guidance to Claude Code when working with the caliper scanner.

## What This Is

Caliper — fully deterministic dependency and code review for CI. 19 scanner plugins (+ OPA policy plugin), 21 deterministic detectors, 61 custom semgrep rules, 12 code graph checks, 10 OPA policy rules, 600+ tests, zero LLM in the decision path.

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
opa test policies/ --ignore '*.yaml' --ignore '*.yml'  # OPA Rego policy tests (--ignore skips semgrep/swiftlint config YAML)
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

10 rules in `policies/policy.rego`. Critical/high vulns deny. Forbidden licenses deny. Package age < 30 days denies. Malicious packages deny (never dev-scope-exempted). Critical/high supply-chain version-bump signals deny. Medium vulns warn. High transitive dep count warns. Medium supply-chain signals warn. Dev-scope exemption (`rules_enabled.dev_scope_exemption`, default off): downgrades the critical/high-vuln and forbidden-license deny rules to warn for `pkg.scope == "dev"` packages.

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

**Size cap is opt-in** (`PartingConfig.size_cap: int | None`, default `None`): the
default cut is **one commit per labelled bucket** — the split is along buckets of
concern, never chopped by line count. A reviewer who wants finer parts sets
`--size-cap N` (or `parting.size_cap`); only then does the R4 within-bucket
accretion split a bucket once its accumulated size exceeds `N`. With no cap a
non-isolated bucket is always a single part with `oversized=False`.

**Bucket grouping rules** (`core/parting.py` `_part_bucket`): `generated`/`binary`
(`_ISOLATED_BUCKETS`) collapse into one part and are never cap-checked (always
`oversized=False`). `documentation` (`_GROUPED_BUCKETS`) also collapses into one
part — a reviewer reads docs as a single unit — cap-exempt but, when a cap is set,
honestly `oversized=True` if the grouped size exceeds it. Every other bucket is one
part by default and accretes by the size cap (R4) only when a cap is set.

**Override table** (`parting.overrides` in `.caliper.yaml`): a version-controlled
`OverrideRule {glob, bucket, note}` list. First matching glob wins; duplicate globs
and structural buckets are rejected at load. It is hashed into `config_digest`, so
an override is provenance-tracked. This is the one human decision point in the
otherwise deterministic classifier — no ML.

**`caliper part --serve [--port N]`** (`cli/part_serve.py`): a loopback sidecar
(127.0.0.1:12700) serving a full **TypeScript SPA** with CLI/web parity — not just
the cut report. `--base/--head` is optional at launch; an untargeted session shows
a targeting prompt (`POST /range` for a literal base/head, `POST /pr` to resolve a
GitHub PR URL/number via the same `cli/part_pr.py` seam the CLI uses). A reviewer
reclassifies a file from the browser → `write_override` appends/updates a
`parting.overrides` entry and re-parts; live `size_cap`/`target` settings
(`POST /repart`), bulk suggestion accept (`POST /suggest/apply`), and a
client-side `--explain` viewer for a loaded `cutlist.json` round out CLI parity.
The transport is **stdlib `http.server` only** — no uvicorn/starlette, so it runs
from any install (no `caliper[copilot]` extra). Routing is the pure
`dispatch(session, method, path, body)` (functional core), tested without binding a
socket; the `BaseHTTPRequestHandler` is the thin shell.

**Optional read-only LAN view** (`--lan <ip> --cert <path> --key <path>`): binds a
**second**, TLS-wrapped server (mkcert-issued cert/key) on a LAN-routable
host/IP, on a separate port (`12701` by default). Its handler
(`_make_readonly_handler`) implements only `do_GET` — `BaseHTTPRequestHandler`
answers any other verb with a bare 501, so every mutating route (`/reclassify`,
`/repart`, `/range`, `/pr`, `/suggest/apply`, `/restack`, `/apply`, `/rollback` —
all POST-only in `dispatch`) is structurally unreachable from the LAN server. The
primary server keeps binding `127.0.0.1` unchanged; both share one
`PartingSession`. All three flags are required together (`serve_part` and the CLI
both validate this).

`PartingSession` holds all
mutable state (target, settings, last generated run, one-shot apply token) behind
a single `RLock`. Browser gate: `scripts/screenshots.ts`.

**`core/part_pipeline.run_part`**: the single orchestrator both `cli/part_cmd.py`
and `cli/part_serve.py` call — `run_gate` → cut (+ pin `resolved_revsets` into
provenance) → suggest (optional apply, which re-cuts) → `probe_path_capability` →
`describe_parts` → `render_restack_script` → write `restack.sh` (0755) +
`cutlist.json` when `out_dir` is set. Returns a typed `PartRunResult` (cutlist,
script text, backup bookmark, rescue op id, jj version, subjects, applied/proposed
overrides, artifact paths). Extracting this out of `part_cmd.py` means the CLI and
the sidecar can never drift on gate→cut→describe→render ordering —
`tests/integration/test_part_e2e.py` guards the CLI side, `tests/unit/
test_part_pipeline.py` (fake `ToolRunnerPort`) guards the pipeline itself.

**Execute + rollback (`POST /restack`, `POST /apply`, `POST /rollback`)** — the one
capability beyond the CLI: `/restack` runs `run_part` and mints a fresh one-shot
CSRF token (`secrets.token_urlsafe(16)`) alongside the rollback header and
downloadable `restack.sh`/`cutlist.json`. `/apply` requires that token
(`hmac.compare_digest`, consumed on first use — replay is rejected) and rejects any
request whose `Origin`/`Host` is not loopback (`_is_loopback_request`/
`_hostname_of`), then runs `bash <restack_path>` for real via `ToolRunnerPort`
(`cwd=repo_path`, 300s timeout) — `restack_path` is resolved to an absolute path
first, since a relative `--out` is rooted at the server's invocation cwd, not
`repo_path`. `/rollback` (no token needed — pure escape hatch) runs
`jj op restore <rescue_op_id>` to undo it. The SPA gates `/apply` behind an in-page
confirm modal that echoes the backup bookmark before firing.

**Frontend build (`scripts/part_ui/`)**: `types.ts` (boundary model mirrors,
bucket list drift-guarded against `_SELECTABLE_BUCKETS`), `api.ts` (one typed
fetch per endpoint), `app.ts` (render + `data-action`-driven event wiring, no
framework), `styles.css` (the `modern-css` skill conventions — `@layer`,
`oklch()`/`color-mix()`, logical properties, `@scope`, `:has()`, `subgrid`,
`prefers-reduced-motion`-gated animation). `build.ts` runs esbuild
(`bundle`/`minify`/`iife`/`es2022`) into the **committed** bundle
`src/caliper/cli/part_ui_dist/{index.html,part_ui.js,part_ui.css}` — package data
(`pyproject.toml` `[tool.hatch.build.targets.wheel] artifacts`), so a built wheel
serves the SPA with **zero Node at runtime**. `make part-ui`
(`scripts/build_part_ui.sh`) type-checks and rebuilds the bundle from
`scripts/part_ui/**`; rerun it (and recommit the bundle) whenever that directory
changes — nothing rebuilds it automatically.

**PR input** (`caliper part --pr <url|number>`, `cli/part_pr.py`): feed a GitHub PR
URL or bare number instead of `--base/--head`. Pure parse in the functional core
(`core/pr_ref.py` `parse_pr_ref` → typed `PrRef`); the imperative shell
(`cli/part_pr.py` `resolve_pr`, all git/gh/jj IO through the `ToolRunnerPort` seam)
always clones the PR into a **centralized, repo-independent workdir** — never the
user's repo — keyed by `<owner>-<repo>-pr<N>` (`PrRef.workdir_slug`, owner-keyed so
two repos sharing a name never collide). The workdir root is XDG-resolved by
`default_part_workdir()`: `CALIPER_STATE_DIR` wins, else
`$XDG_CONFIG_HOME/caliper/state/part-pr`, else `~/.config/caliper/state/part-pr` —
so the throwaway clone and the durable override sidecar live outside any checkout's
`.temp/` and survive `git clean`, repo deletion, and re-clone. It neutralizes jj
immutability in that throwaway clone (a pushed PR's commits are immutable; the gate
would otherwise refuse), and resolves `base = merge-base(base, head)`. Self-healing:
a stale clone is wiped to a clean slate at the start of every run and a partial
clone is removed on failure (`_safe_rmtree`, containment-checked), so a crashed run
never poisons the next. Mutually exclusive with `--base/--head`.

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

**Advisory tier suggester** (`--suggest/--no-suggest`, `--suggest-model`,
`--suggest-apply`): an optional "Sorting Hat" pass that asks a local
OpenAI-compatible model to propose `parting.overrides` globs for the untiered
`logic` residual — the code caliper honestly refused to tier. The model is OFF the
decision path (scanners/OPA/detectors are the decision path) and only ever authors
glob strings; the deterministic boundary decides what survives. Functional-core/
imperative-shell: `core/tier_suggester.py` is the pure boundary — `SELECTABLE_TIERS`
(every `ChangeType` tier except structural facts and `logic`), the typed
request/rule, `TierSuggesterPort`/`NullSuggester`, and `validate_suggestions` with
the **subset guard** (a suggested glob may only tier files that are *currently*
`logic`, never steal an already-tiered one), dedupe, existing-glob drop, and a
25-rule cap. `data/openai_suggester.py` is the only network code (fail-soft → `[]`
on any transport/parse error; pins the legal bucket enum into the system prompt;
tolerates ``` fences). `cli/part_suggest.py` is the env-driven edge
(`suggester_from_env` falls back to `CALIPER_DESCRIBER_MODEL` + the shared base URL;
`suggest_overrides` pulls residual/tiered straight from the cut). Suggester config
is env/CLI-driven and deliberately OUTSIDE `PartingConfig`, so it never enters
`config_digest` — only the globs a human accepts into `.caliper.yaml` change
provenance. Under `--serve`, a "✨ suggest tiers" button (`POST /suggest`) renders
each proposal as an accept chip that reuses `/reclassify`. Print-only by default;
`--suggest-apply` writes the accepted globs and re-parts.

## Dev Ports

Port range 12000-13000 only. Never use common ports.
- PostgreSQL: 12432
- `caliper part --serve` sidecar: 12700 (loopback only by default)
- `caliper part --serve --lan` optional read-only LAN view: 12701 (TLS, mkcert-issued cert/key required; mutating routes stay loopback-only)
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
