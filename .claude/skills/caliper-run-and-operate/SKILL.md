---
name: caliper-run-and-operate
description: >-
  How to actually RUN caliper day-to-day: the `caliper` Click CLI command
  anatomy (review, part, reinstall, audit, baseline, eval, gauge, inspect,
  plugins, healthcheck, check-health), container-based scans via
  scripts/scan.sh (the "cal"-alias pattern), the Foreman Copilot Agent
  (`python -m caliper.agent.main`, FOREMAN_* env vars, its six tools), the
  webhook server (Starlette ASGI, GitHub PR events, HMAC-SHA256, port 12800),
  output formats (markdown/sarif/json/vex-OpenVEX) and where artifacts land
  (evidence/, .caliper/reports/), and the 12000-13000 dev port convention.
  Load before invoking any `caliper` subcommand, before writing a shell
  alias/script that wraps a container scan, before setting FOREMAN_* or
  CALIPER_WEBHOOK_* env vars, before picking an --output/--format flag, or
  before claiming a new local dev port. Do NOT load for: build/rebuild of the
  container image itself (see caliper-build-and-env), the full CALIPER_*
  config surface and .caliper.yaml schema (see caliper-config-and-flags), tier
  boundaries and import rules (see caliper-architecture-contract), writing a
  new scanner plugin (see caliper-plugin-authoring-playbook /
  caliper-plugin-architecture), or OPA policy rule semantics (see
  caliper-opa-policy-playbook).
---

# Caliper: Run and Operate

This skill is the runbook for the four ways a human or an agent actually
invokes caliper: the CLI, a container scan, the Foreman agent, and the
webhook server. Every command below was run against this repo on
2026-07-02 — commands and output tables are the actual observed output, not
guesses at `--help` text.

**Jargon, defined once:**
- **Native run** — `uv run caliper ...` executing directly on the host, using
  whatever scanner binaries are on `$PATH`.
- **Container run** — `podman run ... caliper:latest review ...` — the image
  ships every scanner binary pinned and checksum-verified, so it's the mode
  that has parity with CI.
- **Foreman** — the informal name for the Copilot Agent (`agent/` module);
  "Foreman" only appears in config prefixes (`FOREMAN_*`) and log lines, the
  package itself is `caliper.agent`.
- **Fail-open** — a failing scanner/DB/LLM call never blocks the build; it
  degrades to a typed empty/error result and the pipeline continues. See
  `caliper-fail-open-resilience` for the mechanics; this skill just shows you
  where you'll observe it (e.g. `check-health` below exits 0 even with a
  failed check).

## When to use this skill vs. sibling

| You're about to... | Use this skill? | Otherwise use |
|---|---|---|
| Run `caliper review`/`part`/`reinstall`/etc. and need the flag anatomy | Yes | — |
| Write/adjust a container-scan wrapper alias | Yes | — |
| Wire up Foreman on a new repo (FOREMAN_* env vars, tools) | Yes | — |
| Stand up the webhook server, understand its auth/routing | Yes | — |
| Pick `--format` and figure out where the file lands | Yes | — |
| Claim a new local dev port | Yes | — |
| Build/rebuild the container image itself | No | `caliper-build-and-env` |
| Full `.caliper.yaml` schema, every `CALIPER_*` env var | No | `caliper-config-and-flags` |
| Tier boundaries (`core/` vs `data/` vs presentation imports) | No | `caliper-architecture-contract` |
| Write a new scanner plugin or detector | No | `caliper-plugin-authoring-playbook` / `caliper-plugin-architecture` |
| OPA rule semantics, `rules_enabled` toggles | No | `caliper-opa-policy-playbook` |
| Debug a scanner crash / timeout in production | No | `caliper-debugging-playbook` |

## 1. The CLI — command anatomy

`caliper` is a `click.group()` (`src/caliper/cli/main.py`); every subcommand
below is `cli.add_command(...)`'d there or in its own `cli/*_cmd.py` module.
Full list, confirmed via `uv run caliper --help` (2026-07-02, version
`0.2.27`):

| Command | Does | Module |
|---|---|---|
| `review` | Run plugin review on a repo/diff/folder. **The one you'll use most.** | `cli/review_cmd.py` |
| `evaluate` | Full policy-decision pipeline (OPA verdict, evidence write) on a diff | `cli/main.py` |
| `part` | Cut a diff into an ordered, reviewable commit sequence (`jj` restack script) | `cli/part_cmd.py` |
| `inspect` | Review the parts of a cut list, write per-part LLM-assisted notes | `cli/inspect_cmd.py` |
| `reinstall` | Rebuild + reinstall caliper from local source with a fresh dev build id | `cli/reinstall_cmd.py` |
| `audit` | Holistic trust audit via LLM, concern-by-concern (Alley-Oop) | `cli/main.py` |
| `baseline` | Manage the finding-suppression baseline | `cli/baseline_cmd.py` |
| `eval` | Score the reviewer against a labeled corpus | `cli/eval_cmd.py` |
| `gauge` | The advisory-claim flywheel (propose/backtest/promote/status) | `cli/gauge_cmd.py` |
| `ground` | Deterministic grounding bundle (separate from `review`) | `cli/main.py` |
| `query` | Natural-language question over the code graph | `cli/query_cmd.py` |
| `plugins` | List all registered plugins (table you saw above minus the OPA plugin) | `cli/main.py` |
| `schema` | Print JSON Schema for `caliper review --format json` | `cli/main.py` |
| `supply-chain-diff` | Threat-analyze a dependency version bump | `cli/main.py` |
| `healthcheck` | Are the scanner **binaries** available? | `cli/main.py` |
| `check-health` | Are scanner binaries available **and** is the DB reachable? | `cli/main.py` |

`review` vs `evaluate`: `review` runs the 19 plugins and renders a report
(markdown/sarif/json/vex) — no OPA verdict, no evidence write. `evaluate`
runs the full decision pipeline (OPA policy, evidence sealing under
`evidence/`) and is what CI/Foreman actually gate on. If you just want "what
does caliper see in this diff", use `review`. Deep flag/env semantics for
either are `caliper-config-and-flags` territory — this section is command
shape, not the exhaustive option reference.

### `caliper review` — the day-to-day command

```
Usage: caliper review [OPTIONS]

Options:
  --scope [repo|diff|folder]      Scan scope: repo (full), diff (changed files
                                   only), folder (single directory).
  --diff TEXT                     Path to diff file.
  --repo-path PATH                Repository root.
  --scanners TEXT                 Comma-separated plugin names.
  --category TEXT                 Comma-separated categories.
  --all                           Run all plugins.
  --output PATH                   Write output to file.
  --format [markdown|sarif|json|vex]
                                   Output format.
  --sarif-max-findings INTEGER    Max findings per plugin in SARIF output. 0
                                   for no limit.
  --pr-url TEXT                   PR URL for comment header.
  --pr-num INTEGER                PR number.
  --title TEXT                    PR title.
  --watch                         Watch for file changes and re-run review
                                   (debounced 500 ms).
  --disable TEXT                  Comma-separated plugin names to disable.
  --enable TEXT                   Comma-separated plugin names to
                                   force-enable (overrides --disable).
  --package PATH                  Scan only this package directory.
  --pr INTEGER RANGE              Post findings as inline PR review comments
                                   via GitHub API. Requires gh CLI.  [x>=1]
  --repo TEXT                     GitHub repo (owner/name) for --pr mode.
                                   Auto-detected if omitted.
```
(verbatim `uv run caliper review --help` output, 2026-07-02)

```bash
# from repo root — most common invocation, full repo, all plugins, markdown to stdout
uv run caliper review --repo-path . --all

# just the quality-category plugins (cpd, complexity, ls-lint, blast-radius, typos), JSON, to a file
uv run caliper review --repo-path . --category quality --format json --output /tmp-unused-example.json

# post findings as inline PR review comments (requires gh CLI authenticated)
uv run caliper review --repo-path . --all --pr 42
```

Real observed JSON output shape (`--category quality --format json`, this
repo, 2026-07-02 — trimmed):

```json
{
  "schema_version": "1.0",
  "timestamp": "2026-07-02T23:48:10.858501+00:00",
  "repo": ".",
  "verdict": "clear",
  "security_score": 100.0,
  "quality_score": 100.0,
  "error_count": 0,
  "total_findings": 6106,
  "total_plugins": 3,
  "plugins": [
    {"name": "complexity", "category": "quality", "status": "ran", "findings_count": 6090, "findings": [...] }
  ]
}
```

### `caliper reinstall` — rebuild + reinstall from local source (dev loop)

```
Usage: caliper reinstall [OPTIONS]

Options:
  --repo PATH  Caliper checkout to rebuild from (default: the git repo of the
               current directory).
```

Solves a real `uv tool` gotcha: `uv` caches built wheels by `(name,
version)`, so an unchanged static version can silently serve a **stale**
wheel after `--reinstall`. `caliper reinstall` bumps a `+dev` build-id
segment to bust that cache, then delegates to `scripts/install-local.sh` (a
single source of truth shared with any manual invocation). It resolves the
repo root via `git rev-parse --show-toplevel` (or `--repo`) and validates
`[project].name == "caliper"` in `pyproject.toml` before touching anything —
so running it from the wrong directory fails closed instead of rebuilding an
unrelated project.

```bash
uv run caliper reinstall            # from inside a caliper checkout
uv run caliper reinstall --repo ~/repos/caliper   # from anywhere else
```

### `caliper part` — operational surface only

`part` cuts a diff into an ordered, reviewable commit sequence. The
classification taxonomy, override table, and suggester internals are
CLAUDE.md § "Parting Taxonomy & Reclassify Sidecar" territory, not this
skill — here's just what you invoke and what it binds:

```bash
uv run caliper part --base main --head HEAD --out .temp/part-out
uv run caliper part --base main --head HEAD --serve            # loopback sidecar, port 12700
uv run caliper part --pr https://github.com/org/repo/pull/42   # feed a PR instead of --base/--head
```

`--serve` binds `127.0.0.1:12700` by default (override `--port`); adding
`--lan <ip> --cert <path> --key <path>` also binds a **second**, TLS-wrapped,
**read-only** server on `12701` by default (`--lan-port` to override) — every
mutating route in the sidecar (`/apply`, `/reclassify`, `/repart`,
`/restack`, `/pr`, `/range`, `/suggest/apply`, `/rollback`) is POST-only, and
the LAN handler only implements `do_GET`, so those routes are structurally
unreachable from the LAN view. See § 6 below for how these ports fit the dev
port convention.

### The rest, one line each

| Command | One-line usage |
|---|---|
| `caliper plugins` | `uv run caliper plugins` — table of all registered plugins, binary status, category |
| `caliper healthcheck` | `uv run caliper healthcheck` — are scanner binaries present |
| `caliper check-health` | `uv run caliper check-health` — binaries **and** DB connectivity |
| `caliper baseline update` | `uv run caliper baseline update --repo-path . --reason "..."` — record current findings as accepted |
| `caliper query` | `uv run caliper query "which files import core.pipeline"` — NL question over the code graph |
| `caliper schema` | `uv run caliper schema` — JSON Schema for `review --format json` output |
| `caliper eval` | `uv run caliper eval --corpus-dir <dir>` — score the reviewer against a labeled corpus |

## 2. Container reviews — the "cal"-alias pattern

CLAUDE.md documents a `cal` shell alias as the day-to-day container-scan
entry point. The **committed, ground-truth implementation** of that pattern
in this repo is `scripts/scan.sh` — treat it as canonical over any
hand-rolled `podman run` one-liner; CLAUDE.md's own inline example is a
simplified illustration of the same podman invocation `scan.sh` actually
runs (with image caching, `--security-opt apparmor=unconfined`, a Trivy DB
cache mount, and crashed-container pruning that the inline example omits).

```bash
bash scripts/scan.sh /path/to/repo             # markdown, default
bash scripts/scan.sh ../openoats sarif          # SARIF format
CALIPER_IMAGE=caliper:latest bash scripts/scan.sh . # override image tag
```

To get the `cal <path> [format]` ergonomics CLAUDE.md describes, define a
shell function that forwards to the committed script — don't reinvent the
podman invocation inline, or it drifts from `scan.sh`:

```bash
# add to your shell rc
cal() {
  bash /absolute/path/to/eedom/scripts/scan.sh "$@"
}
```

Why a container run at all, when `uv run caliper review` works natively?
Parity with CI — the image pins and checksum-verifies every scanner binary
(`entrypoint.sh`, `scripts/verify-checksums.sh`), so a container run sees
exactly what the CI runner sees. A native run only sees whatever's on your
`$PATH` (see the `check-health` output in § 5 — this machine has `syft`,
`osv-scanner`, `trivy`, `scancode`, `opa` natively but not e.g. `cfn-nag`).
Building/rebuilding the image itself (`scripts/build.sh`,
`scripts/build-test.sh`) is `caliper-build-and-env` territory, not this
skill.

## 3. Foreman Copilot Agent

`src/caliper/agent/` is a **presentation-tier entry point parallel to
`cli/`** (ADR-001, `docs/adr/001-agent-module-as-separate-entry-point.md`) —
same rule as everywhere else in this repo: it may import `core/`+`data/`,
never the reverse. It wraps the same pipeline as a reactive GitHub PR
reviewer.

```bash
export FOREMAN_GITHUB_TOKEN="ghp_..."
export FOREMAN_PR_NUMBER=123
export FOREMAN_DIFF_PATH=./changes.diff     # or "-" to read the diff from stdin
export FOREMAN_REPO_OWNER=myorg
export FOREMAN_REPO_NAME=myrepo

uv run python -m caliper.agent.main
```

`FOREMAN_PR_NUMBER` is required (exits 1 if unset/`0`, `agent/main.py`
`main()`). Everything else in this block plus `FOREMAN_TEAM` (default
`"default"`) and `FOREMAN_COMMIT_SHA` (optional — only set if you want a
GitHub commit status posted) are read directly from `os.environ` at the top
of `main()`.

### `FOREMAN_*` config (`AgentSettings`, `agent/config.py`) — env-prefixed, independent of `CaliperSettings`

| Env var | Default | Meaning |
|---|---|---|
| `FOREMAN_GITHUB_TOKEN` | *(required)* | GitHub PAT — posts comments, sets commit status |
| `FOREMAN_ENFORCEMENT_MODE` | `warn` | `block` \| `warn` \| `log` — see table below |
| `FOREMAN_LLM_MODEL` | `gpt-4.1` | Model id for the agent's tool-calling session |
| `FOREMAN_MAX_COMMENT_LENGTH` | `3900` | PR comment truncation cap (GitHub has its own cap; this is caliper's) |
| `FOREMAN_REPO_PATH` | `.` | Repo root the tools operate on |
| `FOREMAN_EVIDENCE_PATH` | `./evidence` | Where the deterministic pipeline writes evidence |
| `FOREMAN_OPA_POLICY_PATH` | `./policies` | Rego policy dir |
| `FOREMAN_ENABLED_SCANNERS` | `syft,osv-scanner,trivy` | Comma-separated — decoded by a custom pydantic-settings source |
| `FOREMAN_SEMGREP_TIMEOUT` | `120` | Seconds |
| `FOREMAN_PIPELINE_TIMEOUT` | `300` | Seconds |
| `FOREMAN_DB_DSN` | `postgresql://localhost/caliper` | No real credentials in the default — set explicitly in prod. Unset/unreachable DB triggers the `NullRepository` fallback (fail-open), not a crash. |
| `FOREMAN_POLICY_VERSION` | `1.0.0` | Recorded into evidence |

### Tools (`agent/tools.py`) — six, not three

The topic brief that seeded this skill named three tools
(`evaluate_change`/`check_package`/`scan_code`); the actual module has grown
to **six** — flagging the discrepancy rather than under-documenting it:

| Tool | Signature | What it does |
|---|---|---|
| `evaluate_change` | `(diff_text, pr_url, team, repo_path) -> dict` | Runs the full deterministic pipeline on a PR diff — **the sole source of the block/warn/log decision** (ADR references issue #205: LLM narration failure never suppresses a real reject) |
| `check_package` | `(name, version, ecosystem) -> dict` | Evaluate one package in isolation — policy verdict + findings |
| `scan_code` | `(diff_text, repo_path) -> dict` | Semgrep on changed files, via `PluginRegistry` — **not** a pipeline `Scanner` (ADR-004: informational only, doesn't feed OPA) |
| `scan_duplicates` | `(diff_text, repo_path) -> dict` | CPD copy-paste detection on changed files |
| `scan_k8s` | `(diff_text, repo_path) -> dict` | kube-linter on changed K8s/Helm files |
| `analyze_complexity` | `(diff_text, repo_path) -> dict` | lizard + radon complexity on changed files |

ADR-002 (`docs/adr/002-agent-as-task-fit-llm.md`): the agent **is** the
task-fit LLM — the 8-dimension proportionality rubric is embedded in the
system prompt (`agent/prompt.py`), not called out as a separate HTTP hop.
That means the rubric text is duplicated between `core/taskfit.py` and
`agent/prompt.py` — a known, accepted maintenance cost per the ADR, not a
bug to "fix" unilaterally.

### Enforcement modes

| Mode | PR comment | Build status | Use case |
|---|---|---|---|
| `block` | Yes | **Fails** on reject | Production gate |
| `warn` | Yes | Always passes | Advisory (default) |
| `log` | No | Always passes | Silent monitoring |

The deterministic pipeline result (`has_reject`) is computed the same way in
every mode — only whether it's allowed to fail the build differs. A crashed
LLM narration session degrades to an empty narration comment; it never
flips `has_reject`.

## 4. Webhook server

`src/caliper/webhook/server.py` — Starlette ASGI app, one route:
`POST /webhook`. Production entry point:

```bash
uvicorn caliper.webhook.server:app --host 0.0.0.0 --port 12800
```

Requires `starlette` (`pip install caliper[copilot]` — import-time
`ImportError` with that exact remediation string if missing).

**Auth/routing, in order** (fail-open past this point — every later error
returns HTTP 200, logged):
1. Body `> 1 MiB` → `413` (DoS guard, checked before any HMAC work)
2. Missing `X-Hub-Signature-256` → `401`
3. `hmac.compare_digest` mismatch on HMAC-SHA256(body, secret) → `401`
4. `Content-Type` not `application/json` → `400`
5. `X-GitHub-Event` not `pull_request` → `200 {"status": "ignored"}`
6. `action` not in `{opened, synchronize, reopened}` → `200 {"status": "ignored"}`
7. Runs `review_repository()` with a 300s timeout via `asyncio.wait_for` —
   timeout or any exception degrades to a review-failed message, still
   posted as a PR comment, still `200`.

### `CALIPER_WEBHOOK_*` config (`WebhookSettings`, `webhook/config.py`)

| Env var | Default | Meaning |
|---|---|---|
| `CALIPER_WEBHOOK_SECRET` | *(required)* | HMAC-SHA256 shared secret |
| `CALIPER_WEBHOOK_GITHUB_TOKEN` | *(required)* | GitHub PAT for posting PR comments |
| `CALIPER_WEBHOOK_PORT` | `12800` | Listen port |

Note this is a **separate** entry point from Foreman — the webhook server
runs `review_repository()` directly (a coarse verdict/score comment), it
does not spin up the agent's LLM tool-calling loop. If you need the rich
per-package narration and the six tools above, that's the GitHub Action +
`python -m caliper.agent.main` path in § 3, not this server.

## 5. Output formats & where artifacts land

`--format` on `review`/`evaluate` accepts exactly four values — confirmed
against `render_review_output()` in `cli/review_cmd.py`:

| Format | Renderer | Shape |
|---|---|---|
| `markdown` (default) | `core/renderer.py` `render_comment` | Human-readable PR-comment-style report |
| `sarif` | `core/sarif.py` `to_sarif` | [SARIF](https://sarifweb.azurewebsites.net/) — also the format `--pr` posting uses internally (`sarif_to_review`) |
| `json` | `core/json_report.py` `render_json` | Typed JSON — schema printable via `caliper schema` |
| `vex` | `core/vex.py` `to_vex` | **OpenVEX** v0.2.0 document (https://openvex.dev) — vulnerability *exploitability* disposition, not general findings |

Every format: `--output <path>` writes the file and echoes a one-line
confirmation (`SARIF written to ...` / `JSON written to ...` / `VEX written
to ...` / `Review written to ... (N chars)`); omit `--output` and it goes to
stdout. `--pr <N>` short-circuits straight to SARIF-derived inline PR
comments regardless of `--format`.

### Where artifacts land, by mechanism

| Mechanism | Path | Notes |
|---|---|---|
| `caliper review --output <path>` | wherever you point it | No default — you choose |
| `caliper evaluate` (full pipeline) | `evidence/{sha}/{timestamp}/{package}/decision.json`, `memo.md`, `seal.json`; `evidence/decisions.parquet` | SHA-256 seal chain, atomic writes (temp→fsync→rename), 27-column Parquet lake |
| `make dogfood` / `scripts/dogfood.sh` | `.caliper/reports/dogfood-report-{TIMESTAMP}.md`, `dogfood-{TIMESTAMP}.sarif` + `-latest` symlinks | Gitignored (`.gitignore:52` `.caliper/reports/`) |
| `caliper part --out <dir>` | `<dir>/restack.sh` (mode 0755), `<dir>/cutlist.json` | Also true under `--serve` "download" links |

There is **no** repo-wide `.runs/<pipeline>-<RUN_ID>/` convention wired into
caliper's own CLI today — `scripts/dogfood.sh`'s `{TIMESTAMP}`-suffixed
filenames under `.caliper/reports/` is the closest existing pattern, and
`run-native-review.sh` (shipped with this skill, § 7) follows that same
convention rather than inventing a new one.

## 6. Dev port range: 12000-13000 only

Never use a common port (80, 443, 3000, 5432, 8080, ...) for anything
caliper spins up locally. Confirmed claims, cross-checked against source
(not just CLAUDE.md prose) on 2026-07-02:

| Port | What | Source |
|---|---|---|
| `12432` | PostgreSQL (docker-compose dev DB) | CLAUDE.md § Dev Ports |
| `12700` | `caliper part --serve` sidecar (loopback only by default) | `cli/part_serve.py:74` `DEFAULT_PORT` |
| `12701` | `caliper part --serve --lan` read-only TLS view (mutating routes stay loopback) | `cli/part_serve.py:78` `DEFAULT_LAN_PORT` |
| `12800` | Webhook server | `webhook/config.py:26`, `webhook/server.py:12` |

`cli/part_serve.py` itself encodes the range as `_DEV_PORTS = range(12000,
13000)` and scans it when the requested port is busy — so the convention is
enforced in code, not just documented. Before you bind a **new** local
service (a debug HTTP server, a new sidecar, anything), run:

```bash
bash .claude/skills/caliper-run-and-operate/scripts/check-dev-port.sh <port>
```

## 7. Scripts shipped with this skill

Both were run against this repo on 2026-07-02; documented output above/below
is what was actually observed, not a guess.

| Script | Purpose |
|---|---|
| `scripts/check-dev-port.sh <port>` | Validates a candidate port against § 6's range + claimed-port table before you bind a new local service. Exits 1 on out-of-range or already-claimed; exits 0 (with an informational `lsof` check) otherwise. |
| `scripts/run-native-review.sh [format] [extra caliper review args...]` | Thin wrapper around `uv run caliper review --repo-path . --all --format <fmt>`, landing the artifact under `.caliper/reports/review-<RUN_ID>.<ext>` (mirrors `scripts/dogfood.sh`'s existing timestamp convention — see § 5). |

Observed runs:

```
$ bash .claude/skills/caliper-run-and-operate/scripts/check-dev-port.sh 12800
FAIL: port 12800 is already claimed by: webhook server (caliper.webhook.server)
$ echo $?
1

$ bash .claude/skills/caliper-run-and-operate/scripts/check-dev-port.sh 12750
OK: port 12750 is in range and not claimed by an existing caliper service.
INFO: nothing currently listening on 12750 on this machine.

$ bash .claude/skills/caliper-run-and-operate/scripts/run-native-review.sh json --category quality
=== caliper review (native), format=json ===
JSON written to /Volumes/Extra/repos/gitrdunhq/eedom/.caliper/reports/review-20260702-174935.json
Written: /Volumes/Extra/repos/gitrdunhq/eedom/.caliper/reports/review-20260702-174935.json
```

## Provenance & maintenance

Facts above date-stamped 2026-07-02 (caliper `0.2.27`, `pyproject.toml`).
Re-verify with these — none of them mutate anything:

```bash
# Re-list every CLI command and confirm none were added/removed/renamed
uv run caliper --help

# Re-check review's flag surface hasn't drifted
uv run caliper review --help

# Re-confirm the FOREMAN_* env surface (grep the pydantic model directly, not docs)
grep -n ': .* = \|env_prefix' src/caliper/agent/config.py

# Re-confirm the agent tool count/signatures (this skill flags brief-vs-actual drift — 3 vs 6)
grep -n '^def ' src/caliper/agent/tools.py

# Re-confirm webhook auth order and payload cap
grep -n '_MAX_PAYLOAD_SIZE_BYTES\|_PR_ACTIONS\|_REVIEW_TIMEOUT_S' src/caliper/webhook/server.py

# Re-confirm output formats
grep -n 'output_format ==' src/caliper/cli/review_cmd.py

# Re-confirm dev-port claims directly in source (not just CLAUDE.md prose)
grep -rn '12432\|12700\|12701\|12800' CLAUDE.md src/caliper/cli/part_serve.py src/caliper/webhook/config.py

# Re-run the shipped scripts against current repo state
bash .claude/skills/caliper-run-and-operate/scripts/check-dev-port.sh 12750
bash .claude/skills/caliper-run-and-operate/scripts/run-native-review.sh json --category quality

# Re-count registered plugins (19 scanner plugins + OPA policy plugin, per CLAUDE.md)
uv run caliper plugins | tail -1
```

**Open items / things this skill deliberately does not resolve:**
- The agent brief that seeded this skill said three tools
  (`evaluate_change`/`check_package`/`scan_code`); the module has six today
  (§ 3). Not a bug — just document drift between the original ADR-era design
  and current `tools.py`. Re-check the count if this skill feels stale.
- There is no committed `cal` alias definition anywhere in this repo (it's a
  documented *pattern* in CLAUDE.md, backed by the real `scripts/scan.sh`,
  not a checked-in dotfile) — § 2 gives you the function to add yourself
  rather than pointing at a private shell config.
