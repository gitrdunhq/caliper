<div align="center">
  <img src="assets/hero.svg" alt="Caliper" width="900">
  <br>
  <strong>Fully deterministic dependency review for CI.</strong><br>
  19 plugins. 21 detectors. 6 OPA policy rules. 18 ecosystems. Zero LLM in the decision path.
  <br><br>

  <a href="#quick-start"><img src="https://img.shields.io/badge/get_started-→-d4251a?style=flat-square" alt="Get Started"></a>
  <a href="#the-19-plugins"><img src="https://img.shields.io/badge/19_plugins-deterministic-f2c14a?style=flat-square&labelColor=0e0706" alt="19 Plugins"></a>
  <a href="#opa-policy-rules"><img src="https://img.shields.io/badge/OPA-6_rules-1e3a8a?style=flat-square" alt="OPA Rules"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm_Shield-7ae582?style=flat-square" alt="PolyForm Shield License"></a>
</div>

<br>

---

## Why This Exists

Every PR that touches a dependency or a source file needs someone to answer the same mechanical questions: any known CVEs? License compatible? Package too new to trust? Secrets leaked? Complexity getting worse?

Those checks aren't hard. They're tedious. And they're the reason your senior engineers spend half their review time on things a script could catch — while the stuff that actually needs a human brain (architecture, logic, design intent) gets a tired "LGTM" at the end.

**So what?** When reviews bottleneck, one of two things happens. Teams either slow down — PRs queue up, deploys stall, developers context-switch while waiting — or they speed up wrong. Reviews get rubber-stamped. A critical CVE ships because nobody had the energy to check transitive deps on the fourth PR of the afternoon. A copyleft license sneaks into a commercial codebase because the reviewer was focused on the actual code change, not the new dependency it pulled in.

Both outcomes cost real money. One costs velocity. The other costs incidents.

**Caliper doesn't replace human review. It removes the mechanical half so humans can do the half that requires judgment.** Nineteen plugins run the checks that don't need a brain. OPA policy makes the accept/reject decision deterministically. The reviewer opens a PR and the dependency, vulnerability, license, complexity, and secret checks are already done — with evidence, an audit trail, and a clear verdict. They can skip straight to "does this design make sense?"

---

When a PR touches a dependency manifest — `requirements.txt`, `package.json`, `Cargo.toml`, `go.mod`, any of 18 ecosystems — caliper detects the changed packages, runs 19 plugins in parallel (plus 21 deterministic AST detectors and 61 custom semgrep rules on changed source), deduplicates findings, decorates each with deterministic context (detect-then-scribe), evaluates them against OPA policy, writes tamper-evident evidence, and appends the decision to a Parquet audit log.

Every scanning tool is deterministic. The decision is deterministic. Nothing blocks the build unless OPA says so.

**Two entry points, same pipeline:**

| Entry Point | Interface | Use Case |
|-------------|-----------|----------|
| **CLI** | `caliper evaluate` / `caliper review` | CI pipelines, local dev |
| **Foreman** | `python -m caliper.agent.main` | GitHub Copilot Agent for reactive PR review |

---

## The 19 Plugins

<div align="center">
  <img src="assets/scanners.svg" alt="Scanner lineup" width="700">
</div>

<br>

All deterministic. Zero LLM. The only AI is the optional Copilot agent wrapper that synthesizes results into PR comments — and even that is pluggable and removable. The 19 scanner plugins below feed their findings to a 20th **OPA policy plugin**, which runs last and makes the accept/reject decision.

### Dependency (run on every evaluation)

| # | Plugin | What it does |
|---|--------|-------------|
| 1 | **Syft** | SBOM generation (CycloneDX, 18 ecosystems) |
| 2 | **OSV-Scanner** | Known vulnerability database (CVE/GHSA) |
| 3 | **Trivy** | Vulnerability scanning |
| 4 | **ScanCode** | License detection (SPDX) |

### Code Analysis (run on changed source files)

| # | Plugin | What it does |
|---|--------|-------------|
| 5 | **Semgrep** | AST pattern matching (dynamic rulesets + 61 custom org rules) |
| 6 | **PMD CPD** | Copy-paste detection (15 languages) |
| 7 | **Mypy** | Deterministic cross-file Python type checking (prefers pyright) |
| 8 | **SwiftLint** | Swift style + code smells (200+ rules + 13 custom) |
| 9 | **SwiftFormat** | Swift formatting lint (all findings auto-fixable) |

### Infrastructure

| # | Plugin | What it does |
|---|--------|-------------|
| 10 | **kube-linter** | K8s/Helm security validation |
| 11 | **CDK Nag** | CDK CloudFormation security scanning |
| 12 | **cfn-nag** | CloudFormation template security scanning |

### Quality

| # | Plugin | What it does |
|---|--------|-------------|
| 13 | **Lizard + Radon** | Cyclomatic complexity + maintainability index |
| 14 | **typos** | Source-aware typo detection (crate-ci/typos, low false positives) |
| 15 | **ls-lint** | File naming conventions |
| 16 | **Blast Radius** | AST→SQLite code graph, 12 SQL checks |

### Supply Chain

| # | Plugin | What it does |
|---|--------|-------------|
| 17 | **Supply Chain** | Unpinned deps + lockfile integrity + latest tag detection |
| 18 | **ClamAV** | Malware/virus scanning |
| 19 | **Gitleaks** | Secret/credential detection (800+ patterns) |

### Policy

| Plugin | What it does |
|--------|-------------|
| **OPA** | Policy enforcement (6 Rego rules), runs last (`depends_on=["*"]`) — see [policy rules](#opa-policy-rules) |

### Plus 21 deterministic detectors

On changed source, caliper also runs **21 AST bug detectors** (`CAL-001`…`CAL-021`) — SQL injection, missing JWT audience claim, secrets typed as plain `str`, subprocess without timeout, unbounded caches, non-atomic writes, and more. Deterministic, fail-safe, suppressible with `# noqa: CAL-NNN`. See [`docs/detectors.md`](docs/detectors.md).

**Scanner disagreement:** When OSV-Scanner and Trivy report the same CVE, the normalizer deduplicates on `(advisory_id, category, package_name, version)`. Highest severity wins.

**Plugin execution order:** Plugins can declare `depends_on` to express ordering constraints. The registry performs a topological sort before execution — OPA, for example, always runs after all scanner plugins have produced findings. Circular dependencies are detected at registry initialization and raise an error before any scan begins.

---

## Quick Start

### Review a repo (native)

```bash
uv sync --group dev

# Review all files in the current repo
uv run caliper review --repo-path . --all

# Review only code analysis plugins
uv run caliper review --repo-path . --category code

# List available plugins
uv run caliper plugins

# Post findings as inline PR review comments
uv run caliper review --repo-path . --all --pr 42
```

### Full pipeline evaluation (native)

```bash
uv run python -m caliper.cli.main check-health
uv run python -m caliper.cli.main evaluate \
  --repo-path . --diff changes.diff \
  --pr-url "https://github.com/org/repo/pull/1" \
  --team myteam --operating-mode advise
```

### Run via container

```bash
podman build -t caliper:latest .

git diff origin/main...HEAD > changes.diff

podman run --rm -v "$(pwd):/workspace:ro" caliper:latest \
  uv run python -m caliper.cli.main evaluate \
    --repo-path /workspace --diff /workspace/changes.diff \
    --pr-url "https://github.com/org/repo/pull/1" \
    --team myteam --operating-mode monitor
```

### Foreman (GitHub Copilot Agent)

```bash
export FOREMAN_GITHUB_TOKEN="ghp_..."
export FOREMAN_PR_NUMBER=123
export FOREMAN_DIFF_PATH=./changes.diff
export FOREMAN_REPO_OWNER=myorg
export FOREMAN_REPO_NAME=myrepo

uv run python -m caliper.agent.main
```

---

## Enforcement Modes

| Mode | PR Comment | Build Status | Use Case |
|------|-----------|-------------|----------|
| `block` | Yes | **Fails** on reject | Production gate |
| `warn` | Yes | Always passes | Advisory (default) |
| `log` | No | Always passes | Silent monitoring |

---

## GitHub Action

Install `.github/workflows/foreman.yml` — triggers on PRs that change dependency manifests or source files across 10 ecosystems.

```yaml
name: Caliper
on:
  pull_request:
    paths:
      - 'requirements*.txt'
      - 'pyproject.toml'
      - 'package.json'
      - 'package-lock.json'
      - 'Cargo.toml'
      - 'Cargo.lock'
      - 'go.mod'
      - 'go.sum'
      - '**/*.py'
      - '**/*.ts'
      - '**/*.go'

jobs:
  review:
    runs-on: self-hosted
    timeout-minutes: 10
    container:
      image: caliper:latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: git diff ${{ github.event.pull_request.base.sha }}...${{ github.event.pull_request.head.sha }} > .temp/pr.diff
      - run: uv run python -m caliper.agent.main
        env:
          FOREMAN_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          FOREMAN_ENFORCEMENT_MODE: warn
          FOREMAN_DIFF_PATH: .temp/pr.diff
          FOREMAN_PR_NUMBER: ${{ github.event.pull_request.number }}
          FOREMAN_REPO_OWNER: ${{ github.repository_owner }}
          FOREMAN_REPO_NAME: ${{ github.event.repository.name }}
```

Or use the composite action (`action.yml`):

```yaml
- uses: org/caliper@main
  with:
    operating-mode: advise
    team: platform
```

---

## OPA Policy Rules

6 rules in `policies/policy.rego`. All individually toggleable via `input.config.rules_enabled`.

| Rule | Type | Trigger | Default |
|------|------|---------|---------|
| `critical_vuln` | **deny** | Severity in {critical, high} | Always on |
| `forbidden_license` | **deny** | License in forbidden list | GPL-3.0, AGPL-3.0, SSPL-1.0 |
| `package_age` | **deny** | First published < N days ago | 30 days |
| `malicious_package` | **deny** | Advisory ID starts with `MAL-` | Always on |
| `medium_vuln` | warn | Severity = medium | Always on |
| `transitive_count` | warn | Transitive deps > threshold | 200 |

**Decision logic:**

```
deny non-empty        → "reject"
warn only (no deny)   → "approve_with_constraints"
both empty            → "approve"
OPA unavailable       → "needs_review"
```

```bash
opa test policies/ --ignore '*.yaml' --ignore '*.yml'   # policy tests covering every rule and toggle
```

---

## Architecture

```
src/caliper/
├── cli/                    # Presentation: Click CLI (150 lines)
├── agent/                  # Presentation: Caliper Copilot Agent
│   ├── main.py             #   Agent orchestrator + enforcement
│   ├── tools.py            #   6 @tool functions for the LLM
│   ├── tool_helpers.py     #   Subprocess runners (Semgrep, CPD, kube-linter, lizard)
│   ├── config.py           #   FOREMAN_* env vars
│   └── prompt.py           #   System prompt with 8-dimension rubric
├── core/                   # Logic: all business rules
│   ├── pipeline.py         #   Main orchestrator — evaluate() and evaluate_sbom()
│   ├── plugin.py           #   ScannerPlugin ABC + PluginCategory enum
│   ├── registry.py         #   PluginRegistry — auto-discovery + filtering
│   ├── renderer.py         #   Jinja2 comment renderer + severity rollup
│   ├── sarif.py            #   SARIF v2.1.0 output converter
│   ├── repo_config.py      #   .caliper.yaml loader
│   ├── models.py           #   All Pydantic models and StrEnums
│   ├── policy.py           #   OPA subprocess wrapper
│   ├── diff.py             #   Text diff parser (requirements.txt, pyproject.toml)
│   ├── sbom_diff.py        #   CycloneDX SBOM differ (18 ecosystems via purl)
│   ├── normalizer.py       #   Finding deduplication (highest severity wins)
│   ├── scribe.py           #   Detect-then-scribe pass (SCRIBES, fail-open) — ADR-006
│   ├── actionability.py    #   Actionable vs blocked finding classification
│   ├── orchestrator.py     #   Parallel scanner runner (ThreadPoolExecutor)
│   ├── decision.py         #   Pure assembler — OPA verdict → ReviewDecision
│   ├── memo.py             #   Markdown PR comment generator
│   ├── seal.py             #   SHA-256 evidence chain
│   └── taskfit*.py         #   Optional LLM advisory (disabled by default)
├── plugins/                # 19 scanner plugins + OPA policy plugin + scribes
│   ├── blast_radius.py     #   AST→SQLite code graph + SQL checks
│   ├── semgrep.py          #   AST pattern matching
│   ├── clamav.py           #   Malware/virus scanning
│   ├── gitleaks.py         #   Secret detection (800+ patterns)
│   ├── mypy.py             #   Cross-file Python type checking
│   ├── cdk_nag.py          #   CDK CloudFormation security scanning
│   ├── cfn_nag.py          #   CloudFormation template scanning
│   ├── scribes/          #   Detect-then-scribe: code-graph + opt-in semgrep (ADR-006)
│   └── ...                 #   + 13 more (one file per plugin, incl. _opa.py)
├── detectors/              # 21 deterministic AST bug detectors (CAL-001..021)
│   ├── security/           #   8 detectors (SQL injection, JWT audience, SecretStr, ...)
│   ├── reliability/        #   subprocess timeout, unbounded cache, atomic write, ...
│   ├── scanner.py          #   DeterministicScanner (ScannerPort) — runs them in the pipeline
│   └── _registry.py        #   @register_detector + discover_detectors()
├── composition/            # Composition root: bootstrap() wires the ApplicationContext
├── webhook/                # Starlette ASGI server — GitHub PR webhooks (HMAC, port 12800)
├── templates/              # Jinja2 templates for PR comments
│   ├── comment.md.j2       #   Main comment wrapper (verdict + sections)
│   └── *.md.j2             #   Per-plugin section templates
└── data/                   # Data: scanners, DB, external clients
    ├── scanners/           #   Legacy Scanner ABC + subprocess wrappers
    ├── db.py               #   PostgreSQL + NullRepository fallback
    ├── evidence.py         #   Atomic file-based artifact store
    ├── pypi.py             #   PyPI JSON API client
    ├── parquet_writer.py   #   Append-only Parquet audit log
    ├── catalog.py          #   Org-wide package catalog (pgvector)
    └── alternatives.py     #   Approved alternatives catalog
```

**Three-tier, imports flow downward only.** Presentation → Logic → Data. No exceptions.

---

## Evidence & Audit Trail

Every run writes tamper-evident artifacts:

```
evidence/
  {sha}/{timestamp}/
    {package}/decision.json    # Full typed decision
    {package}/memo.md          # PR comment markdown
    seal.json                  # SHA-256 hash chain
  decisions.parquet            # Append-only audit lake
```

**Atomic writes** — temp file → fsync → rename. Path traversal blocked.

**Seal chain** — each run's seal chains to the previous run's hash. Tampering any artifact breaks the chain.

**Parquet** — 27-column schema, queryable with DuckDB:

```sql
SELECT package_name, decision, advisory_ids
FROM 'evidence/decisions.parquet'
WHERE vuln_critical > 0 AND team = 'platform';
```

---

## Supply Chain Provenance (SLSA)

Every container image pushed to GHCR includes a SLSA Level 3 provenance attestation — cryptographic proof of what code was built, on what runner, with what workflow.

**Caliper proves the code was reviewed. SLSA proves the image was built from that reviewed code.** Together: full chain of custody from PR to production.

Verify any caliper image:

```bash
gh attestation verify oci://ghcr.io/gitrdunhq/caliper:latest --owner gitrdunhq
```

The attestation includes: source commit SHA, workflow file, runner environment, and build timestamp. Tamper with any of these and verification fails.

---

## Fail-Open Philosophy

Nothing blocks the build unless OPA says so. Every external call has a timeout. Every failure returns a typed result, never an exception.

| Failure | What happens |
|---------|-------------|
| Scanner binary missing | `ScanResult.not_installed()` — pipeline continues |
| Scanner timeout | `ScanResult.timeout()` — pipeline continues |
| OPA failure | `needs_review` — flagged for human review |
| Database down | `NullRepository` — decisions made, not persisted |
| PyPI unreachable | No age check — pipeline continues |
| Parquet write fails | Logged — decision already stored as JSON |
| LLM fails | Empty string — no advisory, pipeline continues |

---

## Configuration

### CLI (`CALIPER_*` prefix)

| Variable | Default | Description |
|----------|---------|-------------|
| `CALIPER_OPERATING_MODE` | `monitor` | `monitor` or `advise` |
| `CALIPER_DB_DSN` | — | PostgreSQL DSN (optional — NullRepository fallback) |
| `CALIPER_EVIDENCE_PATH` | `./evidence` | Evidence + Parquet root |
| `CALIPER_ENABLED_SCANNERS` | `syft,osv-scanner,trivy,scancode` | Active scanners |
| `CALIPER_SCANNER_TIMEOUT` | `60` | Per-scanner timeout (s) |
| `CALIPER_COMBINED_SCANNER_TIMEOUT` | `180` | Combined scanner timeout (s) |
| `CALIPER_OPA_TIMEOUT` | `10` | OPA timeout (s) |
| `CALIPER_PIPELINE_TIMEOUT` | `300` | Per-package timeout (s) |
| `CALIPER_LLM_ENABLED` | `false` | Enable optional LLM task-fit advisory |

### Foreman (`FOREMAN_*` prefix)

| Variable | Default | Description |
|----------|---------|-------------|
| `FOREMAN_GITHUB_TOKEN` | **(required)** | GitHub token for PR comments |
| `FOREMAN_PR_NUMBER` | **(required)** | PR number to review |
| `FOREMAN_DIFF_PATH` | — | Path to diff file |
| `FOREMAN_REPO_OWNER` | — | Repository owner |
| `FOREMAN_REPO_NAME` | — | Repository name |
| `FOREMAN_ENFORCEMENT_MODE` | `warn` | `block` / `warn` / `log` |
| `FOREMAN_LLM_MODEL` | `gpt-4.1` | Copilot agent model |
| `FOREMAN_ENABLED_SCANNERS` | `syft,osv-scanner,trivy,scancode` | Pipeline scanners |
| `FOREMAN_SEMGREP_TIMEOUT` | `120` | Semgrep timeout (s) |
| `FOREMAN_PIPELINE_TIMEOUT` | `300` | Pipeline timeout (s) |
| `FOREMAN_POLICY_VERSION` | `1.0.0` | Shown in PR comments |
| `FOREMAN_MAX_COMMENT_LENGTH` | `3900` | Max PR comment chars |

### Running without a database (scanner-only mode)

The full `evaluate` pipeline persists every decision to PostgreSQL for the
audit/evidence trail, but the database is never a hard dependency — scanning
and policy evaluation both run without it.

**`NullRepository` fallback.** When `CALIPER_DB_DSN` is unset, the connection
attempt fails, or repository init raises, `build_decision_repository()`
(`src/caliper/composition/bootstrap.py`) falls back to `NullRepository`
(`src/caliper/data/db.py`) — a no-op repository whose `save_*` methods
silently succeed without writing anything. Scanning, OPA policy evaluation,
and the PR comment/memo still run exactly as they would with a live
database; the only thing you lose is the persisted decision history and the
Parquet audit trail (see [Fail-Open Philosophy](#fail-open-philosophy) and
[Evidence & Audit Trail](#evidence--audit-trail) above — this is the same
`NullRepository` referenced there).

**`caliper review` — the standalone scanner-only command.** `caliper review`
(see [Review a repo](#review-a-repo-native) above) never touches a database
at all: it bootstraps through `bootstrap_review()`, which is explicitly
DB-free and doesn't even require `CaliperSettings` to load successfully. It
runs the plugin registry directly — `--all`/`--category`/`--scanners`/
`--disable`/`--enable` select which plugins run, `--scope repo|diff|folder`
controls what gets scanned, and `--format markdown|sarif|json` prints to
stdout (or `--output <path>`) — and reports a plugin-severity verdict with
no OPA gate and no persisted decision. This is what `make dogfood` and
plugin-only CI jobs use.

**Piping JSON out of a no-DB job.** `caliper review --format json` already
prints to stdout when `--output` is omitted, so it composes naturally with
`jq` or any downstream tool in a scanner-only, no-DB CI job. The full
`evaluate` command's `--output-json` option, by contrast, currently only
writes to a file path (it's a plain `click.Path()`) — there's no stdout
(`-`) convention for it yet. A stdout mode (`--output-json -`) is in
progress; once it lands, a scanner-only CI job that wants the full policy
decision (not just plugin findings) will be able to pipe it straight out the
same way, without a database or an intermediate file.

**Single source of truth for this config.** `db_dsn`, timeouts, evidence
path, and enabled scanners are all defined once in `CaliperSettings`
(`src/caliper/core/config.py`) — see the [Configuration
Reference](docs/CAPABILITIES.md#configuration-reference) for the full table.

---

## Repo-Level Configuration

Drop `.caliper.yaml` at the root of any repo to enable/disable plugins and override thresholds:

```yaml
# .caliper.yaml
plugins:
  disable:
    - clamav         # disable heavy AV scan in local dev
    - typos          # disable typo checking for this repo
  enable:
    - gitleaks       # always on, even if disabled globally

thresholds:
  package_age_days: 14          # stricter than default 30
  transitive_count: 100         # stricter than default 200
  complexity_threshold: 15      # cyclomatic complexity limit

licenses:
  forbidden:
    - GPL-3.0-only
    - AGPL-3.0-only
    - SSPL-1.0
    - Commons-Clause

parting:                          # config for `caliper part` (manual diff cutting)
  size_cap: 400                   # hard cap on lines (added+removed) per part
  target: stack                   # stack (bookmark per part) | series (one tip bookmark)
  move_ambiguity_size: 50         # a rename with a larger content delta is emitted as logic
  validate_command: ""            # optional per-part self-check run by restack.sh (off by default)
  generated_globs:                # parted off first, isolated (lockfiles, codegen, snapshots)
    - "*.lock"
    - "*.generated.*"
  config_globs: ["*.yaml", "*.toml", ".github/**"]
  test_globs: ["test_*.py", "*_test.py", "tests/**"]
```

### Parting — `caliper part`

`caliper part` is a **manual, developer-invoked** operation that proposes how to
cut a big working branch into an ordered *cut list* of small, reviewable *parts*,
and emits a jj `restack.sh` that performs the cut non-destructively. It is **not**
wired into the automatic review pipeline (no Foreman, no webhook, no Action), it
never gates a build, and its output is a proposal, not a verdict.

```bash
# Propose a cut list for the diff base..head and write restack.sh + cutlist.json
uv run caliper part --base main --head HEAD --out .parting

# One commit per part on a single branch instead of a stack of bookmarks
uv run caliper part --base main --head HEAD --target series --out .parting

# Re-print a saved cut list and the rule fired at each kerf
uv run caliper part --explain .parting/cutlist.json
```

The cut is computed by a pure, deterministic function — the same stock always
yields a byte-identical cut list. Before touching anything, a precondition gate
checks the repo is a clean jj/colocated repo with no untracked files, no git
stash, and an unpushed target, then records a rescue point and a backup bookmark
anchoring the pre-parting base (so the rebuilt parts are exactly `backup+::@`).
Every emitted script and printed cut list opens with a rollback header
(`jj op restore <id>`). jj surgery is reversible by construction; parting never
deletes, force-pushes, or rebases shared history — push/submit stay printed
comments you run yourself.

> **Fail-closed carve-out.** Unlike the scanners (which are fail-open — see below),
> the parting path is **fail-closed**: a missing input, a classifier timeout, or
> any partial result is a hard error, never a silent continue. Fail-open is correct
> for scanning because OPA still gates; it would be wrong here, where a degraded
> input would silently change the cut and break determinism.

**v1 plugs in** at three named seams (none implemented in v0): the Blast Radius
CodeGraph for the dependency graph and the R3 (layer) / R5 (risk) rules; the
scribe + taskfit path for deterministic kerf rationale (disabled by default, no
LLM in the decision); and a post-merge scorecard for the convergence metric.

### Inspect — `caliper inspect`

`caliper inspect` reviews the parts of a cut list, one part at a time, and writes a
per-part inspection report plus one integration report over the assembled stack. It
is **manual and advisory**, like `caliper part`: it never gates a build, never enters
the decision audit lake, and is not in the auto review pipeline (no Foreman, no
webhook, no Action).

```bash
# Review each part of a cut list, then the assembled stack
uv run caliper inspect --cutlist .parting/cutlist.json --out .inspect

# Fully deterministic: Screen gauges + Adjudicate only, no model
uv run caliper inspect --cutlist .parting/cutlist.json --out .inspect --no-llm

# Re-print a saved report
uv run caliper inspect --explain .inspect/inspect/<part-id>.json
```

**Three tiers per part:**

- **Screen — gauges (deterministic, no LLM).** Caliper's existing analyzers/
  detectors/secret scanners, scoped to the part's file set and routed by bucket.
  Produces pass/fail verdicts. A part that fails a hard gauge is reported and its
  LLM review is skipped.
- **Review — LLM review (advisory only).** Runs on parts that clear Screen and need
  judgment (mostly `logic`), behind an `LLMPort`. It emits structured **claims** —
  never a verdict, never a gate. Sealed and swappable; cached on part content.
- **Adjudicate — the filter (deterministic, no LLM).** A pure function (sibling of
  `part()`) filters claims by rules in firing order: parse, scope, anchor (a claim's
  `anchor_quote` must be a verbatim substring of the part's changed text before its
  line numbers are trusted — the anti-hallucination keystone), substantiation (a
  `blocking` claim without a Screen witness is downgraded to advisory, not deleted),
  category allow-list per bucket, severity floor, collapse-into-Screen (a non-blocking
  claim that merely corroborates a Screen finding is dropped), and dedup. Only
  survivors reach the report.

> **Determinism boundary.** The *decision path* is deterministic; the *review* is
> not. The defended claim is "no LLM output reaches a human or a gate except through
> the pure Adjudicate filter" — not "no LLM touches review." LLM output is cached
> keyed on part content, so a part inspects identically until it changes (the cache
> is deterministic; the model is not claimed to be).

> **Fail behavior.** Screen and Adjudicate are **fail-closed** (a gauge that errors or
> times out is a hard error). Review is **fail-soft**: if the LLM is unavailable the
> report shows Screen results and notes `skipped_llm` — it never invents claims to
> fill a gap. The LLM lives only behind `LLMPort`; the deterministic tiers are
> structurally unable to import it (enforced by a test), mirroring how `PARTING` is
> isolated from the auto pipeline.

The claim schema, context presentation, evidence binding, model default, bucket→
gauge routing, category allow-lists, and severity floors are research-fed defaults,
each behind a `.caliper.yaml` `inspect:` knob so a finding can replace it without
restructuring. R3/R5 risk-driven routing (and the Blast Radius graph) are a later
phase; this phase routes by bucket only.

### Gauge — the flywheel (`caliper gauge`)

`caliper gauge` is the terminal step of the arc: it turns **recurring advisory LLM
claims into permanent deterministic Screen gauges**, so deterministic coverage grows
and the LLM is needed for less over time. It is maintainer-driven curation, not a
per-PR operation.

```bash
caliper gauge propose                 # cluster the ledger, LLM drafts candidates (only LLM step)
caliper gauge backtest <candidate>    # deterministic four-part validation (LLM-free)
caliper gauge promote <candidate> --by <name>   # human-gated; refuses without a passing backtest
caliper gauge status                  # convergence scorecard
```

The loop: `caliper inspect` appends every advisory/dropped claim to the **claims
ledger** (advisory data, never the audit lake) with a content reference. `propose`
clusters the ledger **deterministically**, ranks by recurrence × severity, and has
the LLM draft a **candidate gauge** for each high-rank cluster. `backtest` validates
each candidate deterministically. `promote` presents passing candidates to a human,
who accepts or rejects. A promoted gauge is a Screen gauge from then on, so the pattern
becomes substantiated (or never reaches Review) and the ledger stops accumulating it
— the loop closes for that pattern.

> **The LLM drafts; it never promotes.** This is the defining boundary of the phase:
> an LLM now drafts artifacts that become deterministic decision logic, so every rule
> exists to keep that safe. A candidate enters Screen only after a deterministic
> backtest **and** an explicit human promotion — there is no code path from LLM
> output to an active gauge that skips both (a gauge is active iff a `Promotion`
> exists for it). `propose` is the only LLM step; `backtest` and `promote` are
> LLM-free. Clustering, ranking, and the backtest are deterministic and
> property-tested.

> **Guards against enshrining model bias (all mandatory).** A *candidacy floor* —
> only correctness/security/behavioral-change claims are eligible; nits and style
> never mint rules. A *recurrence threshold* — a cluster must recur across enough
> distinct parts and authors, so one noisy run cannot create a rule. A *precision
> backtest* — a candidate that fires across a clean corpus above the configured
> false-positive ceiling is rejected. And *human promotion* as the final gate. Every
> promoted gauge records full **lineage** (cluster, backtest stats, model/prompt
> version, promoter) so its origin is auditable forever.

**The convergence scorecard** (`caliper gauge status`) makes the whole arc
measurable: substantiation rate (claims with a deterministic witness — rising means
the flywheel works), advisory recurrence (recurring patterns = open gaps), gauge
coverage (promoted gauges), and LLM novelty (claims that are genuinely new vs
recurring). The end state: the LLM's advisory output trends toward only the
genuinely novel, because everything recurring has become a gauge — the system making
itself need the model less.

### Plugin CLI flags

Override config at the command line for one-off runs:

```bash
# Disable specific plugins for this run
uv run caliper review --repo-path . --all --disable clamav,typos

# Enable a plugin that is disabled in config
uv run caliper review --repo-path . --all --enable gitleaks

# Combine flags
uv run caliper evaluate --repo-path . --diff changes.diff \
  --disable clamav --enable gitleaks \
  --pr-url "https://github.com/org/repo/pull/1" \
  --team myteam --operating-mode advise
```

---

## SARIF Output

Export findings to SARIF for the GitHub Security tab:

```bash
uv run caliper review --repo-path . --all --format sarif --output results.sarif
```

Upload in GitHub Actions:

```yaml
- name: Run Caliper
  run: uv run caliper review --repo-path . --all --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

SARIF output follows the [SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/). Each plugin maps to a SARIF `tool.driver` — findings are `result` objects with `locations`, `level`, and `ruleId`.

---

## PR Review Posting

Post findings as inline GitHub PR review comments — on the exact lines, not one big comment:

```bash
# Post inline review comments on PR #42
uv run caliper review --repo-path . --all --pr 42

# Specify repo explicitly (auto-detected from git remote by default)
uv run caliper review --repo-path . --all --pr 42 --repo org/repo
```

When `--pr` is passed, caliper maps SARIF findings to the PR diff and posts a proper GitHub review:

- Findings on changed files become **inline comments** on the right lines
- Findings outside the diff go in a **collapsed table** in the review summary
- Uses `REQUEST_CHANGES` when error-level findings exist, `COMMENT` otherwise

In CI, this replaces the big markdown comment with native GitHub review UX — reviewers see findings in the diff view, not buried in a comment.

**Prerequisite:** `--pr` requires the [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated (`gh auth login`). The token needs `pull-requests: write` scope.

---

## Watch Mode

Re-run plugins automatically on file save during local development:

```bash
# Watch all plugins
uv run caliper review --repo-path . --all --watch

# Watch code analysis only (faster feedback loop)
uv run caliper review --repo-path . --category code --watch
```

Watch mode debounces file-system events (500 ms default). Press `Ctrl+C` to stop.

---

## Monorepo Support

Caliper auto-discovers packages across a monorepo and runs all 19 plugins per-package.

### Package discovery

Walks the repo recursively and finds all manifest files — `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `requirements.txt`, `Gemfile`, `pom.xml`, `build.gradle`. Each manifest is paired with its lockfile when present. Directories matching `.caliperignore` patterns and standard ignore dirs (`node_modules`, `.git`, `vendor`, `__pycache__`) are skipped.

```bash
# Scan all packages (auto-discovered)
uv run caliper review --repo-path . --all

# Scan a single package
uv run caliper review --repo-path . --package apps/web --all
```

### Per-package output

Findings are grouped by package in the PR comment. Each package gets its own section header and severity score. The overall verdict is the worst across all packages:

```
## apps/web (npm)
...findings...

## libs/core (python)
...findings...
```

### Per-package config overrides

Drop `.caliper.yaml` inside any package directory to override the root config for that package. Child overrides parent — `apps/web/.caliper.yaml` overrides `/.caliper.yaml` for all files under `apps/web/`.

---

## Code Query

Query the CodeGraph SQLite database in plain English. Backed by 12 built-in query templates — no LLM required.

```bash
# Ask a natural language question
caliper query "which functions have the highest fan-out?"

# List all available query templates
caliper query --list
```

Fuzzy matching maps your question to the closest template by keyword overlap. Unrecognized questions fall back to `caliper query --list` with the full template menu.

### Built-in query templates

| Template | What it answers |
|----------|----------------|
| `highest fan-out` | Top functions by outgoing call count |
| `most imported modules` | Fan-in — which modules are depended on most |
| `unused functions` | Orphan symbols with no incoming references |
| `deepest inheritance chains` | Recursive CTE on `inherits` edges |
| `layer violations` | Cross-tier imports (presentation → data direct) |
| `what depends on X` | Upstream walk from a named symbol |
| `what does X call` | Downstream call graph from a named symbol |
| `largest files by symbol count` | Files grouped by defined symbol count |
| `stub functions` | Functions with empty or pass-only bodies |
| `circular imports` | Mutual edge detection |
| `critical path` | Highest-centrality nodes in the call graph |
| `entry points` | Functions with no callers |

---


## Development

```bash
uv sync --group dev                      # Install everything
docker-compose up -d                     # PostgreSQL on port 12432
uv run pytest tests/ -v                  # 1078 tests
uv run ruff check src/ tests/            # Lint
uv run black src/ tests/                 # Format
opa test policies/ --ignore '*.yaml' --ignore '*.yml'  # OPA policy tests
bash scripts/verify-scanners.sh          # Check scanner binaries

# Stress test against real PRs
uv run python scripts/gauntlet.py
```

**Scanner versions** (pinned in Dockerfile): Syft 1.21.0, OSV-Scanner 2.0.1, Trivy 0.70.0, ScanCode 32.3.0, OPA 1.4.2, Semgrep 1.67.0.

---

<div align="center">
  <img src="assets/avatar.png" alt="Caliper" width="96">
  <br>
  <sub>Caliper &middot; Dependency Review Agent &middot; v0.2.4</sub>
</div>
