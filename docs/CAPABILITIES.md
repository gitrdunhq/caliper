# caliper Capability Matrix

<!--
  AUTO-REFRESH CONTRACT: Update this file whenever you add, remove, or modify
  a plugin, semgrep rule, code graph check, OPA policy rule, CLI command,
  output format, or integration. Keep counts accurate. See CLAUDE.md rule.

  LAST VERIFIED: 2026-06-29
  VERIFICATION: 19 auto-discovered scanner plugins (@ANALYZERS.register) + OPA policy
  plugin (20 ScannerPlugin subclasses total); 21 detectors in src/caliper/detectors/;
  61 semgrep rule ids in policies/semgrep/.
-->

## Identity

Caliper — fully deterministic dependency, security, and code review for CI.
19 scanner plugins, 21 deterministic detectors, 61 custom semgrep rules, 12 code graph
checks, 8 OPA policy rules, 600+ tests. Zero LLM in the decision path (the optional
supply-chain version-bump narrative is advisory metadata only).

## Quick Numbers

| Metric | Count |
|--------|-------|
| Scanner plugins | 19 (5 categories) + OPA policy plugin |
| Deterministic detectors | 21 (CAL-001..CAL-021) |
| Custom semgrep rules | 61 (11 rule files) |
| Code graph SQL checks | 12 |
| OPA Rego policy rules | 8 (5 deny, 3 warn) |
| NL query templates | 12 |
| Copilot agent tools | 6 |
| Finding scribes | 4 (enclosing-symbol, code-graph, semgrep opt-in, supply-chain-threat opt-in) |
| CLI commands | 10 |
| Output formats | 4 |
| Supported ecosystems (SBOM) | 18 |
| Supported languages (CPD) | 15 |
| Supported languages (complexity) | 10 |
| Supported languages (semgrep) | 14 file extensions |
| Gitleaks patterns | 800+ |
| Spell check dictionaries | 15 |

---

## Plugins by Category

The 19 auto-discovered scanner plugins (registered via `@ANALYZERS.register`) split across
five categories below. The **OPA policy plugin** is the 20th `ScannerPlugin` subclass but is
wired separately — it consumes every other plugin's findings and runs last
(`depends_on=["*"]`); see [OPA Policy Rules](#opa-policy-rules-8-rules).

### dependency (4)

| Plugin | File | Detects |
|--------|------|---------|
| osv-scanner | `plugins/osv_scanner.py` | Known CVE/GHSA/OSV vulnerabilities. 22 manifest/lockfile formats. CVSS severity mapping. |
| trivy | `plugins/trivy.py` | Vulnerability scanning via Trivy database (`trivy fs --scanners vuln`). |
| scancode | `plugins/scancode.py` | License detection (SPDX extraction + confidence). **Orphaned/disabled** — transitive dep lacks arm64 wheels; not installed in the image nor enabled by default. Plugin code retained for re-enable. |
| syft | `plugins/syft.py` | CycloneDX SBOM generation. 18 ecosystems (npm, PyPI, Cargo, Go, Ruby, Composer, Dart, Elixir, etc). |

### supply_chain (3)

| Plugin | File | Detects |
|--------|------|---------|
| supply-chain | `plugins/supply_chain.py` | **Three sub-checks**: (1) Unpinned deps in package.json + requirements.txt. (2) Lockfile integrity — lockfile changed without manifest or vice versa, 10 lockfile-manifest pairs, SHA-256 fingerprinting. (3) Docker floating tags — `:latest` or no tag in Dockerfiles and docker-compose. Pure Python, no binary. |
| gitleaks | `plugins/gitleaks.py` | Secret/credential detection, 800+ patterns. Custom config via `.caliper/gitleaks.toml`. Secrets never appear in findings — only rule ID, file, line, entropy, fingerprint. Always critical severity. |
| clamav | `plugins/clamav.py` | Malware/virus scanning via ClamAV (`clamscan`). Recursive repo scan. |

### code (5)

| Plugin | File | Detects |
|--------|------|---------|
| semgrep | `plugins/semgrep.py` | AST code pattern matching. Dynamic ruleset selection by file extension (Python, TS, JS, Go, Ruby, Java, Terraform, K8s, Shell, Docker, Swift). 61 custom org rules (see below). Supports pinned local rule snapshots. |
| cpd | `plugins/cpd.py` | PMD Copy-Paste Detector. Token-based duplication across 15 languages. Groups by language, sorts by token count, shows fragment preview. |
| mypy | `plugins/mypy.py` | Cross-file type checking. Prefers pyright (faster, stricter) when available, falls back to mypy. Error + warning severity only. |
| swiftlint | `plugins/swiftlint.py` | Swift style and code smell detection. 200+ built-in rules + 13 project-specific custom rules (NSLock→actor, @unchecked Sendable SAFETY, [weak self] in actor Task, removeFirst() O(n), URL interpolation, etc.). Respects `.caliper/swiftlint.yml` → `.swiftlint.yml` → bundled default. |
| swiftformat | `plugins/swiftformat.py` | Swift formatting lint. Reports files that need reformatting (all auto-fixable with `swiftformat .`). INFO severity only. |

### quality (4)

| Plugin | File | Detects |
|--------|------|---------|
| blast-radius | `plugins/blast_radius.py` | Code graph impact analysis. AST → SQLite, then 12 SQL checks (see below). Full + incremental indexing. Python + JS/TS. Extensible via `graph.register_check()`. |
| complexity | `plugins/complexity.py` | Cyclomatic complexity (Lizard) + maintainability index (Radon). 10 languages. Per-function: CCN, NLOC, tokens, params, MI grade (A/B/C). |
| typos | `plugins/typos.py` | Source-aware typo detection (crate-ci/typos). Single pinned Rust binary, very low false positives, identifier-aware (camelCase/snake_case splitting). Shows corrections. |
| ls-lint | `plugins/ls_lint.py` | File naming convention enforcement. Only runs when `.ls-lint.yml` config exists. |

### infra (3)

| Plugin | File | Detects |
|--------|------|---------|
| cfn-nag | `plugins/cfn_nag.py` | CloudFormation security — IAM wildcards, open security groups, unencrypted resources. Auto-detects CFN templates. |
| cdk-nag | `plugins/cdk_nag.py` | CDK security — always runs `cdk synth` first (never stale `cdk.out/`), then scans synthesized templates. Triggers on `cdk.json` or `cdk.out/`. |
| kube-linter | `plugins/kube_linter.py` | K8s/Helm security — privileged containers, missing resource limits, no liveness probes, host networking, NET_RAW. Shows remediation. |

---

## Custom Semgrep Rules (61 rules, 11 files)

All in `policies/semgrep/`.

### security.yaml (9)
- `org.security.secret-in-log` — logging passwords/secrets/tokens/api_keys/dsn
- `org.security.pickle-load` / `pickle-load-file` — pickle deserialization
- `org.security.eval-call` — eval() usage
- `org.security.os-system` — os.system() command injection
- `org.security.sql-fstring-interpolation` / `sql-format-interpolation` — SQL string interpolation
- `org.security.path-no-resolve-check` — path used without resolve/traversal check
- `org.security.hardcoded-secret-default` — hardcoded secret as a default value

### resource-safety.yaml (9)
- `org.resource.file-read-all-python` / `file-read-all-js` — unbounded file read
- `org.resource.temp-dir-persistent-python` / `temp-dir-persistent-js` — temp dir never cleaned up
- `org.resource.fire-and-forget-task-python` / `fire-and-forget-promise-js` — unawaited task/promise
- `org.resource.lock-held-during-io-python` — I/O while holding a lock
- `org.resource.unbounded-append-in-loop-python` / `unbounded-append-in-loop-js` — unbounded growth in a loop

### org-code-smells.yaml (12)
- `org.python.no-bare-except-pass` — bare except: pass
- `org.python.no-broad-except-return-none` — catch Exception to return None
- `org.python.no-print-in-source` — print() in non-test code
- `org.python.no-hardcoded-localhost` — hardcoded localhost/127.0.0.1/0.0.0.0
- `org.python.no-pickle-load` — pickle.load on untrusted data
- `org.python.no-breakpoint` — breakpoint() left in source
- `org.terraform.no-wildcard-iam-action` — IAM policy with action "*"
- `org.terraform.no-open-ingress` — security group open to 0.0.0.0/0
- `org.terraform.no-unencrypted-s3` — S3 bucket without encryption
- `org.kubernetes.no-privileged-container` — privileged: true
- `org.kubernetes.no-latest-tag` — image: :latest tag
- `org.ci.no-secret-in-run` — secrets directly in run: blocks

### reliability.yaml (6)
- `org.reliability.unconditional-exit-zero` — sys.exit(0) in agent code
- `org.reliability.subprocess-no-timeout` — subprocess.run without timeout
- `org.reliability.silent-pass-fallback` — silent pass in except
- `org.reliability.substring-match-without-boundary` — string `in` check without boundary
- `org.reliability.file-open-missing-oserror` — open() without OSError handling
- `org.reliability.subprocess-run-unhandled-exceptions` — subprocess.run without exception handling

### solid-first.yaml (4)
- `first-no-sleep-in-tests` — time.sleep() in tests
- `first-no-environ-in-tests` — direct os.environ reads in tests
- `first-test-no-assert` — test function with no assert or pytest.raises
- `ocp-isinstance-chain` — isinstance chain with 4+ branches (OCP violation)

### testing.yaml (2)
- `org.testing.weak-assertion-defined` — assert X is not None (weak)
- `org.testing.weak-assertion-truthy` — bare assert X without comparison

### contracts.yaml (2)
- `org.contract.raw-string-status` — raw verdict string literals instead of DecisionVerdict enum
- `org.contract.event-type-string-literal` — string literal event types instead of enums/constants

### arch.yaml (1)
- `org.arch.core-imports-data-private` — core/ importing private symbols from data/

### banned.yaml (1)
- `org.banned.print-in-source` — print() in production code

### swift-code-smells.yaml (8)
- `org.swift.force-try` / `force-cast` — force try!/as! casts
- `org.swift.notification-center-post` / `notification-center-observer` — NotificationCenter usage
- `org.swift.userdefaults-write` — direct UserDefaults writes
- `org.swift.dispatch-main-async` — DispatchQueue.main.async usage
- `org.swift.print-in-source` — print() in Swift source
- `org.swift.todo-fixme` — TODO/FIXME left in source

### swiftui-code-smells.yaml (7)
- `org.swiftui.foreach-unstable-id-self` — ForEach id: \.self
- `org.swiftui.foreach-sort-inline` / `foreach-sort-inline-no-comparator` / `foreach-filter-inline` — sort/filter inside ForEach
- `org.swiftui.formatter-allocation-in-view` — formatter allocated in body
- `org.swiftui.image-decode-inline` — inline image decode in body
- `org.swiftui.nslock-use-actor-instead` — NSLock in SwiftUI; prefer an actor

---

## Deterministic Detectors (21)

AST-driven, fail-safe bug-pattern rules in `src/caliper/detectors/`, exposed to the pipeline
as a single `DeterministicScanner` (`tool_name="deterministic"`). Each is suppressible inline
with `# noqa: CAL-NNN`. Full reference: [`docs/detectors.md`](detectors.md).

| ID | Name | Category | Severity |
|----|------|----------|----------|
| CAL-001 | JWT Missing Audience Claim | security | high |
| CAL-002 | Error Information Exposure | security | high |
| CAL-003 | API Endpoint Missing Rate Limiting | security | medium |
| CAL-004 | Secret Should Use SecretStr | security | high |
| CAL-005 | SQL Injection via String Formatting | security | critical |
| CAL-016 | CI Verification Gate Bypass | security | high |
| CAL-017 | Presentation Tier Imports Data Tier | security | medium |
| CAL-020 | Fixed Heredoc Delimiter w/ GITHUB_OUTPUT | security | low |
| CAL-006 | Unbounded Cache Without Eviction | reliability | medium |
| CAL-007 | Circuit Breaker Missing Half-Open State | reliability | medium |
| CAL-008 | Path String Concatenation | reliability | medium |
| CAL-009 | Cache Lookup Without Freshness Check | reliability | low |
| CAL-010 | Batch Insert Without Rollback Handling | reliability | medium |
| CAL-011 | Health Check Without DB Verification | reliability | medium |
| CAL-012 | Subprocess Call Without Timeout | reliability | medium |
| CAL-015 | High Cardinality Metric Labels | reliability | medium |
| CAL-019 | Nullable advisory_id in Dedup Key | reliability | low |
| CAL-021 | Non-Atomic File Write | reliability | medium |
| CAL-013 | Config Merge Dropping Telemetry | configuration | low |
| CAL-018 | Dockerfile Pin Drift | configuration | medium |
| CAL-014 | Missing Tested-By Annotation | process | low |

By category: security 8, reliability 10, configuration 2, process 1.

---

## Code Graph Checks (12 checks)

All in `plugins/_runners/checks.yaml`. Executed by the blast-radius plugin against a SQLite code graph built from AST analysis.

| Check | Severity | Detects |
|-------|----------|---------|
| blast_radius_critical | critical | Symbol with >25 direct dependents |
| blast_radius_high | high | Symbol with >10 direct dependents |
| mock_stub_in_source | high | Stub/mock/noop patterns in non-test source files |
| layer_violation | high | core/ importing from data/ (three-tier architecture breach) |
| circular_dependency | medium | File import cycles (A imports B imports A) |
| high_fan_out | medium | Function calling >8 other functions (god function) |
| deep_inheritance | medium | Class inheritance chain deeper than 3 levels |
| noop_function | medium | Functions that do nothing (pass/return None/stub/log_only) |
| srp_high_fan_out_imports | medium | Module importing from 4+ distinct packages (SRP violation) |
| srp_large_class | medium | Class with >15 methods (SRP violation) |
| missing_tested_by | medium | Source file missing `# tested-by:` annotation |
| orphan_symbol | info | Function with zero callers (potential dead code) |

### Code Graph Internals

- **SQLite schema**: symbols, edges, checks, file_metadata
- **AST indexing**: Python (full AST) + JS/TS (regex-based)
- **Body classification** (7 types): noop, pass_only, return_none, return_input, log_only, stub, real
- **Edge kinds**: calls, imports, inherits (with confidence scores)
- **Incremental rebuild**: content-hash-based change detection, only re-indexes modified files
- **Extensible**: `graph.register_check(name, query, severity)` for custom SQL checks

---

## OPA Policy Rules (8 rules)

File: `policies/policy.rego`. Consumes findings from all plugins.

| Rule | Type | Trigger |
|------|------|---------|
| Critical/high vulnerability | deny | severity critical or high + category vulnerability |
| Forbidden license | deny | license_id in config forbidden_licenses list |
| Package age < threshold | deny | first_published_date < min_package_age_days (default 90) |
| Malicious package | deny | advisory_id starts with "MAL-" |
| Supply-chain version-bump signal | deny | severity critical or high + category supply_chain |
| Medium vulnerability | warn | severity medium + category vulnerability |
| Transitive dep count | warn | transitive_dep_count > max_transitive_deps (default 200) |
| Supply-chain note | warn | severity medium + category supply_chain |

Decision: any deny → reject. No deny + any warn → approve_with_constraints. Else → approve.
All rules individually toggleable via `config.rules_enabled.*`.

---

## NL Query System (12 templates)

File: `core/nl_query.py`. Keyword-matched SQL queries against the code graph. No ML.

| Query | What it returns |
|-------|----------------|
| Highest fan-out / god functions | Top 20 functions by outgoing call count |
| Most imported / depended on | Top 20 symbols by incoming dependency count |
| Dead code / unused functions | Functions with zero callers |
| Deepest inheritance chains | Classes with deepest inheritance |
| Layer violations | core/ importing from data/ |
| What depends on {symbol} | Upstream walk (parameterized) |
| What does {symbol} call | Downstream walk (parameterized) |
| Largest files | Files ranked by symbol count |
| Stub / noop functions | Functions with body_kind noop/pass_only/stub |
| Circular imports | Mutual import cycles |
| Complex functions | Functions with >10 statements |
| All classes | Complete class listing |

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `caliper evaluate` | Full pipeline on dependency changes. Modes: monitor/advise. Output: JSON. |
| `caliper review` | Plugin review on repo or diff. Filter by --scanners, --category, --enable/--disable. Formats: markdown, json (schema: `docs/schema/report-v1.0.json`), SARIF. Supports --watch (watchdog, 500ms debounce), --pr N (inline PR review), --package (monorepo single package). |
| `caliper check-health` | Verify scanner binaries and DB connectivity. |
| `caliper plugins` | List all registered plugins with binary status and depends_on. |
| `caliper schema` | Print the JSON Schema for `caliper review --format json` output. `--output` writes to a file. Published artifact: `docs/schema/report-v1.0.json`. |
| `caliper query` | Natural language query against code graph SQLite database. |
| `caliper supply-chain-diff` | Separate, feature-flag-gated step (`CALIPER_SUPPLY_CHAIN_DIFF_ENABLED=1`). Fetches the source of both versions of every dependency bump in a diff, scores deterministic supply-chain signals (which gate via OPA), and optionally attaches an advisory LLM narrative. Formats: markdown, json, sarif. Modes: monitor/advise. NOT part of the normal scan. |
| `caliper part` | Manual, developer-invoked diff-cutting. Computes the stock (`--base..--head`), runs a pure deterministic `part()` to propose an ordered cut list of small reviewable parts (rules R1 generated/binary isolation, R2 move/logic separation, R4 size cap), and emits a jj `restack.sh` (`--target stack|series`). Fail-closed and advisory: never gates a build, never enters the decision audit lake, lives in a dedicated PARTING registry (NOT in the review pipeline). A non-destructive precondition gate + rollback header make it fully reversible. `--explain` re-prints a saved cut list. |
| `caliper inspect` | Manual, developer-invoked per-part review of a `caliper part` cut list. Three tiers per part: Tier 0 deterministic gauges (existing analyzers scoped to the part, routed by bucket; fail-closed), Tier 1 advisory LLM claims behind a sealed swappable `LLMPort` (cached on part content; fail-soft), Tier 2 a pure deterministic adjudicator that filters claims by six rules (parse, scope, anchor, substantiation, category allow-list, floor, dedup) so no LLM output reaches a human except through it. Writes per-part + integration reports, and appends advisory/dropped claims to the claims ledger. `--no-llm` is fully deterministic. Advisory only: never gates, never enters the audit lake, LLM backends isolated in a dedicated INSPECT_BACKENDS registry. `--explain` re-prints a report. |
| `caliper gauge` | The flywheel: turn recurring advisory LLM claims into permanent deterministic Tier 0 gauges. Subcommands: `propose` (deterministic clustering/ranking of the claims ledger; the LLM drafts candidate gauges — the only LLM step, behind GAUGE_DRAFTERS), `backtest` (deterministic four-part gate — recall, precision, determinism, performance; LLM-free), `promote` (human-gated; refuses without a passing backtest and `--by`; records a Promotion with full lineage into the tool crib), `status` (convergence scorecard: substantiation rate, advisory recurrence, gauge coverage, LLM novelty). The LLM drafts but never promotes — a gauge is active iff a Promotion exists. Bias guards mandatory: candidacy floor (no nits/style), recurrence threshold, precision backtest, human promotion. Ledger is advisory data, never the audit lake. |

---

## Output Formats

| Format | Where | Description |
|--------|-------|-------------|
| Markdown PR comment | `templates/comment.md.j2` | Verdict badge, health score (0-100), maintainability grade, per-plugin summary table, detailed sections. 65536 char max with truncation. |
| SARIF v2.1.0 | `core/sarif.py` | GitHub Security tab integration. Severity-to-level mapping. Configurable max findings cap. Detect-then-scribe packets surface in each result's `properties.scribe` (parity with the JSON report). |
| Inline PR review | `core/pr_review.py` | SARIF → GitHub PR review. Hunk-aware line placement. REQUEST_CHANGES on reject, COMMENT on approve_with_constraints. Outside-diff findings in collapsed summary. |
| JSON decision | CLI `--output-json` | Machine-readable decision with all findings, policy evaluation, and evidence. |

---

## Integrations

| Integration | File | Description |
|-------------|------|-------------|
| GitHub Action | `action.yml` | Composite action: diff → evaluate → PR comment (upsert) → check warning on reject. |
| GitHub Copilot Agent | `src/caliper/agent/` | Foreman — 6 tools (evaluate_change, check_package, scan_code, scan_duplicates, scan_k8s, analyze_complexity). 8-dimension task-fit rubric. |
| Webhook server | `src/caliper/webhook/server.py` | Starlette ASGI. GitHub PR webhooks (opened/synchronize/reopened). HMAC-SHA256 signature validation. Port 12800. |
| Jenkins | `jenkins/vars/dependencyAdmission.groovy` | Shared library for Jenkins pipelines. |
| Container | `Dockerfile` | Podman/Docker. Read-only workspace mount. |

---

## Core Pipeline Capabilities

| Capability | File | Description |
|------------|------|-------------|
| Parallel scanning | `core/orchestrator.py` | ThreadPoolExecutor with combined wall-clock timeout. |
| Unified verdict (SoT) | `core/review_summary.py` | One `summarize_review()` computes verdict + counts + scores; the markdown badge, JSON report, SARIF properties, and CI header/label all consume it (no divergent re-derivation). Diff-scoped gate: only PR-introduced security findings block; pre-existing dependency CVEs are advisory. |
| Detect-then-scribe | `core/scribe.py`, `core/scribe.py` | Post-detection pass (ADR-006): every plugin finding is decorated with deterministic context in `metadata['scribe']` — enclosing symbol (`detectors` scribe), code-graph blast radius (`plugins` scribe), opt-in nearby semgrep matches (`plugins` scribe), and the opt-in supply-chain-threat LLM narrative (`plugins` scribe). Sequential, fail-open, time-bounded (`scribe_timeout`); verdict-independent. Pluggable via the `SCRIBES` registry; also wired into the Foreman agent's `scan_code`. |
| Cross-scanner dedup | `core/normalizer.py` | Highest severity wins per (advisory_id, category, package, version). |
| Evidence chain | `core/seal.py` | Blockchain-style SHA-256 seals. manifest hash + previous seal → seal hash. `verify_seal()` detects tampering. |
| Parquet audit log | `data/parquet_writer.py` | Append-only per-run audit trail. |
| SBOM diff | `core/sbom_diff.py` | Diff two CycloneDX SBOMs: added/removed/upgraded/downgraded across 18 ecosystems. |
| Dependency diff | `core/diff.py` | Git diff parsing for requirements.txt, pyproject.toml, and package.json (npm). |
| Supply-chain version-bump analysis | `core/supply_chain_diff.py`, `data/pkgsrc.py`, `data/supply_chain_scan.py` | Separate gated step (`caliper supply-chain-diff`): fetches both versions of every dependency bump (PyPI sdist / npm tarball, safe extraction with traversal + zip-bomb defenses), diffs the source, and scores deterministic signals — new install hooks (critical), obfuscation/encoded payloads (high), newly introduced network/exec capability (high), publisher change (medium). Signals gate via the OPA `supply_chain_diff` rule; the optional `supply_chain_threat` scribe attaches an advisory LLM narrative (zero-LLM decision path preserved). Fail-open. |
| Health score | `core/renderer.py` | 0-100 severity-weighted score (critical=10, high=5, medium=2, low=1). |
| Monorepo support | `core/manifest_discovery.py` | Walk repo, discover multiple package roots (8 manifest types, 8 lockfile types), run plugins per-package with scoped config merging. |
| Policy engine | `core/policy.py` | OPA subprocess wrapper with fail-open degradation. |
| Topological ordering | `core/registry.py` | Plugins declare `depends_on` for execution order. `["*"]` = run last. Circular dep detection. |
| Ignore patterns | `core/ignore.py` | `.caliperignore` with 6 built-in defaults (.git/, __pycache__/, node_modules/, .venv/, .claude/, .caliper/). |
| Repo config | `core/repo_config.py` | `.caliper.yaml` — per-plugin enable/disable, thresholds, telemetry. Root + package-level merge. |
| Task-fit advisory | `core/taskfit.py` | Optional LLM 8-dimension proportionality check (NECESSITY, MINIMALITY, MAINTENANCE, SECURITY, EXPOSURE, BLAST_RADIUS, ALTERNATIVES, BEHAVIORAL). |
| Structured errors | `core/errors.py` | 10 error codes: NOT_INSTALLED, TIMEOUT, PARSE_ERROR, PERMISSION_DENIED, BINARY_CRASHED, NO_OUTPUT, SCANNER_DEGRADED, CONFIG_MISSING, INDEX_FAILED, NETWORK_ERROR. |
| Telemetry | `core/telemetry.py` | Anonymous opt-in, 9 signals, Pydantic `extra="forbid"`, file-path stripping, fire-and-forget async. |

---

## Data Tier

| Component | File | Description |
|-----------|------|-------------|
| Decision repository | `data/db.py` | PostgreSQL persistence + NullRepository fallback. Saves requests, scans, policy evals, decisions. |
| Evidence store | `data/evidence.py` | File-based evidence bundles keyed by run_id + package. |
| Parquet writer | `data/parquet_writer.py` | Append-only Parquet audit log per pipeline run. |
| PyPI client | `data/pypi.py` | Package metadata: age, availability. |
| Alternatives catalog | `data/alternatives.py` | 30+ packages mapped to 9 categories. Parses requirements.txt and pyproject.toml. |
| Scanner wrappers | `data/scanners/` | Subprocess wrappers for osv, trivy, syft, scancode. |

---

## Competitive Positioning

**caliper = "is this change safe to ship?"** (vulns, secrets, licenses, supply chain, IaC, blast radius, code smells, policy)

### vs SonarQube

| Capability | SonarQube | caliper |
|------------|-----------|-------|
| Semantic bug detection | Deep per-language rules (25+ languages) | Semgrep AST + 61 custom rules + 21 deterministic detectors |
| Stylistic code smells | Hundreds of built-in rules | Not primary focus |
| Structural code smells | Limited | 12 graph checks (dead code, god functions, SRP, layer violations, circular deps, deep inheritance, stubs) |
| Complexity | Cyclomatic + cognitive | Cyclomatic (Lizard) + MI (Radon) — parity |
| Copy-paste | Built-in CPD | Built-in CPD (15 languages) — parity |
| Coverage gating | Ingests lcov/cobertura, gates on % | **Not supported** |
| Dependency vulns | Developer Edition only (paid) | OSV + Trivy (free) |
| SBOM generation | No | Syft CycloneDX (18 ecosystems) |
| License compliance | No | ScanCode SPDX extraction |
| Secret detection | No | Gitleaks (800+ patterns) |
| Supply chain integrity | No | Lockfile integrity, unpinned deps, Docker floating tags |
| IaC security | No | cfn-nag + cdk-nag + kube-linter |
| Malware scanning | No | ClamAV |
| Policy-as-code | Built-in Java rules | OPA Rego (user-authored) |
| Change impact analysis | No | Blast-radius code graph |
| Evidence chain | No | SHA-256 sealed evidence bundles |
| Audit trail | No | Parquet append-only log |
| Monorepo support | Branch analysis (paid) | Per-package scanning + config merging (free) |

### Not Covered by caliper

- Coverage ingestion and gating
- Cognitive complexity metric (Lizard does cyclomatic, not cognitive)
- Stylistic smell detection (naming, long parameter lists, magic numbers)
- Data Class smell detection
- Feature Envy smell detection
- 25+ language depth for semantic bugs (semgrep covers breadth, not SQ-level depth)

---

## Configuration Reference

| Mechanism | File | Scope |
|-----------|------|-------|
| Env vars | `CALIPER_*` prefix | Global: operating_mode, db_dsn, evidence_path, 7 timeouts, enabled_scanners, LLM settings |
| Repo config | `.caliper.yaml` | Per-repo: plugin enable/disable, per-plugin thresholds, telemetry. Root + package-level merge. |
| Ignore patterns | `.caliperignore` | Per-repo: fnmatch exclusions, layered on top of every file source. |
| File source | `CALIPER_FILE_SOURCE` | Global: `auto` (git ls-files when usable, else walk), `git`, or `walk`. |
| Gitleaks config | `.caliper/gitleaks.toml` | Per-repo: custom gitleaks rules. |
| ls-lint config | `.ls-lint.yml` | Per-repo: file naming conventions. |
| OPA policy | `policies/policy.rego` | Per-repo: deny/warn rules with toggleable `rules_enabled.*`. |
| Semgrep rules | `policies/semgrep/*.yaml` | Per-repo: custom AST pattern rules. |
| Graph checks | `plugins/_runners/checks.yaml` | Per-repo: custom SQL checks against code graph. |
