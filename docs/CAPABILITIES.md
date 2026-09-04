# caliper Capability Matrix

<!--
  AUTO-REFRESH CONTRACT: Update this file whenever you add, remove, or modify
  a plugin, semgrep rule, code graph check, OPA policy rule, CLI command,
  output format, or integration. Keep counts accurate. See CLAUDE.md rule.

  LAST VERIFIED: 2026-09-04
  VERIFICATION: 15 auto-discovered scanner plugins (@ANALYZERS.register) + the
  "deterministic" plugin (composition-registered, wraps DeterministicScanner,
  #457) + OPA policy plugin (17 ScannerPlugin subclasses total); 29 detectors
  in src/caliper/detectors/; 67 semgrep rule ids in policies/semgrep/; 17 OPA
  Rego policy rules in policies/policy.rego (7 deny, 10 warn).
-->

## Identity

Caliper — fully deterministic dependency, security, and code review for CI.
16 scanner plugins (15 auto-discovered + "deterministic", which wraps all 29
CAL-001..030 detectors), 67 custom semgrep rules, 10 code graph
checks, 17 OPA policy rules, 600+ tests. Zero LLM in the decision path (the optional
supply-chain version-bump narrative is advisory metadata only).

Install with `pip install caliper-review` — the PyPI distribution name is
`caliper-review`; the import package and `caliper` console script are
unchanged.

## Quick Numbers

| Metric | Count |
|--------|-------|
| Scanner plugins | 16 (15 auto-discovered + "deterministic", composition-registered) + OPA policy plugin |
| Deterministic detectors | 29 (CAL-001..CAL-030, CAL-013 retired), run via the "deterministic" plugin during `caliper review` |
| Custom semgrep rules | 67 (11 rule files) |
| Code graph SQL checks | 10 |
| OPA Rego policy rules | 17 (7 deny, 10 warn) |
| Code graph query templates | 12 |
| Finding scribes | 6 (enclosing-symbol, code-graph, reachability opt-in, semgrep opt-in, supply-chain-threat opt-in, grounding opt-in) |
| CLI commands | 10 |
| Parting taxonomy buckets | 16 ChangeTypes (4 code tiers, 7 non-code intent, `logic` residual, 4 structural/generated) |
| Output formats | 5 |
| Supported ecosystems (SBOM) | 18 |
| Supported languages (CPD) | 15 |
| Supported languages (complexity) | 10 |
| Supported languages (semgrep) | 14 file extensions |
| Gitleaks patterns | 800+ |

---

## Plugins by Category

The 15 auto-discovered scanner plugins (registered via `@ANALYZERS.register`) split across
five categories below, plus **deterministic** (also `@ANALYZERS.register`, but
composition-registered — see `code (6)` below since `detectors/` may not import
`plugins/` directly). The **OPA policy plugin** is the 17th `ScannerPlugin` subclass but
is wired separately — it consumes every other plugin's findings and runs last
(`depends_on=["*"]`); see [OPA Policy Rules](#opa-policy-rules-15-rules).

### dependency (4)

| Plugin | File | Detects |
|--------|------|---------|
| osv-scanner | `plugins/osv_scanner.py` | Known CVE/GHSA/OSV vulnerabilities. 22 manifest/lockfile formats. CVSS severity mapping. |
| trivy | `plugins/trivy.py` | Vulnerability scanning via the Trivy database plus IaC misconfiguration checks (`trivy fs --scanners vuln,misconfig --skip-check-update`): CloudFormation, Terraform, Kubernetes, Dockerfile, Helm. Misconfig findings carry file, line, and resolution. Checks are the ones embedded in the pinned trivy release (no bundle fetch), so results do not drift. |
| scancode | `plugins/scancode.py` | License detection (SPDX extraction + confidence). **Opt-in** — not installed in the default image and excluded from `--all` by default (`DEFAULT_OPT_IN_PLUGINS`); enable via `--enable scancode`/`--scanners scancode` or `plugins.enable` in `.caliper.yaml`. |
| syft | `plugins/syft.py` | CycloneDX SBOM generation. 18 ecosystems (npm, PyPI, Cargo, Go, Ruby, Composer, Dart, Elixir, etc). |

### supply_chain (3)

| Plugin | File | Detects |
|--------|------|---------|
| lockfile-drift | `plugins/lockfile_drift.py` | Manifest changed without its lockfile (package.json, pyproject.toml, Pipfile, Cargo.toml, go.mod); flags the manifest so the resolved dependency set is regenerated with it. Pure filesystem inspection, no binary. |
| supply-chain | `plugins/supply_chain.py` | **Three sub-checks**: (1) Unpinned deps in package.json + requirements.txt. (2) Lockfile integrity — lockfile changed without its manifest, 10 lockfile-manifest pairs, SHA-256 fingerprinting (the inverse direction, manifest changed without its lockfile, is `lockfile-drift`'s job — see above; supply-chain dropped its own copy of that check since a suffix-filtered whole-repo listing can never contain a lockfile name, which made it false-positive on every whole-repo scan, #507). (3) Docker floating tags — `:latest` or no tag in Dockerfiles and docker-compose. Pure Python, no binary. |
| gitleaks | `plugins/gitleaks.py` | Secret/credential detection, 800+ patterns. Custom config via `.caliper/gitleaks.toml`. Secrets never appear in findings — only rule ID, file, line, entropy, fingerprint. Always critical severity. |

### code (5)

| Plugin | File | Detects |
|--------|------|---------|
| deterministic | `composition/deterministic_plugin.py` | Wraps `DeterministicScanner` (`detectors/scanner.py`) — the 29 AST-based bug detectors (CAL-001..030, CAL-013 retired) selected by `detectors.profiles` in `.caliper.yaml`: `default` (20 general bug patterns, on) and `house-rules` (9 caliper-convention rules, opt-in), plus `enable`/`disable` per id (`detectors/profiles.py`). Composition-registered rather than auto-discovered, since `detectors/` may not import `plugins/` directly (#457). |
| semgrep | `plugins/semgrep.py` | AST code pattern matching via opengrep. Community rules come ONLY from local snapshots, never the registry, so the scan path has no network dependency and the rule set cannot drift. The semgrep/semgrep-rules snapshot (pinned by `SEMGREP_RULES_COMMIT`, language directories selected by file type) is **opt-in at build time** (`--build-arg INCLUDE_SEMGREP_RULES=1`) because its licence permits internal use only; the published image excludes it. The 67 custom org rules (see below) run against every target via `CALIPER_SEMGREP_ORG_RULES_DIR`, and the shared [caliper-community-rules](https://github.com/gitrdunhq/caliper-community-rules) snapshot (Kirby-annotated `rules/**/semgrep/*.yaml`, pinned by `COMMUNITY_RULES_COMMIT`, baked at `/opt/caliper/community-rules`) via `CALIPER_SEMGREP_COMMUNITY_RULES_DIR`; that snapshot also carries three vendored MIT rule sets under `vendor/` (GitLab sast-rules, MIT-headed files only, ~280 rules across Java, Scala, Python, C, Kotlin, Ruby, Go, C#, JS; dgryski/semgrep-go, 66 Go correctness rules; 0xdea/semgrep-rules, 50 C/C++ rules), each pinned by commit with its LICENSE kept. Host runs: `scripts/snapshot-semgrep-rules.sh`, `scripts/snapshot-community-rules.sh` (`--bump` moves the pin to upstream main). Severities are canonical at the boundary: ERROR→high, WARNING→medium, INFO→info. |
| cpd | `plugins/cpd.py` | PMD Copy-Paste Detector. Token-based duplication across 15 languages. Groups by language, sorts by token count, shows fragment preview. |
| mypy | `plugins/mypy.py` | Cross-file type checking. Prefers pyrefly (fastest) when available, falls back to pyright, then mypy. Error + warning severity only. |
| swiftlint | `plugins/swiftlint.py` | Swift style and code smell detection. 200+ built-in rules + 13 project-specific custom rules (NSLock→actor, @unchecked Sendable SAFETY, [weak self] in actor Task, removeFirst() O(n), URL interpolation, etc.). Respects `.caliper/swiftlint.yml` → `.swiftlint.yml` → bundled default. |

### quality (3)

| Plugin | File | Detects |
|--------|------|---------|
| blast-radius | `plugins/blast_radius.py` | Code graph impact analysis. AST → SQLite, then 10 SQL checks (see below). Full + incremental indexing. Python + JS/TS. Extensible via `graph.register_check()`. |
| complexity | `plugins/complexity.py` | Cyclomatic complexity (Lizard) + maintainability index (Radon for Python, bundled typhonjs-escomplex for JS/TS). A function is a finding only when its CCN exceeds `thresholds.complexity.ccn` (default 10, `.caliper.yaml`); every function still feeds the summary (`functions_scanned`, avg/max CCN, NLOC). |
| ls-lint | `plugins/ls_lint.py` | File naming convention enforcement. Only runs when `.ls-lint.yml` config exists. |

### infra (1)

| Plugin | File | Detects |
|--------|------|---------|
| kube-linter | `plugins/kube_linter.py` | K8s/Helm security — privileged containers, missing resource limits, no liveness probes, host networking, NET_RAW. Shows remediation. |

---

## Custom Semgrep Rules (67 rules, 11 files)

All in `policies/semgrep/`.

### security.yaml (9)
- `org.security.secret-in-log` — logging passwords/secrets/tokens/api_keys/dsn
- `org.security.pickle-load` / `pickle-load-file` — pickle deserialization
- `org.security.eval-call` — eval() usage
- `org.security.os-system` — os.system() command injection
- `org.security.sql-fstring-interpolation` / `sql-format-interpolation` — SQL string interpolation
- `org.security.path-no-resolve-check` — path used without resolve/traversal check
- `org.security.hardcoded-secret-default` — hardcoded secret as a default value

### resource-safety.yaml (15)
- `org.resource.file-read-all-python` / `file-read-all-js` — unbounded file read
- `org.resource.temp-dir-persistent-python` / `temp-dir-persistent-js` — temp dir never cleaned up
- `org.resource.fire-and-forget-task-python` / `fire-and-forget-promise-js` — unawaited task/promise
- `org.resource.lock-held-during-io-python` — I/O while holding a lock
- `org.resource.unbounded-append-in-loop-python` / `unbounded-append-in-loop-js` — unbounded growth in a loop
- `org.resource.await-in-consumer-loop-python` / `await-in-consumer-loop-js` — sequential await inside a consumer loop
- `org.resource.unbounded-channel-python` / `unbounded-channel-js` — unbounded queue/channel with no backpressure
- `org.resource.unchecked-thread-safety-python` / `unchecked-thread-safety-js` — shared state mutated without a lock

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

The CDK rules (`cdk-custom-resource-oncreate-without-onupdate`, `cdk-code-fromasset-relative-literal`, `cdk-fixed-iam-role-name`, `cdk-ssm-document-default-update-method`) and `empty-test-body-js` live in [caliper-community-rules](https://github.com/gitrdunhq/caliper-community-rules) and reach every review through the baked snapshot, not through `policies/semgrep/`.

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

## Deterministic Detectors (29)

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
| CAL-022 | Architecture Tier Boundary Violation | security | medium |
| CAL-023 | Lambda Handler Swallows Exceptions | reliability | high |
| CAL-024 | Destructive AWS Call Without Dry-Run Guard | reliability | medium |
| CAL-025 | AWS API Call Missing Required-In-Practice Argument | reliability | medium |
| CAL-026 | Event Field Guard Omits Field Passed To AWS Call | reliability | medium |
| CAL-027 | Committed Build Artifact Beside Source | process | low |
| CAL-028 | Blocking Call Inside Async Function | reliability | high |
| CAL-029 | Delete Or Rollback Path Swallows Failure | reliability | medium |
| CAL-030 | Numeric Setting Used Without Range Guard | reliability | medium |
| CAL-018 | Dockerfile Pin Drift | configuration | medium |
| CAL-014 | Missing Tested-By Annotation | process | low |

By category: security 9, reliability 10, configuration 2, process 1.

---

## Code Graph Checks (10 checks)

All in `plugins/_runners/checks.yaml`. Executed by the blast-radius plugin against a SQLite code graph built from AST analysis.

| Check | Severity | Detects |
|-------|----------|---------|
| blast_radius_critical | critical | Symbol with >25 direct dependents |
| blast_radius_high | high | Symbol with >10 direct dependents |
| mock_stub_in_source | high | Stub/mock/noop patterns in non-test source files |
| circular_dependency | medium | File import cycles (A imports B imports A) |
| high_fan_out | medium | Function calling >8 other functions (god function) |
| deep_inheritance | medium | Class inheritance chain deeper than 3 levels |
| noop_function | medium | Functions that do nothing (pass/return None/stub/log_only) |
| srp_high_fan_out_imports | medium | Module importing from 4+ distinct packages (SRP violation) |
| srp_large_class | medium | Class with >15 methods (SRP violation) |
| orphan_symbol | info | Function with zero callers (potential dead code) |

### Code Graph Internals

- **SQLite schema**: symbols, edges, checks, file_metadata
- **AST indexing**: Python (full AST) + JS/TS (regex-based)
- **Body classification** (7 types): noop, pass_only, return_none, return_input, log_only, stub, real
- **Edge kinds**: calls, imports, inherits (with confidence scores)
- **Incremental rebuild**: content-hash-based change detection, only re-indexes modified files
- **Extensible**: `graph.register_check(name, query, severity)` for custom SQL checks

---

## OPA Policy Rules (17 rules)

File: `policies/policy.rego`. Consumes findings from all plugins.

| Rule | Type | Trigger |
|------|------|---------|
| Critical/high vulnerability | deny | severity critical or high + category vulnerability (not dev-scope-exempted, not unreachable-exempted) |
| Forbidden license | deny | license_id in config forbidden_licenses list (not dev-scope-exempted) |
| Package age < threshold | deny | first_published_date < min_package_age_days (default 90) |
| Malicious package | deny | advisory_id starts with "MAL-" (always denies, never dev-scope-exempted) |
| Supply-chain version-bump signal | deny | severity critical or high + category supply_chain |
| CISA KEV — actively exploited CVE | deny | category vulnerability + advisory_id in config.kev_ids (always denies, never dev-scope-exempted) |
| Strong copyleft, static/unknown link | deny | category license + license_id in config.copyleft_strong + link_type "static" or "unknown" (#347) |
| Medium vulnerability | warn | severity medium + category vulnerability |
| Transitive dep count | warn | transitive_dep_count > max_transitive_deps (default 200) |
| Supply-chain note | warn | severity medium + category supply_chain |
| Dev-scope vulnerability exemption | warn | critical/high vulnerability, pkg.scope == "dev", `rules_enabled.dev_scope_exemption` true, advisory_id not "MAL-"-prefixed |
| Unreachable-vulnerability exemption | warn | critical/high vulnerability, `finding.reachable == false`, `rules_enabled.unreachable_vuln_exemption` true, advisory_id not "MAL-"-prefixed (#348, ADR-009) |
| Dev-scope license exemption | warn | forbidden license, pkg.scope == "dev", `rules_enabled.dev_scope_exemption` true |
| Unmaintained package | warn | days since pkg.last_release_date > max_days_since_release (default 365); fails open when last_release_date absent/null (#346) |
| Strong copyleft, dynamic link | warn | category license + license_id in config.copyleft_strong + link_type "dynamic" (#347) |
| Weak copyleft, any link | warn | category license + license_id in config.copyleft_weak, any link_type (#347) |
| Approved alternative available | warn | pkg.name has an entry in config.alternatives[pkg.ecosystem] with a non-empty prefer list (#480) |

Decision: any deny → reject. No deny + any warn → approve_with_constraints. Else → approve.
All rules individually toggleable via `config.rules_enabled.*`. `dev_scope_exemption`
defaults to `false` (opt-in) — when enabled, it downgrades the critical/high-vulnerability
and forbidden-license deny rules to warn for `pkg.scope == "dev"` packages only; a
`MAL-`-prefixed advisory always denies regardless (#345). `cisa_kev` also defaults to
`false` (opt-in) — when enabled, any vulnerability whose advisory_id is in the
operator-supplied `config.kev_ids` (CISA Known Exploited Vulnerabilities catalog)
always denies, with no dev-scope downgrade path (#344). `unmaintained_package` also
defaults to `false` (opt-in) — when enabled, it warns on stale packages using
`input.pkg.last_release_date` (#346). `copyleft_propagation` also defaults to `false`
(opt-in) — when enabled, a `link_type`-aware copyleft check: a `config.copyleft_strong`
license denies when `link_type` is `"static"` or `"unknown"` (caliper has no linkage-
detection scanner today, so `"unknown"` is treated as conservatively as `"static"`) and
warns when `"dynamic"`; a `config.copyleft_weak` license always warns regardless of
`link_type` (#347). `unreachable_vuln_exemption` also defaults to `false` (opt-in) —
when enabled, it downgrades a critical/high vulnerability deny to warn when the
`reachability` scribe (ADR-009) reports `reachable == false` on the finding (package
declared but never imported anywhere in the repo); an unresolved/missing reachability
(`null`) never downgrades, and a `MAL-`-prefixed advisory always denies regardless (#348).
`approved_alternatives` also defaults to `false` (opt-in) — when enabled, it warns
(never denies — this is a recommendation, not a violation) when the changed package
has an entry in the operator-supplied `config.alternatives[ecosystem][name].prefer`
list. Reads from `input.config` rather than a `data.*` document, matching `kev_ids`'s
precedent: `opa eval` in production is invoked with `-d <policy.rego>` only (see
`core/policy.py` `_run_opa`), so a bundled `data.alternatives` document would never
actually load (#480).

---

## Code Graph Queries (12 templates)

File: `core/nl_query.py`. Twelve canned SQL queries against the code graph, selected by keyword match on the question text. No NLP, no ML; `--list` shows the menu.

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
| `caliper review` | Plugin review on repo or diff. Filter by --scanners, --category, --enable/--disable. Formats: markdown, json (schema: `docs/schema/report-v1.0.json`), SARIF, OpenVEX. Supports --watch (watchdog, 500ms debounce), --pr N (inline PR review), --package (monorepo single package). |
| `caliper check-health` | Verify scanner binaries and DB connectivity. (`caliper healthcheck`, the image's `HEALTHCHECK`, exits 1 only when a default-on scanner is missing; opt-in `scancode` and amd64-only `swiftlint` report as `optional`.) |
| `caliper plugins` | List all registered plugins with binary status and depends_on. |
| `caliper schema` | Print the JSON Schema for `caliper review --format json` output. `--output` writes to a file. Published artifact: `docs/schema/report-v1.0.json`. |
| `caliper query` | Run one of 12 canned code graph queries against the SQLite code graph. Keyword match picks the template; `--list` shows them. |
| `caliper supply-chain-diff` | Separate, feature-flag-gated step (`CALIPER_SUPPLY_CHAIN_DIFF_ENABLED=1`). Fetches the source of both versions of every dependency bump in a diff, scores deterministic supply-chain signals (which gate via OPA), and optionally attaches an advisory LLM narrative. Formats: markdown, json, sarif. Modes: monitor/advise. NOT part of the normal scan. |
| `caliper ground` | Deterministic grounding bundle for a set of files (fact sheet of defined symbols + type contracts referenced from elsewhere) as JSON, plus a markdown twin with `--out`. Feature-flag gated (`CALIPER_GROUNDING_ENABLED=1`); providers: code graph, universal-ctags, ripgrep fallback. Not part of the normal scan; wiring into the scribe pass is tracked in #481. |
| `caliper init` | Write the standard `.caliper.yaml`: every value is the default, each section commented, so a repo's config is a visible diff from the standard rather than a guess (#291). `--print` shows it, `--force` overwrites. A bare `caliper review` already behaves exactly like this file. |
| `caliper install-scanners` | Install the pinned scanner binaries for this machine (`syft`, `trivy`, `osv-scanner`, `opa`, `gitleaks`, `kube-linter`, `ls-lint`, `jq`, `opengrep`) into `$CALIPER_BIN_DIR` or `~/.local/bin`, sha256-verified against `core/scanner_pins.py`, the same releases the container bakes in (a drift-guard test keeps them identical). `caliper review` on a terminal offers this when a plugin reports NOT_INSTALLED; `caliper healthcheck` prints the command. Not covered: pmd (needs a JRE), scancode, swiftlint, lizard/pyrefly. |
| `caliper part` | Manual, developer-invoked diff-cutting. Computes the stock (`--base..--head`, or `--pr <url\|number>` to clone a GitHub PR in isolation and auto-resolve base..head), runs a pure deterministic `part()` to propose an ordered cut list of reviewable parts (rules R1 generated/binary isolation, R2 move/logic separation, R4 size cap), and emits a `restack.sh` (`--target stack\|series`). **Two execution backends** (`core/part_gate.detect_backend`, #520): jj (preferred, path-granular `jj restore` + op-log rollback) when jj is on PATH and the repo is jj/colocated, else a git-native fallback (plain `git checkout --detach` + per-part `git checkout`/`git rm`/`git commit` on a detached HEAD, new `caliper-part-*` branches only) so a reviewer with git but no jj gets the full apply/rollback flow — `cutlist.json` provenance records which backend ran. The default cut is **one commit per labelled bucket of concern** (`size_cap` defaults to `None`); `--size-cap N` is opt-in and only splits *within* a bucket by accumulated line count. Files are classified into a two-axis taxonomy — architectural code tiers (frontend/business/data/infra) + non-code intent buckets (documentation/supply_chain/ci_cd/security_policy/config/schema_contracts), with `logic` as the honest untiered residual a human should label. Generated-file detection isn't glob-only (#525): a batched `.gitattributes` `linguist-generated` content-attribute check (`part_stock._linguist_generated_paths`) catches generated files that don't match a known `generated_globs` pattern — it sits below the human override table (a reviewer's explicit call still wins) and above the glob heuristics. A version-controlled `parting.overrides` table (glob→bucket, in `.caliper.yaml`) sits above the heuristic globs so a reviewer can correct a tier; it is part of the `config_digest` provenance. Fail-closed and advisory: never gates a build, never enters the decision audit lake, lives in a dedicated PARTING registry (NOT in the review pipeline). A non-destructive precondition gate + rollback header make it fully reversible. `--explain` re-prints a saved cut list, per file annotated with the match reason (#521, `CutList.match_reasons`) — which structural fact, override glob, or `PartingConfig` glob field fired, e.g. `[override:src/api/**]` or `[glob:supply_chain_globs]`. `--serve [--port N]` runs a loopback sidecar (127.0.0.1:12700) serving a full TypeScript SPA (`scripts/part_ui/`, esbuild-bundled and committed as package data under `src/caliper/cli/part_ui_dist/` — zero Node needed at runtime) with **CLI/web parity**: live retargeting (`POST /range`, `POST /pr` — paste a base/head or a GitHub PR URL/number without restarting the sidecar), reclassify (writes a `parting.overrides` entry and re-parts, deterministic feedback loop, no LLM), bulk suggestion accept (`POST /suggest/apply`), live `--size-cap`/`--target` settings (`POST /repart`), a client-side `--explain` viewer for a loaded `cutlist.json`, and **restack generation + execution** (`POST /restack` builds `restack.sh` + the rollback header via the same `core/part_pipeline.run_part` orchestrator the CLI uses; `POST /apply` — beyond what the CLI itself does — runs that script for real from the browser behind a one-shot CSRF token (`hmac.compare_digest`) and a loopback Origin/Host check, gated behind an in-page confirm modal that echoes the backup bookmark; `POST /rollback` runs `jj op restore <rescue_op_id>` to undo it). `--serve --lan <ip> --cert <path> --key <path>` additionally binds a second, TLS-wrapped, read-only server (mkcert-issued cert/key) on a LAN-routable IP and a separate port (`12701` default) so a reviewer can browse the cut list from another device; its handler implements only `do_GET`, so every mutating route (reclassify/repart/restack/apply/rollback/range/pr/suggest-apply, all POST-only) is structurally unreachable off the loopback server. Under `--pr --serve` reclassifications persist to a durable per-PR sidecar store OUTSIDE the throwaway clone, so they survive the next run's clean-slate wipe and re-layer onto the cut. The served report headlines the cut shape (`N parts across M buckets · cap none|<n>`) so a no-cap cut reads as intentional. `--describe/--no-describe` (and `--describe-model`) is an optional advisory pass that names each commit's subject line with a local OpenAI-compatible model (Ollama/OMLX/llama.cpp via `CALIPER_DESCRIBER_*` env); fail-soft to the deterministic per-bucket subject. The model only rewrites the cosmetic prose tail — caliper prepends the deterministic `type(scope):` prefix and the describer config stays OUT of `config_digest`, so the cut, classification, and provenance remain 100% deterministic and LLM-free. `--suggest/--no-suggest` (and `--suggest-model`, `--suggest-apply`) is an optional "Sorting Hat" pass that asks a local OpenAI-compatible model to propose `parting.overrides` globs for the untiered `logic` residual; the model is OFF the decision path and only authors glob strings, while the deterministic boundary (`core/tier_suggester.validate_suggestions`) enforces a subset guard (a suggested glob may only tier currently-`logic` files, never steal an already-tiered one), dedupe, existing-glob drop, and a 25-rule cap. Fail-soft to `[]`; suggester config is env/CLI-driven and stays OUT of `config_digest` (only globs a human accepts change provenance). Print-only by default; `--suggest-apply` writes the accepted globs and re-parts. Under `--serve`, a "✨ suggest tiers" button (`POST /suggest`) renders each proposal as an accept chip that reuses `/reclassify`. `--doctor` (#526, `cli/part_doctor.py`) checks the environment and exits (no cutting): jj/git presence + version, which execution backend `detect_backend` will actually pick (never drifts from the real gate), `gh auth status` (needed for `--pr`), the `--pr` state workdir is writable, and — with `--serve --lan` — `mkcert` presence; prints a PASS/FAIL report and exits non-zero if anything failed. A re-run of `--pr` on a moved head (#524) reuses the durable per-PR override store and re-cuts as always, then diffs the new cut against the previous run's `cutlist.json` (read via `core/parting.diff_cutlists` before the clean-slate wipe destroys it) and echoes added/removed/moved files plus part-count drift to the CLI — the header names the head-sha transition explicitly and calls out when a change happened on an *unmoved* head (config/override edit, not new commits), so a size-cap tweak between runs never misreads as "the PR moved." `--post-comment` (#524, requires `--pr`; incompatible with `--serve`) is the foreman/CI comment mode: after the cut, posts an advisory GitHub PR comment (`cli/part_comment.render_part_comment`, via `adapters.github_publisher.GitHubPublisher`) proposing the cut for review — no restack/jj instructions, purely informational; nothing is applied by posting it. `--push` (#524, requires `--pr`; incompatible with `--serve` and `--target series`) opens the cut as a sequential stack of new PRs: `core/part_stack.plan_stack` (pure, no IO) computes each part's local ref (the `caliper-part-<i>` bookmark `render_restack_script` already creates under `target=stack`), a deterministic remote branch name, and the chained base (part N bases on part N-1's remote branch, part 1 on the PR's actual base branch — `ResolvedPr.base_branch`, distinct from the merge-base sha in `.base`). `cli/part_push.run_push` then materializes the stack by running the generated `restack.sh` (the exact `ToolInvocation` shape `part_session.py`'s `/apply` already uses), pushes each part and opens its PR via the new `PullRequestPublisherPort.create_pull_request`, stopping at the first failure with no silent partial success. The original PR is left open and untouched; a linking comment (`part_comment.render_stack_link_comment`) listing every opened PR URL is posted on it only once the full stack opens successfully — a failure to post that comment is non-fatal and never rolls back the already-opened PRs. Retry/resume of a partially-failed stack is explicitly out of scope. |
| `caliper baseline` | Deterministic finding suppression with expiry, no LLM. Subcommand `update` scans the repo the same way `caliper evaluate` does (ScanOrchestrator + `normalize_findings`) and writes a sha256 fingerprint (source_tool, category, package_name, version, advisory_id-or-description, normalized file path — **not** line_number, so line drift never invalidates a suppression) for every unbaselined finding into `.caliper-baseline.yaml`, each entry requiring `--reason` and defaulting to `baseline.default_ttl_days` (90) from `.caliper.yaml`. Re-running against an unchanged finding set is a no-op. `core/pipeline.ReviewPipeline._run_requests` filters findings against the baseline before policy evaluation; an expired entry fails **safe** — the finding returns to the policy-evaluated set rather than being silently dropped — and `ReviewDecision.baseline_suppressed_count`/`baseline_expired_count` plus a per-package `baseline.json` evidence artifact record what was filtered. |

---

## Output Formats

Every format shares one severity vocabulary: `critical`/`high`/`medium`/`low`/`info` (`core/models.py` `FindingSeverity`). `normalize_finding` maps any plugin's raw value (semgrep ERROR/WARNING/INFO, OSV `moderate`, upper-case variants) onto it before rendering, so no consumer special-cases a plugin.

| Format | Where | Description |
|--------|-------|-------------|
| Markdown PR comment | `templates/comment.md.j2` | Verdict badge, health score (0-100), maintainability grade, per-plugin summary table, detailed sections. 65536 char max with truncation. |
| SARIF v2.1.0 | `core/sarif.py` | GitHub Security tab integration. Severity-to-level mapping. Configurable max findings cap. Detect-then-scribe packets surface in each result's `properties.scribe` (parity with the JSON report). |
| Inline PR review | `core/pr_review.py` | SARIF → GitHub PR review. Hunk-aware line placement. REQUEST_CHANGES on reject, COMMENT on approve_with_constraints. Outside-diff findings in collapsed summary. |
| JSON decision | CLI `--output-json` | Machine-readable decision with all findings, policy evaluation, and evidence. |
| OpenVEX v0.2.0 | `core/vex.py` | `caliper review --format vex`. One statement per vulnerability finding: reachability scribe `reachable=False` → `not_affected` (justification `vulnerable_code_not_in_execute_path`); blocking severity → `affected` with upgrade guidance; otherwise `under_investigation`. Worst-status-wins dedup across plugins; deterministic content-addressed `@id`. |

---

## Integrations

| Integration | File | Description |
|-------------|------|-------------|
| GitHub Action | `action.yml` | Composite action: diff → evaluate → PR comment (upsert) → check warning on reject. |
| Webhook server | `src/caliper/webhook/server.py` | Starlette ASGI. GitHub PR webhooks (opened/synchronize/reopened). HMAC-SHA256 signature validation. Port 12800. |
| Jenkins | `jenkins/vars/dependencyAdmission.groovy` | Shared library for Jenkins pipelines. |
| Container | `Dockerfile` | Podman/Docker. Read-only workspace mount. |
| Third-party plugin SDK | `src/caliper/plugins/__init__.py`, `docs/PLUGIN_SDK.md` | External packages publish `ScannerPlugin`/`AnalyzerPort` implementations under the `caliper.plugins` `importlib.metadata` entry-point group; `get_default_registry()` discovers them alongside the 14 in-tree plugins. Fail-open per entry point (a broken third-party plugin is logged and skipped, never crashes discovery) and fail-open on the entry-point lookup itself. |

---

## Core Pipeline Capabilities

| Capability | File | Description |
|------------|------|-------------|
| Parallel scanning | `core/orchestrator.py` | ThreadPoolExecutor with combined wall-clock timeout. |
| Cross-run scan cache | `core/caching_scanner.py`, `core/scan_cache_key.py`, `data/scan_cache.py` | Opt-in, fail-open read-through cache (ADR-010): keyed on `sha256(git tree SHA, scanner name, caliper version, scan-relevant config digest)`, sqlite-backed under the evidence dir (`ScanCachePort`, `SCAN_CACHES` registry, `NullScanCache` fallback). `CachingScanner` wraps each `ScannerPort` before orchestrator construction — the orchestrator itself is unchanged. Only `success` results are ever cached; failed/timeout/skipped scans always re-run. Skipped entirely for non-git targets. |
| Unified verdict (SoT) | `core/review_summary.py` | One `summarize_review()` computes verdict + counts + scores; the markdown badge, JSON report, SARIF properties, and CI header/label all consume it (no divergent re-derivation). Diff-scoped gate: only PR-introduced security findings block; pre-existing dependency CVEs are advisory. |
| Detect-then-scribe | `core/scribe.py`, `core/scribe.py` | Post-detection pass (ADR-006): every plugin finding is decorated with deterministic context in `metadata['scribe']` — enclosing symbol (`detectors` scribe), code-graph blast radius (`plugins` scribe), opt-in vulnerability reachability (`plugins` scribe, ADR-009 — declared-vs-imported via the code graph's import edges), opt-in nearby semgrep matches (`plugins` scribe), the opt-in supply-chain-threat LLM narrative (`plugins` scribe), and the opt-in grounding cross-file context (`plugins` scribe, #481 — symbols the finding's file defines plus type-like symbols it references but doesn't define, from the same `GroundingProviderPort` `caliper ground` uses). Sequential, fail-open, time-bounded (`scribe_timeout`); verdict-independent. Pluggable via the `SCRIBES` registry. |
| Vulnerability reachability | `plugins/scribes/reachability.py`, `core/import_resolution.py` | Opt-in scribe (ADR-009): resolves a vulnerable package's distribution name to its import name (curated map → `importlib.metadata` best-effort → heuristic fallback) and checks the code graph for an `imports` edge. Attaches `metadata.scribe.reachability = {reachable: bool\|None, evidence}`. `reachable=false` (declared, never imported) can downgrade a critical/high vuln deny to warn via the opt-in `unreachable_vuln_exemption` OPA rule (T-348); `reachable=None` (unresolved import name, no code graph) never downgrades — absence of evidence is not evidence of absence. |
| Grounding context | `plugins/scribes/grounding.py`, `adapters/grounding.py` | Opt-in scribe (#481): for a finding's file, calls the resolved `GroundingProviderPort` (`grounding_provider` setting — codegraph/ctags/gitnexus, gated by `grounding_enabled`) and attaches `metadata.scribe.grounding = {defined, contracts, provider}` — symbols the file defines and type-like symbols it references but doesn't define, each capped by `grounding_max_symbols`. Memoized per file within one scribe pass (a file with many findings calls the provider once). Fail-open: a provider error yields an empty packet, not a dropped finding. Off unless `grounding_enabled`, in which case the injected provider resolves to the null provider and the scribe is a no-op. |
| Cross-scanner dedup | `core/normalizer.py` | Highest severity wins per (advisory_id, category, package, version). |
| Evidence chain | `core/seal.py` | Blockchain-style SHA-256 seals. manifest hash + previous seal → seal hash. `verify_seal()` detects tampering. |
| Parquet audit log | `data/parquet_writer.py` | Append-only per-run audit trail. Requires the `parquet` extra (`pip install caliper-review[parquet]`); not in the default container image, where the writer fails open. |
| SBOM diff | `core/sbom_diff.py` | Diff two CycloneDX SBOMs: added/removed/upgraded/downgraded across 18 ecosystems. |
| Dependency diff | `core/diff.py` | Git diff parsing for requirements.txt, pyproject.toml, and package.json (npm). |
| Supply-chain version-bump analysis | `core/supply_chain_diff.py`, `data/pkgsrc.py`, `data/supply_chain_scan.py` | Separate gated step (`caliper supply-chain-diff`): fetches both versions of every dependency bump (PyPI sdist / npm tarball, safe extraction with traversal + zip-bomb defenses), diffs the source, and scores deterministic signals — new install hooks (critical), obfuscation/encoded payloads (high), newly introduced network/exec capability (high), publisher change (medium). Signals gate via the OPA `supply_chain_diff` rule; the optional `supply_chain_threat` scribe attaches an advisory LLM narrative (zero-LLM decision path preserved). Fail-open. |
| Health score | `core/renderer.py` | 0-100 severity-weighted score (critical=10, high=5, medium=2, low=1). |
| Monorepo support | `core/manifest_discovery.py` | Walk repo, discover multiple package roots (8 manifest types, 8 lockfile types), run plugins per-package with scoped config merging. |
| Policy engine | `core/policy.py` | OPA subprocess wrapper with fail-open degradation. |
| Topological ordering | `core/plugin_registry.py` | Plugins declare `depends_on` for execution order. `["*"]` = run last. Circular dep detection. |
| Ignore patterns | `core/ignore.py` | `.caliperignore` layered on built-in defaults (VCS, build, venv, IDE dirs) **plus test code** (`tests/`, `test/`, `__tests__/`, `testdata/`, `test_*.py`, `*_test.go`, `*.test.ts`, `*Test.java`, ...): findings in tests are noise for a gate, so they are skipped by default; `caliper review --include-tests` or `CALIPER_INCLUDE_TESTS=1` opts back in. Applied by the file source, manifest discovery, trivy (`--skip-dirs`) and osv-scanner (`--experimental-exclude`). |
| Repo config | `core/repo_config.py` | `.caliper.yaml` — per-plugin enable/disable, thresholds. Root + package-level merge. |
| Structured errors | `core/errors.py` | 10 error codes: NOT_INSTALLED, TIMEOUT, PARSE_ERROR, PERMISSION_DENIED, BINARY_CRASHED, NO_OUTPUT, SCANNER_DEGRADED, CONFIG_MISSING, INDEX_FAILED, NETWORK_ERROR. |

---

## Data Tier

| Component | File | Description |
|-----------|------|-------------|
| Decision repository | `data/db.py` | PostgreSQL persistence + NullRepository fallback. Saves requests, scans, policy evals, decisions. |
| Evidence store | `data/evidence.py` | File-based evidence bundles keyed by run_id + package. |
| Parquet writer | `data/parquet_writer.py` | Append-only Parquet audit log per pipeline run. |
| PyPI client | `data/pypi.py` | Package metadata: age, availability. |
| Scanner wrappers | `data/scanners/` | Subprocess wrappers for osv, trivy, syft, scancode. |

---

## Competitive Positioning

**caliper = "is this change safe to ship?"** (vulns, secrets, licenses, supply chain, IaC, blast radius, code smells, policy)

### vs SonarQube

| Capability | SonarQube | caliper |
|------------|-----------|-------|
| Semantic bug detection | Deep per-language rules (25+ languages) | Semgrep AST + 67 custom rules + 29 deterministic detectors |
| Stylistic code smells | Hundreds of built-in rules | Not primary focus |
| Structural code smells | Limited | 12 graph checks (dead code, god functions, SRP, layer violations, circular deps, deep inheritance, stubs) |
| Complexity | Cyclomatic + cognitive | Cyclomatic (Lizard) + MI (Radon for Python, escomplex for JS/TS) — parity |
| Copy-paste | Built-in CPD | Built-in CPD (15 languages) — parity |
| Coverage gating | Ingests lcov/cobertura, gates on % | **Not supported** |
| Dependency vulns | Developer Edition only (paid) | OSV + Trivy (free) |
| SBOM generation | No | Syft CycloneDX (18 ecosystems) |
| License compliance | No | ScanCode SPDX extraction |
| Secret detection | No | Gitleaks (800+ patterns) |
| Supply chain integrity | No | Lockfile integrity, unpinned deps, Docker floating tags |
| IaC security | No | trivy misconfig (CloudFormation/Terraform/K8s/Dockerfile/Helm) + kube-linter |
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
| Repo config | `.caliper.yaml` | Per-repo: plugin enable/disable, per-plugin thresholds, `baseline.path`/`baseline.default_ttl_days`. Root + package-level merge. |
| Finding baseline | `.caliper-baseline.yaml` (path configurable) | Per-repo: deterministic finding suppressions (fingerprint, reason, added, expires), written by `caliper baseline update`. |
| Ignore patterns | `.caliperignore` | Per-repo: fnmatch exclusions, layered on top of every file source. |
| File source | `CALIPER_FILE_SOURCE` | Global: `auto` (git ls-files when usable, else walk), `git`, or `walk`. |
| Gitleaks config | `.caliper/gitleaks.toml` | Per-repo: custom gitleaks rules. |
| ls-lint config | `.ls-lint.yml` | Per-repo: file naming conventions. |
| OPA policy | `policies/policy.rego` | Per-repo: deny/warn rules with toggleable `rules_enabled.*`. |
| Semgrep rules | `policies/semgrep/*.yaml` | Per-repo: custom AST pattern rules. |
| Graph checks | `plugins/_runners/checks.yaml` | Per-repo: custom SQL checks against code graph. |
