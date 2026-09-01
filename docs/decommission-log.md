# Decommission Log

Features deliberately removed from caliper, with the archive point that still holds the code. The product thesis is a deterministic CI review gate with zero LLM in the decision path; anything below was cut because it was dead, off-thesis, or both.

**Recovery:** every entry names a git tag. `git show <tag>:<path>` prints a removed file; `git checkout <tag> -- <path>` restores it into the working tree. Tags are local until pushed.

## Archive tag: `archive/pre-cut-tier1`

Points at `17eb7d6` (main as of 2026-09-01, release 0.2.30 plus the pyrefly type-checker commit). Every cut listed under this tag is recoverable from it.

### 1. `caliper audit` and the concern-review LLM fan-out (2026-09-01)

**What it was.** A CLI command that clustered repo files into "concerns", ran the scanners, then fanned each cluster out to an LLM (default: a free OpenRouter model) for a holistic review. A sibling module asked the same LLM for a failing test plus a patch per finding.

**Why it was cut.**

- Contradicted the product thesis: an LLM code reviewer shipped in the binary whose README says "no AI detected a potential issue".
- Sent source to a third-party free model by default.
- Abandoned: docstrings still used pre-rename names ("dom", "Alley-Oop"); the only commits ever touching it were tree-wide mechanical refactors.
- Its two idempotency guard tests pointed at the files' old `core/` paths and had been silently skipping since the move to `data/`.
- The June 2026 LLM-review spec (`docs/llm-review/`) already concluded it was not the base for future work because of its direct-httpx-in-core leak.

**Removed.**

| Path | Lines |
|---|---|
| `src/caliper/cli/audit_cmd.py` | 79 |
| `src/caliper/data/concern_review.py` | 494 |
| `src/caliper/data/concern_prompt.py` | 199 |
| `src/caliper/data/concern_remediate.py` | 234 |
| `tests/unit/test_concern_review.py` | 571 |
| `tests/unit/test_concern_remediate.py` | 181 |

**Also cleaned.** The `audit` registration in `cli/main.py`; the `_AUDIT_SUFFIXES` constant in `cli/cli_shared.py`; the `default_llm_model` / `default_llm_endpoint` settings in `core/config.py` (only these modules read them) and their two tests in `test_config.py`; the two always-skipping guard tests in `test_deterministic_idempotency_guards.py`; a docstring in `tests/unit/plugins/test_semgrep_plugin.py` that named the remediation module as its consumer.

**Not touched.** `docs/llm-review/*` and `docs/reviews/*` still reference these modules as historical analysis; they are records, not live docs.

### 2. Issue solver (2026-09-01)

**What it was.** `data/solver.py` read a GitHub issue, built a prompt, and asked an OpenRouter-hosted model (free tier by default in the wrapper script) to generate a detector test, with a model fallback ladder and rate-limit backoff. Its only caller was `scripts/solve-issues.py`.

**Why it was cut.**

- Dev-automation experiment shipped inside the user-facing wheel under the `data` tier; no source, CLI, Action, README, or CAPABILITIES reference.
- Second module found that posts source-derived prompts to a third-party free model endpoint by default.
- Has an LLM write tests, which contradicts the repo's own RED-first TDD rule.
- No feature work after its first day (2026-04-29); only tree-wide sweeps touched it since.

**Removed.**

| Path | Lines |
|---|---|
| `src/caliper/data/solver.py` | 559 |
| `scripts/solve-issues.py` | 306 |
| `tests/unit/test_solver.py` | 557 |

**Also cleaned.** Nothing else referenced it.

### 3. Task-fit LLM advisory (2026-09-01)

**What it was.** `core/taskfit.py` asked an LLM whether a package was proportionate for its stated use across eight dimensions; `core/taskfit_validator.py` rejected any response missing a dimension. Gated behind `CALIPER_LLM_ENABLED`, default off.

**Why it was cut.**

- Unreachable: nothing in `src/` imported either module. The pipeline, renderer, and agent never called it, so the flag could not actually turn anything on. The Foreman agent's task-fit rubric is prompt text in `agent/prompt.py` and is unaffected.
- README and CAPABILITIES advertised it as a live optional feature.
- Off-thesis: an LLM judgment call inside the review package.

**Removed.**

| Path | Lines |
|---|---|
| `src/caliper/core/taskfit.py` | 250 |
| `src/caliper/core/taskfit_validator.py` | 216 |
| `tests/unit/test_taskfit.py` | 544 |
| `tests/unit/test_taskfit_validator.py` | 323 |

**Also cleaned.** The `TestLLMPromptInjection` class in `tests/unit/test_security.py` (it only exercised `TaskFitAdvisor`); stale `taskfit*.py` and never-existing `core/solver.py` entries in three deterministic guard tests; the README tree listing and kerf paragraph; the CAPABILITIES "Task-fit advisory" row.

**Kept for now.** The `llm_enabled` / `llm_endpoint` / `llm_model` / `llm_api_key` settings and `data/llm_client.py` are still used by the supply-chain-threat scribe and `core/llm_port.py`. Revisit when that scribe is decided.

### 4. Org-wide package catalog (2026-09-01)

**What it was.** `data/catalog.py` (`PackageCatalog`, `CatalogEntry`) and `migrations/002_package_catalog.sql`: a PostgreSQL + pgvector table design for scanning each package once org-wide and serving later evaluations as a lookup, with a `scan_queue` table and an embeddings column for semantic search.

**Why it was cut.**

- Unreachable: nothing in `src/` imported it; the pipeline never read or wrote the catalog. Present since the repo's first commit with no feature work since.
- No embeddings are produced anywhere, so the pgvector column and the `CREATE EXTENSION vector` superuser requirement were pure cost and a hard failure on stock Postgres.
- README listed it as a live component.
- The on-thesis successor already exists: the ADR-010 scan cache (tree-SHA keyed, sqlite, no extension).

**Removed.**

| Path | Lines |
|---|---|
| `src/caliper/data/catalog.py` | 342 |
| `migrations/002_package_catalog.sql` | 132 |
| `tests/unit/test_catalog.py` | 422 |
| `tests/unit/test_deterministic_cache_guards.py` | specimen-only guard |
| `tests/unit/test_deterministic_queue_guards.py` | specimen-only guard |
| `tests/unit/test_deterministic_idempotency_guards.py` | specimen-only guard (its other targets were cut in entry 1) |

The three guard files were `xfail(strict=False)` bug detectors whose only specimens were `catalog.py` (and, before entry 1, the concern modules). They documented issue #172-era bugs in code nobody ran and could never fail.

**Also cleaned.** The `catalog.py` entry in `test_deterministic_cache_key_guards.py`; the `catalog.py` and never-existing `core/solver.py` entries in `test_deterministic_eviction_guards.py`; the README data-tier tree line. `test_deterministic_migration_guards.py` still names the migration in a docstring example only.

### 5. Approved-alternatives catalog (2026-09-01)

**What it was.** `data/alternatives.py`: a Pydantic schema for a JSON file mapping packages to categories and "approved alternatives", `requirements.txt` / `pyproject.toml` parsers, a ~30-name hardcoded category table, and `scripts/bootstrap_alternatives.py` to generate the JSON. Meant to let the Foreman agent suggest safer substitutes.

**Why it was cut.**

- Unreachable: nothing in `src/` imported it. `CaliperSettings.alternatives_path` was read by no code; no `alternatives.json` existed; `agent/main.py` never passed `alternatives=` to `build_system_prompt`, so the agent's ALTERNATIVES rubric had no data source.
- First-commit code, untouched except by the rename.
- Wrong home: if it returns, it belongs in OPA data next to the rest of policy. Tracked as [#480](https://github.com/gitrdunhq/caliper/issues/480).

**Removed.**

| Path | Lines |
|---|---|
| `src/caliper/data/alternatives.py` | 197 |
| `scripts/bootstrap_alternatives.py` | 67 |
| `tests/unit/test_alternatives.py` | 451 |

**Also cleaned.** The `alternatives_path` setting and its three assertions in `test_config.py`; the `categorize_package` determinism property test in `test_properties.py`; the README data-tier tree line; the CAPABILITIES "Alternatives catalog" row. The agent prompt's `alternatives` parameter is kept (harmless, independently tested, and the natural hook for #480).

### 6. Grounding provider and `caliper ground` — KEPT (2026-09-01)

Reviewed and kept. `adapters/grounding.py` is deterministic, fail-open, and properly ported, but its only in-product consumer is the `ground` CLI export for external LLM reviewers. Wiring it into the detect-then-scribe pass as an opt-in scribe is tracked as [#481](https://github.com/gitrdunhq/caliper/issues/481). Side note: `caliper ground` is not listed in the CAPABILITIES CLI table.

### 7. Supply-chain-threat LLM scribe — KEPT (2026-09-01)

Reviewed and kept as-is. Opt-in behind two switches (`llm_enabled` plus `supply_chain_threat` in `enabled_scribes`), advisory-only, fail-open, prompt-injection hardened, and reachable from `caliper supply-chain-diff`. It is the one deliberate LLM touchpoint in the scan path; the narrative never changes severity or verdict.

### 8. `detectors/_sample_detectors.py` (2026-09-01)

Thirteen-line re-export of four registered detectors "for framework demonstration". No references anywhere, no `# tested-by:` annotation. Deleted; the detectors themselves are unaffected.

### 9. `caliper reinstall` moved to `make reinstall` (2026-09-01)

**What it was.** A CLI subcommand that located the caliper checkout via `git rev-parse`, validated it, and ran `scripts/install-local.sh` to rebuild and reinstall the `caliper` uv tool with a unique local version suffix.

**Why it moved.** Dev-only, but shipped in the public CLI: every PyPI/container user got a subcommand that assumes a git checkout of caliper's own source and rewrites `pyproject.toml`. The script already did all the work.

**Removed.** `src/caliper/cli/reinstall_cmd.py` (143 lines), `tests/unit/test_reinstall_cmd.py` (164 lines), the CLI registration, and the CAPABILITIES row (CLI command count 11 -> 10).

**Kept.** `scripts/install-local.sh`, now invoked by the new `make reinstall` target.

### 10. `caliper query` — KEPT, renamed in docs (2026-09-01)

Reviewed and kept. Twelve canned SQL templates over the code graph, chosen by keyword overlap. Reachable, tested, deterministic. The docs called it a "natural language" / "NL query" system, which oversold keyword matching; README, CAPABILITIES, and the command docstring now describe it as code graph queries. Module and test file names (`nl_query`) are unchanged to avoid churn.

## Archive tag: `archive/pre-cut-tier2`

Points at `9f5de1d` (main after the Tier 1 merge plus the ratchet-allowlist fix, 2026-09-01).

### 11. The flywheel: `caliper inspect`, `caliper gauge`, `caliper eval` (2026-09-01)

**What it was.** Three commands built together on 2026-06-29. `inspect` took a `caliper part` cut list, ran deterministic "Screen" gauges per part, optionally asked an LLM for review claims, filtered them through a pure "Adjudicate" function, and appended survivors and drops to a claims ledger. `gauge` clustered the ledger, had an LLM draft candidate gauges, backtested them deterministically, and let a human promote one into a permanent Screen gauge. `eval` scored the Adjudicate filter against a seeded-bug corpus. ADR-008 and `docs/llm-review/` document the design.

**Why it was cut.**

- It never touched the gate: nothing in `review`, `evaluate`, the plugins, scribes, or composition root imported it. A promoted gauge became active only in inspect's own Screen tier, so the CI gate users run gained nothing from flywheel curation.
- It could not run without Tier 3: `caliper inspect` required a `cutlist.json` from `caliper part`.
- It was a research program for making LLM review trustworthy, which is the problem the product says it sidesteps. One-day build, no feature work since, no open issues.

**Removed.**

| Area | Files |
|---|---|
| `core/` | `inspect.py`, `inspect_eval.py`, `inspect_runner.py`, `inspect_gauges.py`, `inspect_view.py`, `inspect_cache.py`, `gauge.py`, `gauge_engine.py`, `gauge_propose.py`, `gauge_status.py`, `flywheel.py`, `ledger.py`, `tool_crib.py`, `backtest.py` |
| `data/` | `_inspect_llm.py` |
| `cli/` | `inspect_cmd.py`, `gauge_cmd.py`, `eval_cmd.py` |
| `scripts/` | `try-caliper-on-pr.sh` (a `part` -> `inspect` runner; `caliper part --pr` covers the `part` half natively) |
| tests | 14 unit files (`test_inspect_*`, `test_gauge_*`), 2 integration files (`test_inspect_cli.py`, `test_gauge_cli.py`) |

Roughly 2,600 source lines and 2,200 test lines.

**Also cleaned.** `core/llm_port.py` trimmed to just `LLMTransportPort` (the kept supply-chain-threat scribe's seam); `INSPECT_BACKENDS` and `GAUGE_DRAFTERS` registries; the inspect and gauge model section of `core/models.py` (`Severity`, `Category`, `Confidence`, `Claim`, `GaugeFinding`, `GaugeResult`, `DroppedClaim`, `InspectionReport`, `LedgerEntry`, `ClaimCluster`, `Backtest`, `CandidateGauge`, `Promotion`); `InspectConfig`, `GaugeConfig`, their research-fed default tables, and their merge handling in `core/repo_config.py`, which changes the published `.caliper.yaml` schema; the README Inspect and Gauge sections; three CAPABILITIES CLI rows (CLI command count 10 -> 7); the inspect/gauge merge test in `test_repo_config_merge.py`.

**Kept.** `cli/inspect_cmds.py` (despite the name it holds `healthcheck`, `check-health`, `plugins`, `schema`); `data/llm_client.py` and `tests/unit/test_llm_client.py`; `scripts/cutlist_report.py` (its inspect input was optional); ADR-008 and `docs/llm-review/` as historical records.

**Worth salvaging later.** The Adjudicate filter's anchor-quote rule: a claim's quoted text had to appear verbatim in the part's changed text before its line numbers were trusted. It is a reusable anti-hallucination primitive for any future LLM consumer. It lived in `core/inspect.py` at the archive tag.

## Archive tag: `archive/pre-scanner-audit`

Points at `07ee6d2` (main after the Tier 2 merge, 2026-09-01). The scanner audit that followed the feature cuts; fixes and cuts land on `chore/scanner-audit-fixes`.

### 12. cfn-nag, cdk-nag, swiftformat plugins (2026-09-01)

**What they were.** `cfn-nag`: CloudFormation template scanning via the Ruby `cfn-nag` gem. `cdk-nag`: `cdk synth` of the target (Node + a pinned `aws-cdk`) followed by `cfn_nag_scan` over the output. `swiftformat`: Swift formatting lint reported as review findings.

**Why they were cut.**

- cfn-nag pulled Ruby into the image for one tool, and Trivy's config scanner covers CloudFormation natively; its e2e test was already `xfail` as flaky.
- cdk-nag depended on `cfn_nag_scan`, required a full `cdk synth` of the target inside the scanner (Node, npm, aws-cdk in the image), and its e2e test only asserted that it completed. A CDK repo that commits or CI-synthesises `cdk.out/` gets the same coverage from Trivy.
- swiftformat is a formatter; "file needs reformatting" belongs in pre-commit, not a CI review gate. swiftlint stays for Swift users.

**Replacement.** `trivy fs --scanners vuln,misconfig --skip-check-update` (commit `96c9667`): CloudFormation, Terraform, Kubernetes, Dockerfile, Helm misconfigurations with file, line, and resolution, using the checks embedded in the pinned trivy release.

**Removed.** `plugins/cfn_nag.py`, `plugins/cdk_nag.py`, `plugins/swiftformat.py`, `plugins/_runners/cfn_nag_runner.py`, `plugins/_runners/cdk_nag_runner.py`, their three unit test files, the cfn/cdk e2e tests (replaced by `test_trivy_finds_iac_misconfig`), and from the image: Node.js 22, npm, `aws-cdk`, Ruby, `ruby-dev`, `build-essential`, `gnupg`, the `cfn-nag` gem, and the SwiftFormat binary. Plugin count 19 -> 16 auto-discovered (17 with `deterministic`).

### 13. Blast-radius `layer_violation` and `missing_tested_by` checks (2026-09-01)

`layer_violation` duplicated the CAL-017/CAL-022 tier-boundary detectors and the architecture guard test. `missing_tested_by` could not see the annotation (the symbols table has none) and listed every changed `.py` file, so it was pure noise; CAL-014 owns that check in the `house-rules` profile. 12 -> 10 code graph checks (commit `5d7a627`).

### Scanner audit fixes that were not cuts

- Semgrep community rules pinned to a `semgrep-rules` commit baked into the image; registry packs never fetched; org rules applied to every target (`b948a18`).
- Complexity reports only functions above `thresholds.complexity.ccn` (`b1e2e23`).
- Detector profiles: `default` (12 general bugs) on, `house-rules` (10 caliper conventions) opt-in (`5f486fc`).
- Review scope documented; dogfood D2 closed (`0a9fea8`).

### 14. `caliper part` — KEPT, invest (2026-09-01)

Tier 3 decision: keep `caliper part` in caliper and make it excellent rather than extract or cut it. Roadmap and definition of done in [#482](https://github.com/gitrdunhq/caliper/issues/482) (git-native restack, classification corpus + scoring, per-part diff preview in the SPA, PR push flow, docs). It remains isolated from the review pipeline via the `PARTING` registry.

## Archive tag: `archive/pre-cut-foreman`

Points at `a3e7eec` (2026-09-01, end of the scanner audit branch).

### 15. Foreman Copilot agent (2026-09-01)

**What it was.** `src/caliper/agent/`: a second presentation-tier entry point (`python -m caliper.agent.main`) wrapping the review pipeline as a GitHub Copilot Extension, with six `@tool` functions, an eight-dimension task-fit rubric in its system prompt, `FOREMAN_*` settings, and enforcement modes. ADR-001 through ADR-004 record its design.

**Why it was cut.**

- Pinned to `agent-framework-github-copilot==1.0.0rc1`, a release candidate, and never included in the container image.
- No Copilot users; the CI workflow that carries the "Foreman" name (`.github/workflows/foreman.yml`) runs the CLI via composite actions and never invoked the agent.
- Its `scan_code` tool was the only caller of `build_default_scribes`, and its prompt was the last home of the task-fit rubric cut in entry 3.

**Removed.** `src/caliper/agent/` (6 files, ~1,400 lines); `tests/unit/test_agent_*.py`, `test_copilot_agent_profiles.py`, `test_deterministic_agent_block_mode_guards.py`, `test_deterministic_sbom_mutation_guards.py`; the agent-only tests in `test_deterministic_runtime_contracts.py` and `test_deterministic_eviction_guards.py`; `scripts/gauntlet.py` and `scripts/generate-pr-comment.py` (both imported the agent); `build_default_scribes`; the `agent` tier in `core/tier_map.py`.

**Also changed.** The `copilot` extra is now `webhook` (starlette + uvicorn only; the agent framework is gone from `uv.lock`). README, CLAUDE.md, WHY.md, ARCHITECTURE.md, CAPABILITIES, and the elevator pitch no longer describe a second entry point; the README workflow snippet runs `caliper review --diff ... --pr N` instead.

**Kept.** `.github/workflows/foreman.yml` (the CI job, unrelated to the agent module), the webhook server, `docs/adr/001-004` as historical records.

## Archive tag: `archive/pre-cut-telemetry`

Points at `1d3736b` (2026-09-01, after the Foreman cut).

### 16. Opt-in telemetry and the CAL-013 detector (2026-09-01)

**What it was.** `core/telemetry.py` (a Pydantic `TelemetryEvent` with nine signals, `extra="forbid"`, file-path stripping) and `data/telemetry_sender.py` (fire-and-forget POST to `https://telemetry.caliper.dev/v1/events`), configured by `telemetry.enabled`/`telemetry.endpoint` in `.caliper.yaml`. `CAL-013` ("Config Merge Dropping Telemetry") existed solely to guard that config section against the #262 merge bug.

**Why it was cut.**

- Nothing in `src/` ever constructed an event or called the sender; only the config section and a cluster of guard tests referenced it. Dead code with a public endpoint in it.
- No backend is known to listen at the endpoint.
- CAL-013 had no purpose once the section it guarded was gone; its id is retired, never reused.

**Removed.** `core/telemetry.py`, `data/telemetry_sender.py`, `detectors/config/config_merge.py`, `TelemetryConfig` and its merge handling in `core/repo_config.py`, and the tests: `test_telemetry.py`, `test_deterministic_telemetry_merge_guards.py`, `test_deterministic_metrics_guards.py`, `test_deterministic_config_guards.py`, `detectors/config/test_config_merge.py`, plus the telemetry cases in `test_repo_config_merge.py`, `test_deterministic_runtime_contracts.py`, and `test_deterministic_feature_flag_guards.py`. Detector count 22 -> 21 (house-rules profile 10 -> 9).
