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
