---
name: caliper-config-and-flags
description: Catalogs every caliper configuration axis - CaliperSettings pydantic fields and their CALIPER_* env vars, the .caliper.yaml RepoConfig schema, OPA rules_enabled toggles and their defaults, and the miscellaneous CALIPER_* env vars outside CaliperSettings (webhook, describer, suggester, graph db, state dir, host-test bypass). Load this skill when asked "what does CALIPER_X do", "what's the default for Y", "how do I turn on/off an OPA rule", "how do I add a new config flag/setting", "what goes in .caliper.yaml", or before editing core/config.py, core/repo_config.py, core/opa_input.py, or policies/policy.rego's rules_enabled gates. Do NOT load for OPA rule *authoring*/Rego syntax (use caliper-opa-policy-playbook), for running/operating caliper day-to-day (use caliper-run-and-operate), or for container build scripts (use caliper-build-and-env).
---

# Caliper Config & Flags

Every knob caliper has, where it lives, what it defaults to, and how to
verify that hasn't drifted since 2026-07-02 (the date every fact below was
checked against the actual repo at commit `c78154b`).

## When NOT to use this skill

| If you need to... | Use instead |
|---|---|
| Write/modify an OPA Rego rule, understand `deny`/`warn` set semantics, add a new `T-xxx` rule | `caliper-opa-policy-playbook` |
| Run `caliper review`, the `cal` alias, or operate a scan day-to-day | `caliper-run-and-operate` |
| Build/push the container image, understand podman-vs-docker flag differences | `caliper-build-and-env` |
| Understand the ports-and-adapters tier boundaries, not config | `caliper-architecture-contract` |
| Write a new scanner plugin | `caliper-plugin-authoring-playbook` |
| Follow TDD red/green process, commit discipline, PR process for a config change | `caliper-change-control`, `caliper-testing-and-tdd` |

This skill is purely a **map of configuration surface** — what exists, what
it defaults to, and how to add to it safely. It does not explain *why* a
given OPA rule fires or *how* to run the scanner.

## Jargon, defined once

- **`CaliperSettings`** — the one pydantic-settings class
  (`src/caliper/core/config.py`) that maps every `CALIPER_*` env var to a
  typed field. This is process-wide, ambient config (timeouts, DSNs,
  feature toggles for LLM/grounding/supply-chain-diff subsystems).
- **`.caliper.yaml` / `RepoConfig`** — per-repo, version-controlled config
  (`src/caliper/core/repo_config.py`) for the repo *being scanned* — plugin
  allow/disable lists, `caliper part` tuning, thresholds. Loaded fresh per
  invocation from the target repo's working tree, not from env vars.
- **`rules_enabled`** — a dict of booleans inside the OPA `input.config`
  payload (`src/caliper/core/opa_input.py`) that gates individual
  `policies/policy.rego` deny/warn rules on or off. **Not** a `CaliperSettings`
  field and **not** currently wired to `.caliper.yaml` — see the OPA section
  below, this is a real gotcha.
- **fail-open** — see `CLAUDE.md` / `caliper-fail-open-resilience`: a config
  or subsystem failure never blocks the pipeline; it degrades to a safe
  default (usually `needs_review` or "rule doesn't fire").

## 1. `CaliperSettings` — env-var-driven process config

Source: `src/caliper/core/config.py`. `model_config = SettingsConfigDict(env_prefix="CALIPER_", case_sensitive=False)` — **every** field below is automatically also `CALIPER_<FIELD_NAME_UPPER>`; there is no allowlist step, so adding a pydantic field *is* adding an env var.

Verified 2026-07-02 via `uv run python .claude/skills/caliper-config-and-flags/scripts/dump_settings.py` — **33 fields**, reproduced here verbatim:

| Field | Env var | Default | Status |
|---|---|---|---|
| `operating_mode` | `CALIPER_OPERATING_MODE` | `monitor` | production |
| `db_dsn` | `CALIPER_DB_DSN` | `None` | production (unset → `NullRepository` fallback, decisions not persisted) |
| `evidence_path` | `CALIPER_EVIDENCE_PATH` | `./evidence` | production |
| `scanner_timeout` | `CALIPER_SCANNER_TIMEOUT` | `60` | production |
| `combined_scanner_timeout` | `CALIPER_COMBINED_SCANNER_TIMEOUT` | `180` | production |
| `opa_timeout` | `CALIPER_OPA_TIMEOUT` | `10` | production |
| `llm_timeout` | `CALIPER_LLM_TIMEOUT` | `30` | production |
| `pipeline_timeout` | `CALIPER_PIPELINE_TIMEOUT` | `300` | production |
| `pypi_timeout` | `CALIPER_PYPI_TIMEOUT` | `10` | production |
| `osv_exclude_paths` | `CALIPER_OSV_EXCLUDE_PATHS` | `["tests/e2e/fixtures"]` | production — see `CLAUDE.md` "Scanner Exclusions" |
| `file_source` | `CALIPER_FILE_SOURCE` | `auto` | production — `auto\|git\|walk`, see `core/file_source.py` |
| `opa_policy_path` | `CALIPER_OPA_POLICY_PATH` | `./policies/policy.rego` | production |
| `enabled_scanners` | `CALIPER_ENABLED_SCANNERS` | `["syft", "osv-scanner", "trivy"]` | production (`scancode` is orphaned — comment in `config.py` says its transitive dep lacks arm64 wheels) |
| `enabled_scribes` | `CALIPER_ENABLED_SCRIBES` | `["enclosing_symbol", "code_graph"]` | production (ADR-006). `semgrep` scribe is opt-in, deliberately absent from default |
| `scribe_timeout` | `CALIPER_SCRIBE_TIMEOUT` | `30` | production |
| `llm_enabled` | `CALIPER_LLM_ENABLED` | `False` | opt-in — task-fit advisory subsystem |
| `llm_endpoint` | `CALIPER_LLM_ENDPOINT` | `None` | opt-in, paired with `llm_enabled` |
| `llm_model` | `CALIPER_LLM_MODEL` | `None` | opt-in |
| `llm_api_key` | `CALIPER_LLM_API_KEY` | `None` | opt-in — `SecretStr` (F-021: never logged) |
| `default_llm_model` | `CALIPER_DEFAULT_LLM_MODEL` | `claude-haiku-4-5-20251001` | production, but for the concern-review fan-out subsystem only (`core/concern_review.py`), always-on and independent of `llm_enabled` |
| `default_llm_endpoint` | `CALIPER_DEFAULT_LLM_ENDPOINT` | `https://api.anthropic.com` | production, same subsystem as above |
| `supply_chain_diff_enabled` | `CALIPER_SUPPLY_CHAIN_DIFF_ENABLED` | `False` | opt-in — needs registry egress, not part of a normal scan |
| `supply_chain_diff_timeout` | `CALIPER_SUPPLY_CHAIN_DIFF_TIMEOUT` | `60` | opt-in |
| `supply_chain_diff_ecosystems` | `CALIPER_SUPPLY_CHAIN_DIFF_ECOSYSTEMS` | `["pypi", "npm"]` | opt-in |
| `supply_chain_diff_max_archive_bytes` | `CALIPER_SUPPLY_CHAIN_DIFF_MAX_ARCHIVE_BYTES` | `67108864` (64 MiB) | opt-in |
| `grounding_enabled` | `CALIPER_GROUNDING_ENABLED` | `False` | opt-in — code-grounding producer/consumer step, gated + on-demand |
| `grounding_provider` | `CALIPER_GROUNDING_PROVIDER` | `auto` | opt-in |
| `grounding_timeout` | `CALIPER_GROUNDING_TIMEOUT` | `60` | opt-in |
| `grounding_max_symbols` | `CALIPER_GROUNDING_MAX_SYMBOLS` | `40` | opt-in |
| `gitnexus_graph_path` | `CALIPER_GITNEXUS_GRAPH_PATH` | `None` | opt-in, paired with grounding |
| `alternatives_path` | `CALIPER_ALTERNATIVES_PATH` | `./alternatives.json` | production |
| `scancode_timeout` | `CALIPER_SCANCODE_TIMEOUT` | `60` | dormant — `scancode` scanner is orphaned (see `enabled_scanners` note); field exists but the plugin it tunes isn't wired in `_SCANNERS_DEFAULT` |
| `scancode_license_score` | `CALIPER_SCANCODE_LICENSE_SCORE` | `0` | dormant, same as above |

**List-valued env vars accept comma-separated strings**, not just JSON: `CALIPER_ENABLED_SCANNERS=syft,trivy` works because `CaliperSettings` installs a custom `_CommaSeparatedEnvSource` (`config.py`) that falls back to comma-splitting when `json.loads()` fails — including a single value with no comma (`CALIPER_SUPPLY_CHAIN_DIFF_ECOSYSTEMS=pypi`), which would otherwise fail list validation.

**Special case — never use in scripts/CI you write:** `CALIPER_ALLOW_HOST_TESTS=1` bypasses the container-only test guard in `tests/conftest.py`. Per `CLAUDE.md` and `caliper-testing-and-tdd`, this is reserved for `make test-host` (an explicit escape hatch) and pinned CI workflow steps that already run inside a container equivalent (`release-candidate.yml`, `foreman.yml`) — it is **not** a general-purpose flag and `tests/unit/test_github_actions_policy.py` asserts it's absent from other workflow run blocks. Do not set it locally to skip the container.

## 2. `.caliper.yaml` — per-repo `RepoConfig`

Source: `src/caliper/core/repo_config.py`. Loaded via `load_repo_config(repo_path)` — absent file → `RepoConfig()` all-defaults (never an error); malformed YAML or a schema violation → `ValueError` (fails loud, does not fail-open, because a human wrote this file and a typo should be caught, not silently ignored).

Top-level `RepoConfig` fields (all optional, all have defaults):

| Key | Model | Purpose |
|---|---|---|
| `plugins` | `PluginConfig` | `enabled`/`disabled` scanner-plugin allowlist/denylist + nested `semgrep.extra_config_dirs` / `semgrep.exclude_rules` |
| `thresholds` | `dict[str, dict]` | free-form per-check threshold overrides (e.g. `blast-radius.graph_db`) |
| `telemetry` | `TelemetryConfig` | `enabled` (default `False`) + `endpoint` for anonymous opt-in telemetry |
| `parting` | `PartingConfig` | `caliper part` tuning — `size_cap`, `target`, rename/copy thresholds, the 10 taxonomy glob lists, `overrides` (the human reclassify table), `validate_command` |
| `inspect` | `InspectConfig` | `caliper inspect` per-part review knobs — `token_budget`, `backend`, `allowed_categories`, `severity_floor`, `bucket_gauges`, `llm_buckets`, `allow_missing_gauges` |
| `gauge` | `GaugeConfig` | `caliper gauge` flywheel — eligibility/recurrence/backtest thresholds |
| `baseline` | `BaselineConfig` | `caliper baseline` suppression file path + default TTL |
| `architecture` | `ArchitectureConfig` | opt-in CAL-022 tier-boundary enforcement — `package`, `src_root`, `tiers`, `allow` (empty by default: unconfigured means CAL-022 never fires) |

Real example, this repo's own `.caliper.yaml` (verified 2026-07-02):

```yaml
plugins:
  disabled:
    - mypy
    - blast-radius
    - clamav
```

**Package-level merge**: `load_merged_config(repo_path, package_root)` merges a subdirectory's own `.caliper.yaml` over the root one — `plugins.enabled`/`disabled`/`semgrep`, `thresholds` (per-key), `telemetry`, `parting`, `inspect`, and `gauge` all merge with package-level taking precedence when set. **`baseline` and `architecture` are not part of `load_merged_config`'s explicit merge list** (verified against `repo_config.py:564-570`, 2026-07-02) — a package-level `.caliper.yaml` currently falls back to root for those two only insofar as the root object is reused wholesale; if this matters for your task, re-read `load_merged_config` before relying on it, since this is exactly the kind of thing that silently regresses (see the `#262`/`#442` comments in that file — two prior bugs of precisely this shape).

**Rule for adding a new `.caliper.yaml` key**: add the field to the relevant `BaseModel` in `repo_config.py` with a sensible default (unconfigured must mean "off"/"no-op", never a surprise), and if it's one of the six merge-tracked configs, add it to both the `merged_*` variable list and the final `RepoConfig(...)` call in `load_merged_config` — a field that's easy to add to the model and easy to forget in the merge function is exactly how `#262`/`#442` happened.

## 3. OPA `rules_enabled` — policy-rule toggles

Source: `src/caliper/core/opa_input.py` (`_DEFAULT_RULES_ENABLED`, `_DEFAULT_CONFIG`) — the **single canonical place** these defaults live (the module docstring documents that before it existed there were three drifted copies).

**Gotcha, verified 2026-07-02**: `rules_enabled` is **not** a `.caliper.yaml` key and **not** a `CaliperSettings` field. The live production pipeline (`core/pipeline.py:135`) constructs `PolicyInput(..., config={})` — an **empty** config dict — so in a normal `caliper review` run, every rule below runs at its coded-in default. The only way to override `rules_enabled` today is to pass a `config` dict programmatically to `OpaEvaluator.evaluate(...)` / `build_opa_input(...)` (used by tests and the standalone supply-chain-diff path) — there is currently **no CLI flag and no `.caliper.yaml` key** that reaches this dict (confirmed: `grep -n "rules_enabled\|opa" src/caliper/cli/main.py` returns nothing). If you need this to be operator-configurable from `.caliper.yaml`, that's new work, not a documented flag — check `caliper-opa-policy-playbook` or file an issue before assuming it already exists.

Verified 2026-07-02 via `uv run python .claude/skills/caliper-config-and-flags/scripts/dump_rules_enabled.py`:

| Rule key | Default | Rego rule(s) gated | Status |
|---|---|---|---|
| `critical_vuln` | **ON** | T-010 deny (critical/high vuln) + both its warn downgrades | production |
| `forbidden_license` | **ON** | T-011 deny + dev-scope warn downgrade | production |
| `package_age` | **ON** | T-011 deny (age < `min_package_age_days`, default 90) | production |
| `malicious_package` | **ON** | T-011 deny (`MAL-` prefixed advisory) — never downgradable by any exemption | production |
| `transitive_count` | **ON** | T-011 warn (`transitive_dep_count` > `max_transitive_deps`, default 200) | production |
| `supply_chain_diff` | **ON** | T-012 deny (critical/high) + warn (medium) | production |
| `dev_scope_exemption` | off | T-345 helper — downgrades `critical_vuln`/`forbidden_license` deny→warn for `pkg.scope == "dev"` | opt-in |
| `cisa_kev` | off | T-344 deny — advisory_id in operator-supplied `config.kev_ids` (caliper ships none) | opt-in, needs threat-intel input |
| `unmaintained_package` | off | T-346 warn — no release in `max_days_since_release` days (default 365); fail-open if `pkg.last_release_date` absent | opt-in |
| `copyleft_propagation` | off | T-347 deny (strong-copyleft, static/unknown link) + 2 warns (strong-dynamic, weak-any) | opt-in, needs `copyleft_strong`/`copyleft_weak` lists (caliper ships none) |
| `unreachable_vuln_exemption` | off | T-348 helper — downgrades `critical_vuln` deny→warn when the reachability scribe (ADR-009) found `reachable == false`; `null`/missing never downgrades | opt-in, needs the `reachability` scribe enabled via `enabled_scribes` to have any effect |

**Rule count**: see `caliper-opa-policy-playbook` for the current Rego
rule-block count and the `CLAUDE.md` "11 rules" staleness note — this skill
defers to that one rather than re-deriving it.

**Second gotcha — two different defaults for `min_package_age_days`**: the T-011 package-age Rego rule itself has an inline fallback `object.get(input.config, "min_package_age_days", 30)`, but `opa_input.py::_DEFAULT_CONFIG` sets it to `90`. Any caller that goes through `build_opa_input` (i.e. every production and test path) gets **90**. Only a hand-rolled `opa eval` invocation that skips the canonical builder and omits `min_package_age_days` from its input would see Rego's own fallback of **30**. Don't be surprised by a 30-vs-90 mismatch if you ever eval the policy by hand.

Non-`rules_enabled` config knobs (also in `_DEFAULT_CONFIG`, same file):

| Key | Default |
|---|---|
| `forbidden_licenses` | `[]` |
| `max_transitive_deps` | `200` |
| `min_package_age_days` | `90` |
| `copyleft_strong` | `[]` |
| `copyleft_weak` | `[]` |

For Rego syntax, rule-authoring conventions, and `opa test` mechanics, see `caliper-opa-policy-playbook` — this skill only tracks the toggle inventory and defaults.

## 4. Other `CALIPER_*` env vars (outside `CaliperSettings`)

These are read directly via `os.environ.get(...)` in specific modules, not via the pydantic-settings model — they don't show up in `dump_settings.py` above.

| Env var | Read in | Purpose | Status |
|---|---|---|---|
| `CALIPER_ALLOW_HOST_TESTS` | `tests/conftest.py` | bypass container-only test guard | **never use manually** — see section 1 |
| `CALIPER_FILE_SOURCE` | `core/file_source.py` | also mirrored as `CaliperSettings.file_source`; direct-env-read path used by `select_file_source(prefer=...)` when no explicit `prefer` arg is passed | production |
| `CALIPER_STATE_DIR` | `cli/part_pr.py` | overrides the XDG-resolved root for `caliper part --pr`'s throwaway clone + override sidecar workdir | production |
| `CALIPER_GRAPH_DB` | `plugins/_runners/graph_builder.py` | explicit override for the code-graph SQLite db path (resolution order: this env var → `.caliper.yaml` `thresholds.blast-radius.graph_db` → legacy `<repo>/.caliper/code_graph.sqlite` → XDG cache dir) | production |
| `CALIPER_DESCRIBER_MODEL` | `cli/part_describe.py`, `cli/part_suggest.py` (fallback) | model id for the advisory commit-describer / tier-suggester (Ollama/OMLX/llama.cpp) | opt-in, advisory-only, deliberately outside `config_digest` |
| `CALIPER_DESCRIBER_BASE_URL` | `cli/part_describe.py`, `cli/part_suggest.py` (fallback) | base URL for the above | opt-in |
| `CALIPER_DESCRIBER_API_KEY` | `cli/part_describe.py` | API key (falls back to `OMLX_API_KEY`) | opt-in |
| `CALIPER_DESCRIBER_TIMEOUT` | `cli/part_describe.py` | request timeout, default `20`s in code | opt-in |
| `CALIPER_DESCRIBER` | `cli/part_describe.py` | explicit opt-out sentinel (`--no-describe` equivalent via env) | opt-in |
| `CALIPER_SUGGESTER_MODEL` | `cli/part_suggest.py` | model id for the tier-suggester; falls back to `CALIPER_DESCRIBER_MODEL` if unset | opt-in |
| `CALIPER_SUGGESTER_BASE_URL` | `cli/part_suggest.py` | falls back to `CALIPER_DESCRIBER_BASE_URL` | opt-in |
| `CALIPER_SUGGESTER_API_KEY` | `cli/part_suggest.py` | falls back to `OMLX_API_KEY` | opt-in |
| `CALIPER_SUGGESTER_TIMEOUT` | `cli/part_suggest.py` | default `30`s in code | opt-in |
| `CALIPER_SUGGESTER` | `cli/part_suggest.py` | explicit opt-out sentinel | opt-in |
| `CALIPER_WEBHOOK_SECRET` | `webhook/config.py` (`env_prefix="CALIPER_WEBHOOK_"`) | HMAC-SHA256 shared secret for GitHub PR webhook validation | production, secret |
| `CALIPER_WEBHOOK_GITHUB_TOKEN` | `webhook/config.py` | GitHub PAT for posting PR comments | production, secret |
| `CALIPER_WEBHOOK_PORT` | `webhook/config.py` | listen port, default `12800` per `CLAUDE.md` Dev Ports table | production |

All of the describer/suggester knobs are **deliberately outside `PartingConfig`/`config_digest`** — per `CLAUDE.md`, the advisory LLM-driven passes (`--describe`, `--suggest`) must never make the deterministic cut/classification provenance depend on an LLM call. Do not "fix" this by moving them into `.caliper.yaml` without re-reading that constraint first.

## 5. Checklist: adding a new config flag

Pick the right axis first — this is the step people skip:

- **Process-wide, ambient, env-driven** (timeouts, feature toggle for a subsystem, endpoint/credential) → `CaliperSettings` in `core/config.py`.
- **Per-repo, version-controlled, applies to the repo being scanned** (plugin allow/deny, parting/inspect/gauge tuning, architecture tiers) → a field on the relevant model in `core/repo_config.py`.
- **An OPA policy on/off switch** → `_DEFAULT_RULES_ENABLED` in `core/opa_input.py`, default `False` unless the brief explicitly says the rule should ship on (the six on-by-default rules are all hard security/license/malware gates — a new rule needs the same bar to default on).

Then, regardless of axis:

1. **RED first** (per `CLAUDE.md`/`caliper-testing-and-tdd`): write the failing test — `tests/unit/test_config.py` for a `CaliperSettings` field, `tests/unit/test_repo_config.py` for a `RepoConfig` field, `tests/unit/test_opa_input.py` + an `opa test` case in `policies/` for a `rules_enabled` key. Confirm it fails.
2. **Default must be safe unconfigured.** An absent/default value must never turn on a behavior a repo didn't ask for — this is why every opt-in subsystem above (`llm_enabled`, `supply_chain_diff_enabled`, `grounding_enabled`, every off-by-default `rules_enabled` key, empty `ArchitectureConfig.tiers`) defaults to inert.
3. **Type it, don't stringify it.** Pydantic field with an explicit type, not a raw string parsed ad hoc — this is what gets you free env-var coercion and validation errors instead of a silent typo.
4. **If it's a `RepoConfig` field that should survive a package-level merge**, add it to `load_merged_config`'s explicit merge list (see section 2's warning — this is the single most common way a new config field silently regresses on package-level repos).
5. **If it's a list-valued `CaliperSettings` field**, confirm the comma-separated env fallback still round-trips a single value with no comma (`_CommaSeparatedEnvSource` in `config.py` already handles this generically — you don't need new code, just a test).
6. **Update the capability/doc surface**: `docs/CAPABILITIES.md` if it's user-facing, and re-run this skill's dump scripts (section "Provenance & maintenance" below) so the next reader isn't working from a stale table.
7. **GREEN**: implement, run the test, run `make test` (container-only — never `CALIPER_ALLOW_HOST_TESTS=1` locally).
8. Follow `caliper-change-control` for commit/PR discipline (one flag = one logical commit, conventional-commit prefix — a new flag with no new user-facing capability is `fix:`/`chore:`, not `feat:`, unless it's genuinely a new capability per `CLAUDE.md`'s Commit Message Discipline section).

## Provenance & maintenance

Every fact above was checked against commit `c78154b` (2026-07-02) on branch `arch-review-fixes-and-enhancements`. Re-verify with these exact commands from repo root before trusting this document on anything volatile:

```bash
# Full CaliperSettings field/env-var/default table (33 fields as of 2026-07-02)
uv run python .claude/skills/caliper-config-and-flags/scripts/dump_settings.py

# rules_enabled + other OPA config defaults, straight from the source of truth
uv run python .claude/skills/caliper-config-and-flags/scripts/dump_rules_enabled.py

# Re-count deny/warn Rego rule blocks (16 as of 2026-07-02) vs CLAUDE.md's stated "11"
grep -c "^deny contains msg if\|^warn contains msg if" policies/policy.rego

# Confirm rules_enabled has no .caliper.yaml or CLI wiring (should be empty as of 2026-07-02)
grep -n "rules_enabled" src/caliper/cli/main.py src/caliper/core/repo_config.py

# Re-run the OPA policy test suite (51/51 as of 2026-07-02)
opa test policies/ --ignore '*.yaml' --ignore '*.yml'

# Full text of any CALIPER_* env var reference outside CaliperSettings
grep -rohE "CALIPER_[A-Z_]+" src/ tests/ Makefile scripts/ 2>/dev/null | grep -v __pycache__ | sort -u

# Confirm which RepoConfig fields load_merged_config actually merges
grep -n "merged_" src/caliper/core/repo_config.py

# This repo's own .caliper.yaml, as a live example
cat .caliper.yaml
```

If any of these produce a different shape than documented above (field count, rule count, a merge list that now includes `baseline`/`architecture`, a CLI flag for `rules_enabled` that didn't exist before), the repo has moved — update this file, not your assumptions.
