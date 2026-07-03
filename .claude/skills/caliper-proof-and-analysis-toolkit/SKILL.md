---
name: caliper-proof-and-analysis-toolkit
description: >-
  First-principles analysis methods used inside caliper's own detection
  pipeline -- "prove it, don't just install it." Covers the vulnerability
  reachability scribe (ADR-009, declared-vs-imported reachability +
  unreachable_vuln_exemption OPA rule), the cross-run incremental scan cache
  (ADR-010, whole-target content-addressed key) and its correctness
  invariant, and the 12 code-graph SQL checks (Blast Radius plugin). Load
  this when asked "how does caliper know a vuln is unreachable", "what would
  make a cached scan result wrong", "what do the 12 code graph checks
  actually check", "prove this finding is real", "why didn't the cache
  invalidate", or before touching `core/import_resolution.py`,
  `plugins/scribes/reachability.py`, `core/scan_cache_key.py`,
  `core/caching_scanner.py`, `data/scan_cache.py`, or
  `plugins/_runners/graph_builder.py` / `checks.yaml`. Not for: the OPA
  rule catalog / Rego syntax in general (use caliper-opa-policy-playbook),
  config flags and env vars (use caliper-config-and-flags), the
  detect-then-scribe plugin *mechanism* itself (use
  caliper-plugin-architecture), or multi-agent adversarial code review (use
  adversarial-review). Frontier/unbuilt tiers of these features live in
  caliper-research-frontier, not here.
---

# Caliper Proof & Analysis Toolkit

Caliper's founding bet is that a claim only counts if it comes with a
deterministic witness. This skill collects the three places in the codebase
that embody that bet most literally: a scribe that proves a vulnerability is
*declared but never imported* rather than assuming it, a cache key that
proves a scan result is *still valid for this exact tree/tool/config* rather
than assuming staleness doesn't matter, and a SQL check suite that proves a
structural property of the code graph (a cycle, an SRP violation, a dead
function) rather than eyeballing a diff.

**Read this before**: touching `core/import_resolution.py`,
`plugins/scribes/reachability.py`, `core/scan_cache_key.py`,
`core/caching_scanner.py`, `data/scan_cache.py`,
`plugins/_runners/graph_builder.py`, or `plugins/_runners/checks.yaml`; or
before you assert "this vuln is unreachable" / "this scan was cached
correctly" / "this SQL check is a real finding" without having run the
verification commands below.

## When NOT to use this skill

| If you need... | Use instead |
|---|---|
| The full 16-rule OPA catalog, Rego syntax, `opa test` mechanics in general | `caliper-opa-policy-playbook` |
| Every `CaliperSettings` field / `CALIPER_*` env var / `.caliper.yaml` key | `caliper-config-and-flags` |
| How the detect-then-scribe *pass itself* is wired (SCRIBES registry, `applies_to`, ordering) | `caliper-plugin-architecture` |
| Step-by-step "how do I write a new plugin/scribe" | `caliper-plugin-authoring-playbook` |
| Fail-open/timeout design philosophy in general | `caliper-fail-open-resilience` |
| Symptom -> root-cause triage for a scan that looks wrong | `caliper-debugging-playbook` |
| Multi-agent Haiku/Sonnet/Opus adversarial review orchestration | `adversarial-review` |
| Unbuilt Tier-2 follow-ups (symbol-level reachability, per-file cache) | `caliper-research-frontier` |

All facts below were verified against commit `2a8054a` (reachability) and
`56f16ad` (scan cache) on **2026-07-02**. Re-run the commands in
[Provenance & maintenance](#provenance--maintenance) before trusting a
number here after that date.

---

## Recipe 1 — Vulnerability reachability (ADR-009)

**Jargon**: *declared-vs-imported reachability* — does the scanned repo
actually `import` the vulnerable package anywhere, or is it just listed in a
manifest? This is a **tier-1, module-level** check. It does NOT check
whether the specific vulnerable *symbol* inside that module is called (that
would need advisory-level symbol data caliper doesn't parse yet — ADR-009
calls this "Tier 2, deferred, noted not built"). Don't oversell what a
`reachable=True` means: it proves the module is imported somewhere, not that
the vulnerable code path executes.

### What it can prove

| Signal | Meaning | Can the OPA exemption downgrade on it? |
|---|---|---|
| `reachable=True` | An `imports` edge to the resolved import name exists in the code graph | No (never downgrades) |
| `reachable=False` | The import name resolved but **no** import edge exists anywhere in the repo | Yes, if `unreachable_vuln_exemption` is on |
| `reachable=None` | The distribution name couldn't be resolved to an import name, or the graph is unavailable | **Never** — absence of evidence is not evidence of absence (SAFETY property, ADR-009 §Consequences) |

### How resolution actually works

`core/import_resolution.py::resolve_import_name` is a pure, 3-step
deterministic fallback (verify: `Read src/caliper/core/import_resolution.py`):

1. A curated map of ~18 well-known divergent names (`pyyaml`→`yaml`,
   `beautifulsoup4`→`bs4`, `pillow`→`PIL`, `pycryptodome`→`Crypto`, …).
2. `importlib.metadata` `top_level.txt` lookup — only useful when the
   scanned repo's dependency happens to *also* be installed in caliper's own
   venv. Best-effort, not primary.
3. Heuristic: lowercase, `-`/`.` → `_`. Covers the mechanical majority
   (`django`→`django`, `requests`→`requests`).

Returns `None` only when step 3 doesn't produce a valid Python identifier —
callers must treat `None` as "unknown," never as `False`.

`CodeGraph.imports_module(import_name)` (`plugins/_runners/graph_builder.py`)
then does a single indexed lookup against `edges` joined to `symbols` where
`kind='imports'`, matching the import name exactly or as a dotted prefix
(`"yaml.%"`) — same cost class as `symbol_at`/`blast_radius`, no full-graph
walk.

### Worked example — run it yourself

```bash
uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/prove_reachability.py
```

Actual output (captured 2026-07-02, `git rev-parse HEAD` = `c78154b`):

```
--- imported ---
  declared package : 'PyYAML'
  resolved import  : 'yaml'
  imports_module() : True

--- declared-but-unimported ---
  declared package : 'PyYAML'
  resolved import  : 'yaml'
  imports_module() : False

--- unresolvable-name ---
  declared package : '123-not-an-identifier'
  resolved import  : None
  imports_module() : None
```

This mirrors `tests/unit/plugins/test_reachability_scribe.py` exactly — the
script is a standalone, readable version of the same three cases the test
suite locks down (`test_reachable_when_import_found`,
`test_unreachable_when_declared_but_never_imported`,
`test_unresolvable_import_name_yields_none_never_false`).

### The OPA exemption — proven, not assumed

`unreachable_vuln_exemption` (T-348 in `policies/policy.rego`) downgrades a
critical/high vuln `deny` to `warn` **only** when
`input.findings[_].reachable == false` exactly. Don't take that on faith —
run the actual Rego unit tests:

```bash
opa test policies/ --ignore '*.yaml' --ignore '*.yml' --run 'test_unreachable' -v
```

Actual output (2026-07-02):

```
policies/policy_test.rego:909:
data.policy_test.test_unreachable_vuln_deny_when_exemption_disabled: PASS (1.014625ms)
policies/policy_test.rego:882:
data.policy_test.test_unreachable_vuln_downgraded_to_warn: PASS (1.240709ms)
policies/policy_test.rego:984:
data.policy_test.test_unreachable_malicious_advisory_never_downgraded: PASS (1.6265ms)
--------------------------------------------------------------------------------
PASS: 3/3
```

There's a fourth safety test in the same file worth reading directly —
`test_null_reachability_never_downgrades_deny` (line 935) and
`test_reachable_true_never_downgrades_deny` (line 959) — both assert the
exemption is a one-way door: only an *explicit* `false` fires it, never a
missing field and never `true`.

### Known limitation — this is opt-in and NOT wired into a live run today

Two separate opt-ins have to both be true, and as of 2026-07-02 **the second
one has no operator-facing knob**:

1. `enabled_scribes` must include `"reachability"` — it's not in
   `DEFAULT_SCRIBES` (`("enclosing_symbol", "code_graph")` in
   `core/config.py`). Set via `CALIPER_ENABLED_SCRIBES` — see
   `caliper-config-and-flags` for the exact syntax.
2. `rules_enabled.unreachable_vuln_exemption` must be `true` in the OPA
   `input.config`. Per `caliper-config-and-flags`' verified finding: the
   live production pipeline (`core/pipeline.py`) builds `PolicyInput` with
   an **empty** `config={}`, so every `rules_enabled` key runs at its
   coded-in Rego default (`unreachable_vuln_exemption` defaults **off**).
   There is currently no CLI flag and no `.caliper.yaml` key that reaches
   this dict. The exemption is real, tested, and correct — but today it's
   only reachable from `opa test`/a hand-built `OpaEvaluator.evaluate(...,
   config=...)` call, not from a normal `caliper review` invocation. Don't
   tell a user "just turn on the exemption in `.caliper.yaml`" — that key
   doesn't exist yet. Flag this as a follow-up if you need it operator-facing.

### Case-sensitivity bug fixed alongside this ADR

Commit `2a8054a` also fixed a pre-existing bug in the curated map: `pillow`
and `pycryptodome` were mapped to lowercase `pil`/`crypto`, which would never
match the real `import PIL` / `import Crypto` statements the graph indexes
(Python import names are case-sensitive; the graph stores the literal
dotted path as written). Verify the fix is in place:

```bash
grep -n '"pillow"\|"pycryptodome"' src/caliper/core/import_resolution.py
```

Expect `"pillow": "PIL"` and `"pycryptodome": "Crypto"` (capitalized) — if
you ever see these lowercased again, that's a regression of the exact bug
this ADR fixed.

---

## Recipe 2 — Cross-run incremental scan cache (ADR-010)

**Jargon**: *tree_sha* — the target repo's `HEAD` commit SHA (not a
per-file hash). *config_digest* — a sha256 over a **scoped subset** of
`CaliperSettings`, not the whole settings object.

### The correctness invariant, verbatim

```
key = sha256(tree_sha ++ "\0" ++ scanner_name ++ "\0" ++ tool_version ++ "\0" ++ config_digest)
```

A cached `ScanResult` is safe to reuse only when **all four** components
still match:

| Component | Source | What would make a stale hit WRONG |
|---|---|---|
| `tree_sha` | `pipeline_helpers.resolve_git_sha(repo_path)` = `HEAD` SHA | The tree changed since the cached run **and** you're re-scanning the same `HEAD` (impossible — a new commit gets a new SHA). The real gap: **uncommitted changes since `HEAD` are invisible to this key** — a dirty working tree can get served a stale hit. Documented, accepted limitation for CI (always a clean checkout); a real correctness gap for local `caliper review` on a dirty tree. |
| `scanner_name` | e.g. `"osv-scanner"` | N/A — different scanners never share a key |
| `tool_version` | `caliper.core.version.get_version()` — the installed caliper package version, used as a **proxy** for "did scanner logic change" | An external tool binary (osv-scanner, trivy, …) floats independently of the caliper package version. Today that can't happen — binaries are pinned by the container image, and an image rebuild always bumps the caliper version too. If that pinning ever breaks, this proxy silently stops working. |
| `config_digest` | `scan_cache_key.settings_digest(config)` over exactly `enabled_scanners`, `osv_exclude_paths`, `scanner_timeout`, `combined_scanner_timeout`, `file_source` | Any *other* `CaliperSettings` field changing (LLM config, publisher tokens, evidence path) must NOT bust the cache — that's by design, not a bug, if you see a cache hit survive an unrelated config change. |

**Second, independent safety invariant**: `CachingScanner.scan` only calls
`cache.put(...)` when `result.status == ScanResultStatus.success`
(`core/caching_scanner.py`). A `failed`/`timeout`/`skipped` result is
returned to the caller but never written — a transient scanner failure can
never poison a future run with a false "clean" cached result.

### Worked example — prove the key is deterministic and collision-resistant

```bash
uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/prove_scan_cache_key.py
```

Actual output (2026-07-02):

```
same inputs twice        : True  (308521263efe...)
tree_sha changed          : True
scanner_name changed      : True
tool_version changed      : True
config_digest changed     : True

base digest               : 86f80449188f...
scanner_timeout=999 -> digest changes : True
opa_timeout=999 (irrelevant) -> same  : True
```

The last line is the one worth re-reading: `opa_timeout` is a real
`CaliperSettings` field, and it does **not** perturb the digest, because it
isn't in `_SCAN_RELEVANT_FIELDS`. This is the mechanism that keeps unrelated
config edits from silently invalidating every cached scan.

### Where the cache actually lives, and how to inspect a real one

```bash
# after any real `caliper review`/`evaluate` run against a git target:
sqlite3 <evidence_path>/scan_cache.sqlite "SELECT key, length(result_json) FROM scan_cache LIMIT 5;"
```

`data/scan_cache.py::SqliteScanCache` is a single table
(`scan_cache(key TEXT PRIMARY KEY, result_json BLOB)`), one row per
`(tree, scanner, version, config)` tuple. A corrupt or unreadable row is
treated as a cache miss, never a crash (`try/except` around both `get` and
`put`, logged at `debug`, never raised) — fail-open, same as every other
optional collaborator in this codebase. `NullScanCache` (always-miss,
discards writes) is the fallback when the evidence dir isn't writable
(`composition/bootstrap.py::build_scan_cache`).

### When to distrust a cache hit

- **Non-git target.** `resolve_git_sha` returns `None` → caching is skipped
  entirely for that run (`pipeline.py::_build_orchestrator`: `if
  commit_sha is not None and cache is not None`). No stale-hit risk here —
  there's simply no cache in play.
- **Dirty working tree.** The one deliberately-accepted gap above. If you're
  debugging "why did my local uncommitted fix not show up in this scan,"
  check this first — it is the documented, expected behavior for tier 1, not
  a bug to chase.
- **A scanner binary was hot-patched inside a running container without a
  version bump.** `tool_version` wouldn't change, so a stale result could
  be served. Not a normal caliper deployment path, but worth knowing the
  boundary of the proxy.

---

## Recipe 3 — The 12 code-graph SQL checks (Blast Radius plugin)

**Jargon**: *code graph* — an AST → SQLite index of `symbols` (functions,
classes) and `edges` (`calls`, `imports`, `inherits`), built fresh
per-scan by `plugins/_runners/graph_builder.py::CodeGraph`. This is plugin
#16 in the README's plugin table ("Blast Radius"), category `quality`.

All 12 checks are declared in `plugins/_runners/checks.yaml` (verified
count 2026-07-02: `grep -c '  - name:' src/caliper/plugins/_runners/checks.yaml`
→ 12) and loaded via `CodeGraph._register_builtin_checks`. Each is a plain
SQL query templated with `{changed_files}` (an IN-list of the files being
reviewed) and `{fan_out_limit}` (configurable, default 8).

| Check | Severity | What it structurally proves |
|---|---|---|
| `blast_radius_high` | info | Symbol has >10 direct dependents (edges targeting it) |
| `blast_radius_critical` | medium | Symbol has >25 direct dependents |
| `circular_dependency` | medium | Two files' `imports` edges form a 2-cycle |
| `orphan_symbol` | info | Function/method with zero `calls` edges targeting it (potential dead code) |
| `high_fan_out` | medium | Function has >`fan_out_limit` outgoing `calls` edges (god function) |
| `deep_inheritance` | medium | Class inheritance chain (`inherits` edges) deeper than 3 levels |
| `noop_function` | medium | Function body classified as `noop`/`pass_only`/`return_none`/`stub`/`log_only` |
| `mock_stub_in_source` | high | Stub/mock-shaped body found in a file that isn't a test file |
| `layer_violation` | high | A `core/` symbol has an `imports` edge into `data/` (tier violation) |
| `missing_tested_by` | medium | A `.py` source file (non-test, non-`__init__`) has no `# tested-by:` annotation |
| `srp_high_fan_out_imports` | medium | A file imports from 4+ distinct target files (SRP violation signal) |
| `srp_large_class` | medium | A class has >15 methods (SRP violation signal) |

Extensible at runtime: `graph.register_check(name, query, severity,
description)` — any consumer (a third-party plugin, a one-off audit script)
can add its own SQL check without touching `checks.yaml`.

### Worked example — run all 12 against real caliper source

```bash
uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/run_code_graph_checks.py \
    src/caliper/plugins/_runners/graph_builder.py
```

Actual output (2026-07-02, in-memory graph, whole repo indexed for edge
visibility, checks scoped to the one target file):

```
indexed 1288 files under /Volumes/Extra/repos/gitrdunhq/eedom
stats: {'symbols': 11358, 'edges': 23960, 'checks': 12, 'files': 2420}

16 findings across 1 target file(s): ['src/caliper/plugins/_runners/graph_builder.py']
  [    info] orphan_symbol                Function with zero callers (potential dead code): resolve_graph_db_path
  ... (13 orphan_symbol hits total)
  [  medium] missing_tested_by            Source file has no tested-by annotation
  [  medium] srp_high_fan_out_imports     Module imports from 4+ distinct packages (SRP violation signal) (import_count=10)
  [  medium] srp_large_class              Class has >15 methods (SRP violation signal): CodeGraph (method_count=26)
```

Two things worth noting about this *real, unedited* output — this is the
whole point of the "prove it, don't just install it" framing:

1. **`missing_tested_by` is a genuine, currently-open finding.** As of
   2026-07-02, `src/caliper/plugins/_runners/graph_builder.py` itself has no
   `# tested-by:` header comment, despite `CLAUDE.md`'s project-wide rule
   that every source file carries one (`grep -c "tested-by"
   src/caliper/plugins/_runners/graph_builder.py` → 0). This check isn't a
   toy — it caught a real gap in caliper's own source during the writing of
   this skill. Not fixed here (read-only scope for this skill); worth a
   follow-up.
2. **`orphan_symbol` has a real false-positive mode — verify before you
   trust it.** `CodeGraph._add_edge` resolves a call target by `name` match
   only (`WHERE ... t.name = ? LIMIT 1`, no type/class-scope resolution,
   arbitrary tie-break on name collisions across the whole indexed repo).
   Every method in `graph_builder.py` flagged here (`run_checks`,
   `index_directory`, `stats`, …) is a **public API called from other files
   in this repo** — they are not actually dead. Treat `orphan_symbol` as a
   *lead to grep-confirm*, never as ground truth on its own; that's exactly
   why its severity is `info`, not `high`.

### How to run it against your own diff

Point the script at whatever files changed in your working tree:

```bash
uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/run_code_graph_checks.py \
    $(git diff --name-only --diff-filter=ACMR HEAD -- '*.py')
```

For the full plugin (severity buckets, PR-comment rendering, threshold
config from `.caliper.yaml`'s `thresholds.blast-radius`), see
`src/caliper/plugins/blast_radius.py` and run it through the real pipeline —
see `caliper-run-and-operate` for the container invocation (`cal` /
`caliper review --repo-path`).

---

## Provenance & maintenance

Everything above was verified against commit `2a8054a` (reachability, ADR-009)
and `56f16ad` (scan cache, ADR-010) on **2026-07-02**, repo HEAD `c78154b`.
Re-run these before trusting a fact past that date:

```bash
# Re-confirm the two source commits and their diffstat
git show --stat 2a8054a
git show --stat 56f16ad

# Re-count the 12 code-graph checks
grep -c '  - name:' src/caliper/plugins/_runners/checks.yaml

# Re-run both worked-example scripts (no repo files are mutated by either)
uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/prove_reachability.py
uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/prove_scan_cache_key.py

# Re-run the three OPA reachability-exemption unit tests
opa test policies/ --ignore '*.yaml' --ignore '*.yml' --run 'test_unreachable' -v

# Re-check whether rules_enabled has grown a CLI/.caliper.yaml knob yet
# (as of 2026-07-02 it has not -- see caliper-config-and-flags)
grep -n "rules_enabled" src/caliper/cli/main.py src/caliper/core/repo_config.py

# Re-check the curated-map case-sensitivity fix is still in place
grep -n '"pillow"\|"pycryptodome"' src/caliper/core/import_resolution.py

# Re-check the graph_builder.py missing-tested-by finding (does it still reproduce?)
uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/run_code_graph_checks.py \
    src/caliper/plugins/_runners/graph_builder.py

# Re-count total OPA rules (16 as of 2026-07-02: 7 deny + 9 warn)
grep -c "^deny contains msg if" policies/policy.rego
grep -c "^warn contains msg if" policies/policy.rego
```

If any of these produce a different shape than documented above (a new
check added to `checks.yaml`, a new curated-map entry, `rules_enabled`
finally gaining a CLI flag), update this file — that drift is exactly the
kind of thing this skill exists to keep honest.
