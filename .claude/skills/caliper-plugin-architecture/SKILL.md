---
name: caliper-plugin-architecture
description: Load when working on caliper's plugin system itself — PluginRegistry auto-discovery, adding/removing/renaming a scanner plugin, depends_on / topological execution order, the SCRIBES detect-then-scribe pass (ADR-006), the third-party plugin SDK / entry-point discovery ("caliper.plugins" group), scanner-disagreement dedup in core/normalizer.py, or diagnosing registration/discovery failures — a plugin that never appears in `caliper plugins` at all ("my plugin didn't register", "my scribe didn't fire", "two scanners disagree on severity", "a third-party entry-point plugin isn't showing up in the list"). Not for a plugin that registers fine but silently times out or fails mid-scan (use caliper-debugging-playbook) or for a new detector that's registered but missing from live `caliper review` output (use caliper-plugin-authoring-playbook's live-scan wiring gap). This is the architecture reference. For the step-by-step "how do I write a new plugin" tutorial, use caliper-plugin-authoring-playbook instead.
---

# Caliper Plugin Architecture

This is the hardest live problem on caliper per the maintainer: keeping 19+
independently-evolving plugins, 5 scribes, and now third-party entry-point
plugins all coherent as the system grows. Read this before touching
`src/caliper/plugins/`, `src/caliper/core/plugin_registry.py`,
`src/caliper/core/port_registries.py`, or `src/caliper/core/scribe*.py`.

All facts below were re-verified against the repo on **2026-07-02** at commit
`c78154b` (HEAD of branch `arch-review-fixes-and-enhancements`). Counts and
line numbers drift — see "Provenance & maintenance" at the bottom for the
exact commands to re-check them yourself before trusting a number in here.

## When NOT to use this skill

| You want to... | Use instead |
|---|---|
| Write a brand-new in-tree plugin step by step, with a full worked example | `caliper-plugin-authoring-playbook` |
| Understand the ports-and-adapters tier boundaries (presentation/core/data) in general | `caliper-architecture-contract` |
| Run OPA policy tests, understand Rego rule semantics | `caliper-opa-policy-playbook` |
| Understand fail-open/timeout conventions project-wide (not just plugins) | `caliper-fail-open-resilience` |
| Run the test suite, TDD red/green workflow | `caliper-testing-and-tdd` |
| Multi-agent adversarial code review orchestration | `adversarial-review` |
| Change-control rules (commit discipline, `feat`/`fix`/`chore`) | `caliper-change-control` |

This skill is the "how the plugin machine works and how it breaks" reference.
It does not teach you Python or walk you through creating a plugin file line
by line — that's the authoring playbook's job.

## Mental model in one picture

```
┌─────────────────────────────────────────────────────────────────┐
│ discovery (import time)                                          │
│                                                                    │
│  src/caliper/plugins/*.py  ──@ANALYZERS.register("name")──┐      │
│  (19 non-underscore modules, autodiscover() skips "_*.py") │      │
│                                                              ▼      │
│                                                    ANALYZERS Registry│
│                                                              │      │
│  entry_points(group="caliper.plugins") ──third-party pkgs──┤      │
│  (installed via `pip install caliper-plugin-X`)             │      │
│                                                              ▼      │
│                              get_default_registry() → PluginRegistry│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ execution (per review run) — PluginRegistry.run_all()            │
│                                                                    │
│  1. filter by names/categories/disabled/enabled                  │
│  2. _topological_sort() by depends_on                            │
│  3. ThreadPoolExecutor — independent plugins run in parallel      │
│  4. each plugin wrapped: exception → PluginResult(error=...)      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼  raw findings (PluginResult list)
┌─────────────────────────────────────────────────────────────────┐
│ normalize (core/normalizer.py) — cross-scanner dedup              │
│  same (advisory_id, category, package, version) → highest         │
│  severity wins, counts collapse into one Finding                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼  Finding list
┌─────────────────────────────────────────────────────────────────┐
│ detect-then-scribe (ADR-006) — core/scribe_pass.py                │
│  sequential, per-finding, per-scribe, fail-open, scribe_timeout=30s│
│  writes finding.metadata["scribe"][...]                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ policy — context.policy_engine.evaluate() (POLICY_ENGINES/"opa")  │
│  a SEPARATE seam from PluginRegistry — see "OPA gotcha" below      │
└─────────────────────────────────────────────────────────────────┘
```

## Part 1 — PluginRegistry auto-discovery

**Files**: `src/caliper/plugins/__init__.py`, `src/caliper/core/plugin_registry.py`,
`src/caliper/core/plugin.py`.

Discovery and execution are two different modules on purpose:

- `core/plugin_registry.py` — `PluginRegistry` is *purely* the execution
  adapter: register/get/list, topological sort, thread-pool run, per-plugin
  exception handling. It has **no** knowledge of where plugins come from.
- `src/caliper/plugins/__init__.py` — the discovery seam. Two sources feed
  one `Registry[AnalyzerPort]` called `ANALYZERS`:
  1. **In-tree**: `autodiscover(__name__, __path__)` (generic helper in
     `src/caliper/adapter_registry.py`) calls `pkgutil.iter_modules` over
     `src/caliper/plugins/` and imports every module whose name does **not**
     start with `_`. Each imported module runs its
     `@ANALYZERS.register("name")` decorator as an import side effect.
  2. **Third-party**: `_discover_entry_point_plugins()` reads
     `importlib.metadata.entry_points(group="caliper.plugins")` — see Part 4.

`get_default_registry()` is the one function that turns `ANALYZERS` + the
entry-point plugins into a live `PluginRegistry`:

```python
def get_default_registry() -> PluginRegistry:
    registry = PluginRegistry()
    for key in ANALYZERS.keys():
        registry.register(ANALYZERS.create(key))
    for plugin in _discover_entry_point_plugins():
        registry.register(plugin)
    return registry
```

Underscore-prefixed modules (`_opa.py`, `_parting.py`, `_inspect_llm.py`,
`_runners/`) are **intentionally excluded** from autodiscovery — they either
wire in through a different seam (`_opa.py`, see the gotcha below) or are
consumed directly by a specific CLI command rather than the generic
`review` plugin loop (`_parting.py` by `caliper part`, `_inspect_llm.py` by
`caliper inspect`).

**Verify it yourself** (script shipped with this skill, output reproduced
verbatim from a 2026-07-02 run):

```
uv run python .claude/skills/caliper-plugin-architecture/scripts/list_plugins_and_scribes.py
```

```
=== 19 scanner plugins (PluginRegistry) ===
  blast-radius     category=quality        depends_on=-
  cdk-nag          category=infra          depends_on=-
  cfn-nag          category=infra          depends_on=-
  clamav           category=supply_chain   depends_on=-
  complexity       category=quality        depends_on=-
  cpd              category=code           depends_on=-
  gitleaks         category=supply_chain   depends_on=-
  kube-linter      category=infra          depends_on=-
  ls-lint          category=quality        depends_on=-
  mypy             category=code           depends_on=-
  osv-scanner      category=dependency     depends_on=-
  scancode         category=dependency     depends_on=-
  semgrep          category=code           depends_on=-
  supply-chain     category=supply_chain   depends_on=-
  swiftformat      category=code           depends_on=-
  swiftlint        category=code           depends_on=-
  syft             category=dependency     depends_on=-
  trivy             category=dependency     depends_on=-
  typos            category=quality        depends_on=-

=== 5 registered scribes (SCRIBES registry) ===
  code_graph
  enclosing_symbol
  reachability
  semgrep
  supply_chain_threat

'opa' present in default scanner registry: False
```

None of the 19 in-tree plugins currently declares a real `depends_on` —
today's ordering is flat (all run in parallel, thread pool sized
`min(len(plugins), 8)`). The only historical user of `depends_on=["*"]` was
`OpaPlugin`, which is no longer in the default registry (see the gotcha).
`_topological_sort()` and the `["*"]` convention still exist and are still
tested (`tests/unit/test_plugin_registry.py`) because third-party plugins or
future in-tree plugins may need them — don't remove the machinery just
because nothing currently exercises `["*"]` in production.

List what's registered from the CLI:

```bash
uv run python -m caliper.cli.main plugins
```

## Part 2 — `depends_on` and topological execution order

**File**: `src/caliper/core/plugin_registry.py`, function `_topological_sort`.

- Default `depends_on` is `[]` (no ordering constraint) — declared on
  `ScannerPlugin.depends_on` in `core/plugin.py` as a property returning
  `[]`.
- A plugin lists other plugins' `name` strings it must run **after**.
  Unknown names (typo, plugin disabled this run) are silently dropped —
  this is deliberate fail-open behavior, not a bug: a missing dependency
  should never hard-fail a scan.
- `depends_on = ["*"]` is sugar for "run after every other plugin in this
  batch that does not itself use `"*"`" — computed fresh per run from
  whichever plugins are actually enabled, not from the full static registry.
  This was the pre-refactor mechanism for running the OPA policy check last.
- Cycles raise `ValueError` from `graphlib.TopologicalSorter` — a plugin bug,
  not a fail-open case. A circular `depends_on` graph aborts `run_all()`
  entirely (this is the one place plugin misconfiguration is NOT fail-open —
  by design: a cycle means the execution order itself is undefined, so there
  is no safe default to fall back to).
- Execution: plugins sorted topologically, then run inside a
  `ThreadPoolExecutor(max_workers=min(len(plugins), 8))`. Topological order
  only constrains *scheduling intent* in the current implementation — the
  thread pool still runs everything concurrently once dependencies are
  satisfied in list order; there is no explicit wave-by-wave barrier. If you
  add a plugin whose `run()` truly must see completed results from another
  plugin (not just "run later" but "consume its output"), do not rely on
  `depends_on` alone — check how `OpaPlugin.run(..., findings=...)` used to
  receive injected findings (now dead code, see gotcha) before assuming the
  registry threads data between plugins for you. Today, no in-tree plugin
  passes data to another through the registry; the scribe pass is the
  sanctioned mechanism for "finding needs more context from elsewhere in the
  codebase."

## Part 3 — the 19 scanner plugins, by category

`PluginCategory` (`core/plugin.py`): `dependency`, `code`, `infra`, `quality`,
`supply_chain`. Category drives diff-scope file selection —
`_REPO_WIDE_CATEGORIES = {dependency, infra, supply_chain}` always sees the
full repo file list even in diff mode; `code`/`quality` see only changed
files (`PluginRegistry.run_all`, `repo_files` vs `files` parameter).

| category | plugins (19 total) |
|---|---|
| `dependency` | osv-scanner, scancode, syft, trivy |
| `code` | cpd, mypy, semgrep, swiftformat, swiftlint |
| `infra` | cdk-nag, cfn-nag, kube-linter |
| `quality` | blast-radius, complexity, ls-lint, typos |
| `supply_chain` | clamav, gitleaks, supply-chain |

Every plugin implements the `AnalyzerPort` structural protocol (or subclasses
the concrete `ScannerPlugin` ABC) defined in `src/caliper/core/plugin.py`:
`name`, `description`, `category`, `depends_on` (optional), `can_run(files,
repo_path) -> bool`, `run(files, repo_path) -> PluginResult`, `render(...)`.
Full field-by-field contract and a worked example: `docs/PLUGIN_SDK.md`
(authoritative — it's what third-party authors read) or the
`caliper-plugin-authoring-playbook` skill for the guided walkthrough.

## Part 4 — third-party plugin SDK (entry points) — newest subsystem, commit `c78154b`

**Files**: `src/caliper/plugins/__init__.py` (`_discover_entry_point_plugins`,
`_ENTRY_POINT_GROUP = "caliper.plugins"`), `docs/PLUGIN_SDK.md`,
`tests/unit/test_plugin_sdk.py`.

A third-party Python package publishes a zero-arg factory under the
`caliper.plugins` entry-point group in its own `pyproject.toml`:

```toml
[project.entry-points."caliper.plugins"]
mytool = "caliper_plugin_mytool.plugin:MyPlugin"
```

Once that package is `pip install`ed alongside caliper, `get_default_registry()`
picks it up automatically — no fork, no PR against this repo, no config file.
It gets the exact same `PluginRegistry` treatment as an in-tree plugin: same
topological sort, same thread pool, same per-run exception wrapping.

Fail-open at **two** levels (verified in `_discover_entry_point_plugins`):

1. **Metadata backend itself errors** (e.g. a broken `importlib.metadata`
   install) → caught, logs `plugin_sdk.entry_points_lookup_failed`, returns
   `[]` — falls back to in-tree plugins only. The scan still runs.
2. **One entry point fails to load or construct** (`entry_point.load()` or
   the factory call raises) → caught per-entry-point, logs
   `plugin_sdk.plugin_load_failed` with `entry_point=<name>`, that one entry
   point is skipped, every other third-party and in-tree plugin still loads
   and runs.

Design decision worth remembering (from the commit message, verified against
the code): entry-point discovery lives in `plugins/__init__.py`, **not** on
the `PluginRegistry` class. `PluginRegistry` stayed a pure execution adapter
with zero discovery knowledge; `plugins/__init__.py` was already the
in-package discovery seam (`ANALYZERS` + `autodiscover`), so third-party
discovery joined it there instead of teaching the adapter a new
responsibility.

Test the discovery mechanism yourself without installing a real package —
`tests/unit/test_plugin_sdk.py` fakes `importlib.metadata.entry_points` via
`monkeypatch` and exercises: a valid plugin registers and runs, a
broken-constructor plugin is skipped without blocking the run, a
metadata-backend failure falls back to in-tree-only. Read that file before
writing a new fail-open-path test for this subsystem — the pattern
(`_FakeEntryPoint`, `_patch_entry_points`) is already there.

## Part 5 — the scribes subsystem (ADR-006: detect-then-scribe)

**Files**: `src/caliper/plugins/scribes/` (4 modules),
`src/caliper/detectors/scribes/enclosing_symbol.py` (1 more — scribes live in
whichever tier owns the tool they wrap), `src/caliper/core/scribe.py`
(`ScribeNote`, `ScribeContext`, `merge_scribe`, the shared `enclosing_symbol`
resolver), `src/caliper/core/scribe_pass.py` (`scribe_findings` — the pass
itself), `src/caliper/core/port_registries.py` (`SCRIBES` registry),
`docs/adr/006-detect-then-scribe.md`, `docs/adr/009-reachability.md`.

**What it's for**: plugins detect findings with thin context (a file, a
line, a message). A downstream consumer (Foreman agent, a human reviewer)
has to re-derive what function this is in, who calls it, is it actually
reachable — expensive, and non-deterministic if an LLM does it. Scribe is a
**second, deterministic pass** that runs after detection and before policy
and attaches that context so the re-derivation never has to happen.

**Hard invariants** (ADR-006, and enforced by `scribe_pass.py`'s own
docstring/code — read both before writing a scribe):

- **Deterministic** — pure function of repo content; same input → same
  scribe output. Zero LLM.
- **Never affects the verdict** — only adds `metadata["scribe"]`; policy/OPA
  never reads scribe output to change a decision, it's advisory context
  (T-348 exemptions read scribe metadata to make already-decided rules more
  precise — see `caliper-opa-policy-playbook` for the policy side of that).
- **Fail-open** — a scribe error never drops a finding. `scribe_findings()`
  wraps each `scribe.scribe(...)` call in its own `try/except Exception`; on
  failure it logs `scribe.failed` and the finding passes through with
  whatever context it already had.
- **Time-bounded by `scribe_timeout`** (default **30s**, `CaliperSettings.scribe_timeout`,
  env `CALIPER_SCRIBE_TIMEOUT`) — one shared deadline (`time.monotonic() +
  scribe_timeout`) for the *entire pass* across *all* findings and *all*
  scribes, not per-scribe or per-finding. Once the deadline passes, remaining
  (finding, scribe) pairs are skipped with a `scribe.budget_exhausted` log and
  the finding keeps whatever scribe context it already accumulated.
- **Sequential, not threaded** — deliberately not run in the plugin
  `ThreadPoolExecutor`. Reason (from the module docstring): shared tool state
  like the `CodeGraph` is built once per run and read without locks; adding
  concurrency here would require locking the graph for no real throughput win
  (scribe work is sub-10ms per finding for graph/AST-based scribes).

**The `ScribePort` structural contract** (`core/ports.py`, restated by every
scribe implementation, e.g. `ReachabilityScribe`):

```python
class ScribePort(Protocol):
    name: str
    def applies_to(self, finding: PluginFinding) -> bool: ...
    def scribe(self, finding: PluginFinding, ctx: ScribeContext) -> PluginFinding: ...
```

**The 5 registered scribes today** (verified 2026-07-02):

| key | module (tier) | applies_to | writes |
|---|---|---|---|
| `enclosing_symbol` | `detectors/scribes/enclosing_symbol.py` | every finding with a file+line | `scribe.enclosing_symbol`, `scribe.enclosing_kind` |
| `code_graph` | `plugins/scribes/code_graph.py` | findings the code graph can resolve | `scribe.blast_radius` |
| `semgrep` | `plugins/scribes/semgrep.py` | opt-in, subprocess-cost | `scribe.related` (nearby semgrep matches) |
| `reachability` | `plugins/scribes/reachability.py` | `finding.package` non-empty (SCA findings) | `scribe.reachability = {reachable, evidence}` — ADR-009, newest, commit `2a8054a` |
| `supply_chain_threat` | `plugins/scribes/supply_chain_threat.py` | supply-chain findings | threat-signal context |

**Default-on vs opt-in** — `DEFAULT_SCRIBES = ("enclosing_symbol",
"code_graph")` in `core/config.py`. `semgrep`, `reachability`, and
`supply_chain_threat` are **not** in the default list (subprocess cost for
`semgrep`; `reachability`/`supply_chain_threat` are consumed by specific
opt-in policy exemptions, not every review). Override with
`CaliperSettings.enabled_scribes` / env `CALIPER_ENABLED_SCRIBES` (comma-list
via pydantic-settings). A scribe that's registered but not in
`enabled_scribes` simply never runs — that's a config decision, not a
failure mode.

**Reading a scribe example** — `ReachabilityScribe` (ADR-009,
`src/caliper/plugins/scribes/reachability.py`) is the cleanest recent
worked example of the pattern: resolve a distribution name to an import
name, check a cached `CodeGraph.imports_module()` edge, and write
`{"reachable": True|False|None, "evidence": [...]}`. Note the three-way
result — `reachable=None` (not `False`) when the graph is unavailable or the
import name can't be resolved, specifically so an absence of evidence is
never conflated with evidence of absence downstream in policy. Follow this
shape for any new scribe that produces a boolean-ish signal.

**Writing a new scribe** — see `merge_scribe()` in `core/scribe.py`. It's the
one helper every scribe should use to write into
`metadata["scribe"]`: it accumulates a `sources` list (so you can tell which
scribes touched a finding), handles both the frozen `PluginFinding` and the
raw-dict finding shape, and never clobbers a sibling scribe's fields. Don't
hand-roll `metadata["scribe"] = {...}` in a new scribe — you'll clobber
`enclosing_symbol`'s output.

## Part 6 — scanner disagreement resolution: highest severity wins

**File**: `src/caliper/core/normalizer.py`, function `normalize_findings`.

When two+ scanners report what is, after normalization, "the same" finding,
`normalize_findings` collapses them into one `Finding` and keeps the
**highest-severity** version. Rank table (`_SEVERITY_RANK`):

```python
_SEVERITY_RANK = {
    FindingSeverity.critical: 5,
    FindingSeverity.high: 4,
    FindingSeverity.medium: 3,
    FindingSeverity.low: 2,
    FindingSeverity.info: 1,
}
```

Dedup key differs by finding shape:

- **Vulnerability findings with an advisory ID** — key is
  `(advisory_id, category, package_name, version)`. Two scanners both citing
  `CVE-2024-XXXX` for the same package/version collapse to one finding at
  whichever scanner rated it more severely.
- **Findings without an advisory ID** (secret-scan hits, code-smell/detector
  findings) — the key adds `source_tool` and `description`. This is
  deliberate: collapsing purely on `(category, package_name, version)` for
  non-advisory findings caused unrelated findings to silently collapse into
  one (referenced in the code as bug `#234`) — so non-advisory findings only
  dedup against literal duplicates from the *same* tool with the *same*
  description, never across tools.
- **License findings** (`category == FindingCategory.license`) are excluded
  from the dedup pass entirely (`non_vuln_findings`) and pass through
  unmodified — every scanner's license finding is kept.

If you add a new scanner plugin whose findings should participate in
cross-scanner dedup, make sure it populates `advisory_id` when one exists —
otherwise your finding dedups only against itself, which is usually what you
want for non-CVE findings anyway.

## Part 7 — the fail-open contract, precisely

Two *different* fail-open layers exist in this system — know which one
you're debugging:

| Layer | Where | Timeout | On failure |
|---|---|---|---|
| Plugin execution | `PluginRegistry._run_one` | `scanner_timeout=60s` (per-scanner subprocess budget, enforced inside each plugin's own `run_subprocess_with_timeout` call — the registry itself does not impose a wall-clock timeout on `plugin.run()`) | `try/except Exception` around `plugin.run()` → `PluginResult(error=str(exc))`. The scan continues; other plugins are unaffected. |
| Scribe pass | `core/scribe_pass.scribe_findings` | `scribe_timeout=30s`, one shared deadline for the whole pass | `try/except Exception` around each `scribe.scribe(...)` call → finding passes through unchanged; deadline exceeded → remaining pairs skipped, already-accumulated scribe context is kept. |

Both layers share the same philosophy from `CLAUDE.md`: **no scanner failure
blocks a build.** A plugin that throws produces a typed `PluginResult(error=...)`
that shows up in the report as an error, not a silent gap and not a crashed
pipeline. See `caliper-fail-open-resilience` for the project-wide version of
this pattern (it also covers OPA's own `opa_timeout=10s` and the pipeline's
outer `pipeline_timeout=300s`, which are outside this skill's scope).

`can_run()` returning `False` is **not** a failure — it's a normal skip path
(`plugin.skip_reason()` is surfaced in the report as `skip_reason`/
`skip_remediation`, not an error). Don't conflate "plugin declined to run
because its prerequisite tool/file type wasn't present" with "plugin
crashed."

## Known fragility points (2026-07-02)

1. **The OPA-policy-plugin gotcha** — `src/caliper/plugins/_opa.py` defines
   `OpaPlugin(ScannerPlugin)` with `depends_on = ["*"]`, and its own module
   docstring calls it "the OPA policy plugin." **It is not in the default
   registry.** Verified: `get_default_registry().get("opa")` returns `None`
   (see the script output in Part 1, and `tests/unit/test_registry_no_policy.py::
   test_opa_plugin_not_in_default_registry`, which asserts exactly this).
   Live policy enforcement runs through a completely separate seam:
   `POLICY_ENGINES.create("opa", ...)` (`core/opa_adapter.py`, registered via
   `composition.bootstrap.load_adapters()`), wired into
   `ApplicationContext.policy_engine`, and called directly from
   `core/pipeline.py` as `context.policy_engine.evaluate(...)` — never through
   `PluginRegistry.run_all()`. `_opa.py` survives today only as (a) a
   reference/test fixture for the `depends_on=["*"]` topological-sort
   convention (`tests/unit/test_plugin_registry.py`) and (b) documentation of
   what the OPA-as-a-plugin shape used to look like before the
   `PolicyEnginePort` extraction. **If you are asked to "wire the OPA policy
   plugin into the registry" — stop and confirm with the maintainer first.**
   That was a deliberate, tested architectural decision
   (`tests/unit/test_registry_no_policy.py`), not an oversight.
   `TASKS.md` packet 2 (`#156`–`#158`, "Separate Analyzer and Policy
   Contracts") still shows these as `TODO` in that file — the file is stale
   for this item; the code and the passing test both confirm the split is
   already implemented. Don't trust `TASKS.md` status columns over the
   code+tests for this specific area; re-check before citing either source.
   CLAUDE.md's phrase "19 scanner plugins (+ OPA policy plugin)" is best
   read as "19 plugins in `PluginRegistry`, plus OPA policy enforcement
   elsewhere in the pipeline" — not as "20 entries in one registry."

2. **`depends_on` ordering doesn't gate data flow.** Topological sort only
   changes iteration order fed into the thread pool; it does not create a
   wave barrier or pass one plugin's output into another's `run()`. Today
   zero in-tree plugins rely on this for anything beyond historical OPA
   ordering (which is now dead). If a future plugin needs another plugin's
   findings as input, the registry does not currently give you that for
   free — don't assume `depends_on` solves it.

3. **Unknown `depends_on` names are silently dropped**, and a plugin
   disabled via `--disable` simply vanishes from the dependency graph rather
   than causing an error for anything that named it. This is intentional
   fail-open behavior but it means a typo'd dependency name produces zero
   feedback — nothing tells you your ordering constraint was ignored. If
   your plugin's execution order looks wrong, check the exact string spelling
   against `PluginRegistry.list()` / the `plugins` CLI output before assuming
   a bug elsewhere.

4. **Two "plugin" concepts share vocabulary but not a registry.**
   `ANALYZERS`/`PluginRegistry` (scanner plugins, this skill) is a completely
   different mechanism from `PARTING` (`caliper part` analyzers,
   `plugins/_parting.py`) and `INSPECT_BACKENDS`/`GAUGE_DRAFTERS` (LLM-backed
   `caliper inspect`/`caliper gauge` backends, `plugins/_inspect_llm.py`) —
   all four are `Registry[T]` instances from the same generic
   `adapter_registry.Registry` class, all self-register via decorators, but
   they are four separate registries with four separate `ANALYZERS`-style
   sibling names in `core/port_registries.py`. "Add it to the registry" is
   ambiguous in this codebase — always name which registry.

5. **Third-party plugin SDK is brand new** (commit `c78154b`, 2026-07-02) —
   it has exactly one consumer package in the wild: none yet. The fail-open
   paths are unit-tested with a faked `entry_points()` (`test_plugin_sdk.py`)
   but there is no integration test installing a real, separately-packaged
   third-party plugin end-to-end. If you're debugging "my installed plugin
   package isn't showing up," first confirm `importlib.metadata.entry_points(
   group="caliper.plugins")` actually sees it in the same Python environment
   caliper is running in (a common failure: the plugin package installed into
   a different venv than caliper, especially inside the container — see
   `caliper-build-and-env` for how the container's `/opt/caliper/.venv`
   differs from a host venv) before assuming the SDK itself is broken.

## Provenance & maintenance

Everything above was verified against commit `c78154b` on branch
`arch-review-fixes-and-enhancements`, repo root
`/Volumes/Extra/repos/gitrdunhq/eedom`, on 2026-07-02. Re-run these before
trusting a number in this file after that date:

```bash
# Re-count in-tree scanner plugins + confirm autodiscovery skip pattern:
ls src/caliper/plugins/*.py | grep -v '/_' | grep -v __init__ | wc -l

# Re-list what's actually live in the registries (also a smoke check):
uv run python .claude/skills/caliper-plugin-architecture/scripts/list_plugins_and_scribes.py

# Re-confirm OPA is (still) excluded from the default scanner registry:
bash scripts/build-test.sh -- tests/unit/test_registry_no_policy.py -k opa_plugin_not_in_default_registry

# Re-check depends_on / topological sort behavior:
bash scripts/build-test.sh -- tests/unit/test_plugin_registry.py

# Re-check scribe fail-open + timeout behavior:
bash scripts/build-test.sh -- tests/unit/test_scribe.py
grep -n "scribe_timeout" src/caliper/core/config.py

# Re-check third-party SDK fail-open paths:
bash scripts/build-test.sh -- tests/unit/test_plugin_sdk.py

# Re-check severity-rank dedup table hasn't changed:
grep -n "_SEVERITY_RANK" -A 6 src/caliper/core/normalizer.py

# Re-check CAPABILITIES.md agrees with what you just found:
grep -n "plugin" docs/CAPABILITIES.md | head -20
```

**Tests run in a container only.** `uv run pytest ...` on the host fails fast
with "caliper tests must run inside a container" (`tests/conftest.py`,
verified 2026-07-02) — that's enforced, not a suggestion. Use
`bash scripts/build-test.sh -- <pytest args>` for a single file/pattern, or
`make test` for the full suite. Never set `CALIPER_ALLOW_HOST_TESTS=1` (see
`caliper-testing-and-tdd`). The `uv run python` script invocation above
(listing plugins/scribes) is fine on the host — it's a plain script, not a
pytest run, and has no container guard.
