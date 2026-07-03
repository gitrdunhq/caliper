---
name: caliper-architecture-contract
description: >-
  The load-bearing design contract for caliper's own source tree: the
  ports-and-adapters tier boundary (presentation / core / data / adapters /
  plugins / detectors / kernel), WHY imports must flow inward only, how the
  boundary is mechanically enforced (AST guard test, not a lint suggestion),
  and known-weak points in the current refactor. Load this BEFORE adding a
  new top-level directory under src/caliper/, BEFORE adding an import that
  crosses cli/agent/webhook/composition <-> core <-> data/adapters/plugins/
  detectors, when a PR fails
  tests/unit/test_deterministic_architecture_guards.py, when asked "why can't
  core import X", "where does this module belong", "is this a layering
  violation", or "what is the state of Epic #146 / the black-box refactor".
  Not for: plugin internals (see caliper-plugin-architecture), writing a new
  plugin (see caliper-plugin-authoring-playbook), build/container mechanics
  (see caliper-build-and-env), test process (see caliper-testing-and-tdd),
  commit/PR process (see caliper-change-control).
---

# Caliper Architecture Contract

Ground truth as of **2026-07-02**, commit `c78154b`. This skill states the
rule, states WHY, tells you how to check yourself in 5 seconds, and tells you
plainly where the refactor is still unfinished. If anything here conflicts
with `CLAUDE.md`'s "Architecture" section or with
`tests/unit/test_deterministic_architecture_guards.py`, **those two win** —
this skill is a guide to them, not a replacement.

## When NOT to use this skill

| If you're... | Use instead |
|---|---|
| Writing/modifying a scanner plugin's internals | `caliper-plugin-architecture` |
| Authoring a brand-new plugin from scratch | `caliper-plugin-authoring-playbook` |
| Building/rebuilding the container image | `caliper-build-and-env` |
| Deciding how to structure a TDD red/green split or a commit | `caliper-change-control` |
| Debugging why a test suite run fails | `caliper-testing-and-tdd` |
| Reading `.caliper.yaml` config flags | `caliper-config-and-flags` |
| Root-causing a past incident | `caliper-failure-archaeology` |

Use *this* skill when the question is "which tier does this file belong in"
or "why is this import forbidden" or "is the architecture doc still
accurate".

## The rule (one sentence)

Imports flow **inward, toward `core`, never outward, never sideways between
outer tiers.** `presentation` is the only tier allowed to import anything.

## The tier map (verified against `src/caliper/core/tier_map.py`, `DEFAULT_ALLOWED`)

| Source tier | Directories | May import | May NOT import |
|---|---|---|---|
| `presentation` | `cli/`, `agent/`, `webhook/`, `composition/` | anything (`ANY_TIER`) | — (unrestricted; this is where concrete adapters get wired together) |
| `core` | `core/` | `core`, `kernel` | `presentation`, `data`, `adapters`, `plugins`, `detectors` |
| `data` | `data/` | `data`, `core`, `kernel` | `presentation`, `adapters`, `plugins`, `detectors` |
| `adapters` | `adapters/` | `adapters`, `core`, `kernel` | `presentation`, `data`, `plugins`, `detectors` |
| `plugins` | `plugins/` | `plugins`, `core`, `kernel` | `presentation`, `data`, `adapters`, `detectors` |
| `detectors` | `detectors/` | `detectors`, `core`, `kernel` | `presentation`, `data`, `adapters`, `plugins` |
| `kernel` | root-level `src/caliper/*.py` (e.g. `_base.py`, `adapter_registry.py`) | `kernel` only | everything in `caliper` (depends on nothing) |

**Jargon, defined once:**
- **kernel** — the two root-level modules directly under `src/caliper/` (not `__init__.py`, which is special-cased as the public-API facade and counts as `presentation`). Importable from *any* tier because it imports nothing else in `caliper`. Verified: as of 2026-07-02 this is exactly `_base.py` and `adapter_registry.py` — a tiny, deliberately narrow surface. Treat adding a third kernel module as a decision, not a drive-by: anything placed there becomes globally importable, which is the one place the boundary can be silently widened.
- **`data/adapters/plugins/detectors` are siblings, not a hierarchy** — `data` cannot import `plugins`, `plugins` cannot import `detectors`, etc. Each outer tier can only reach inward to `core`/`kernel` or sideways within itself.
- **package-root facade** — `src/caliper/__init__.py` is classified as `presentation` (not `kernel`) specifically so it may re-export from `core` (it currently re-exports `REPORT_SCHEMA_VERSION`, `FindingModel`, etc. from `caliper.core.report_schema`) without being flagged as a boundary violation.

## WHY (the design rationale)

- **Business logic must be testable without a container, a DB, or a subprocess.** `core/` has zero knowledge of Click, HTTP, or concrete scanner subprocess invocation — it only knows ports/contracts. This is what lets `tests/unit/test_deterministic_architecture_guards.py` itself run without any runtime wiring (pure AST + pure `tier_map` functions, no I/O beyond reading `.py` files).
- **`presentation` is where concrete adapters get wired** (composition root, `src/caliper/composition/`) — it is intentionally the *only* unrestricted tier, so wiring concerns don't leak into anything that has to stay pure.
- **Outer tiers (`data`/`adapters`/`plugins`/`detectors`) are siblings by design**, not because caliper forgot to unify them — a plugin has no legitimate reason to import a detector's internals or vice versa; both should only ever need `core`'s ports.
- **Fail-fast over fail-quiet**: an import of an unmapped `caliper.*` package resolves to the tier `"unknown"`, which is in nobody's allow-set — so a typo'd or new top-level directory fails loudly instead of silently being treated as kernel-safe. `test_unmapped_target_is_a_violation_not_kernel` guards this specific footgun.
- **Relative imports are resolved, not skipped.** A `from ..data.parquet_writer import x` written inside `core/` is resolved to its absolute `caliper.data.parquet_writer` form before the check runs — `test_relative_upward_import_is_flagged` exists because a lazier implementation could let a two-level-up relative import quietly cross a tier boundary.

## How it's enforced — three related-but-distinct mechanisms (don't conflate them)

| Mechanism | File | Scope | Enforcement | Fires on |
|---|---|---|---|---|
| **The guard test** | `tests/unit/test_deterministic_architecture_guards.py` | caliper's own repo only | Enforced in CI, not `xfail` — a new violating import fails the build | Any `src/caliper/**/*.py` |
| **CAL-022 detector** | `src/caliper/detectors/security/tier_boundary.py` | Any repo caliper scans, opt-in | Medium-severity finding, fail-open when unconfigured | Only fires if the *scanned* repo declares `architecture.tiers`/`allow` in its own `.caliper.yaml` — generalizes caliper's own pattern for other codebases to adopt |
| **`ArchBoundaryDetector`** (older, narrower) | `src/caliper/detectors/security/arch_boundary.py` | Any repo caliper scans | Regex-based, single hardcoded rule | Only flags `presentation` (`agent/`, `cli/`) directly importing `caliper.data` — predates the AST guard (GitHub #231), narrower and regex-based rather than AST-based |

Verified 2026-07-02: caliper's own `.caliper.yaml` does **not** set
`architecture.tiers` — so CAL-022 never fires on caliper scanning itself. The
guard test is the only thing enforcing caliper's own boundary. If you're
asking "how do I stop *my own new module* from violating the tier rule," the
answer is always the guard test (`make test`, see below), not CAL-022.

Both `tier_boundary.py` (CAL-022) and the guard test import the *same* pure
resolution functions from `core/tier_map.py` (`source_tier`, `target_tier`,
`imported_caliper_modules`, `kernel_modules`) — one bug fix in `tier_map.py`
fixes both. `arch_boundary.py` is independent, older code and does not share
that logic.

## Self-check before you push

**Fast, no container, no network** — reuses the exact `tier_map.py` functions
the enforced test imports:

```bash
uv run python .claude/skills/caliper-architecture-contract/scripts/check_tier_boundaries.py
```

Verified output on this repo, 2026-07-02, commit `c78154b`:
```
No tier boundary violations found.
```

Add `--summary` for a per-tier file count and import-edge table (also
verified against this repo, 2026-07-02):

```bash
uv run python .claude/skills/caliper-architecture-contract/scripts/check_tier_boundaries.py --summary
```
```
Tiered files: 210
  adapters     5 files
  core         81 files
  data         19 files
  detectors    37 files
  kernel       2 files
  plugins      36 files
  presentation 30 files

Import edges observed (source_tier -> target_tier: count):
  adapters     -> core         : 6
  core         -> core         : 168
  core         -> kernel       : 5
  data         -> core         : 23
  data         -> data         : 12
  data         -> kernel       : 1
  detectors    -> core         : 36
  detectors    -> detectors    : 120
  detectors    -> kernel       : 1
  plugins      -> core         : 112
  plugins      -> kernel       : 1
  plugins      -> plugins      : 29
  presentation -> adapters     : 7
  presentation -> core         : 129
  presentation -> data         : 13
  presentation -> detectors    : 1
  presentation -> plugins      : 22
  presentation -> presentation : 43
```

This script is a **fast local signal only**. It is not a substitute for the
real test in CI — exit code 0 here does not mean the PR passes; it means this
one guard, run outside the container, currently sees no violations. Per
`CLAUDE.md`, the authoritative run is always containerized:

```bash
make test                                                          # full suite, container
bash scripts/build-test.sh -- tests/unit/test_deterministic_architecture_guards.py -x   # this test only, container
```

Never use `CALIPER_ALLOW_HOST_TESTS=1` to skip the container for the real
run — see `caliper-testing-and-tdd` / `caliper-change-control` for why.

## Deciding which tier a new file belongs in

1. Does it parse args, format output, or wire concrete adapters together? → `presentation` (`cli/`, `agent/`, `webhook/`, or `composition/` — pick based on which entry point owns it).
2. Is it pure business logic / a port definition / policy / rendering logic with no I/O of its own? → `core`.
3. Does it do persistence or call an external service (DB, PyPI, parquet)? → `data`.
4. Is it a hexagonal-architecture port *adapter* (persistence, code-graph grounding, GitHub publishing)? → `adapters`.
5. Is it a `ScannerPlugin` subclass or plugin-registry-discovered code? → `plugins`.
6. Is it one of the 22 deterministic AST bug detectors (CAL-001..022) or their shared framework? → `detectors`.
7. Does it need to be importable from literally everywhere and itself import nothing else in `caliper`? → kernel (root-level `src/caliper/*.py`) — verify this is really necessary before adding a third kernel module; see the WHY section above.

If a file doesn't cleanly fit, don't force it into `core` to "be safe" — `core`'s allow-set is the tightest (`core` + `kernel` only), so a misclassified file there will fail the guard test the moment it needs to call out to anything concrete.

## Known weak points — stated plainly, verified 2026-07-02

### 1. `TASKS.md` (Epic #146, "Black-Box Architecture Refactoring") is stale — trust `git log`, not the table

`TASKS.md` at repo root lists **every** packet/task (#147–#174) as `TODO`,
last touched 2026-04-28 — that table is **not current state**. Packet 0 is
actually DONE, packets 1–4 have substantially landed, and packets 5–10 are
partially landed (port definitions exist; several adapter-implementation
tasks are genuinely still open). **Practical rule:** if you need Epic #146's
real status, do not read `TASKS.md`'s Status column — grep
`git log --all --oneline` for the task number and check ancestry against
your branch. Full packet-by-packet detail (which commits closed which
packets, exact ancestry verification commands): see
`caliper-failure-archaeology` § "A stale planning doc worth knowing about:
`TASKS.md`" — that skill is this fact's single authoritative home.

### 2. `ARCHITECTURE.md` §2 ("Three-Tier Architecture") is stale relative to the actual 6-tier + kernel model

`ARCHITECTURE.md` section 2 (as of 2026-07-02: presentation / logic / data
headings only) predates the `adapters`/`plugins`/`detectors` split and the
kernel concept, and doesn't mention the AST guard test at all — it reads as
if `core/` ("Logic") talks directly to `data/`, with no `adapters`,
`plugins`, or `detectors` tier called out, and no kernel concept. `CLAUDE.md`
("Architecture" section) and `core/tier_map.py`/the guard test are the
current, mechanically-enforced source of truth; `ARCHITECTURE.md` §2 has not
been updated to match. Don't design against `ARCHITECTURE.md` §2's
description — verify against the guard test or this skill's tier table
instead.

### 3. The kernel is a bypass valve with only two members today

Because kernel modules are importable from every tier with no allow-set
check at all, kernel is the one place the boundary can be silently widened.
Verified 2026-07-02: exactly `_base.py` and `adapter_registry.py`
(`kernel_modules()` in `tier_map.py` derives this automatically from
`<src_root>/*.py`, so a new root-level module becomes kernel the instant it's
added — there is no separate approval gate beyond code review). If you're
tempted to add a third kernel module, ask first whether it actually needs to
be importable from `core` *and* `presentation` *and* `data` *and*
`plugins`/`detectors`/`adapters` simultaneously — most things don't, and
belong in `core` instead.

## Provenance & maintenance

Facts below are volatile — re-verify with these exact commands before
trusting them beyond 2026-07-02:

```bash
# current HEAD / date this skill was last verified against
git log -1 --format='%h %cd' --date=short HEAD

# re-run the tier boundary self-check (see "Self-check before you push" above)
uv run python .claude/skills/caliper-architecture-contract/scripts/check_tier_boundaries.py --summary

# re-check Epic #146 packet 0 (mirror-tree cleanup) status
git log --oneline --all | grep -E "closes #147, #148, #149"

# re-check which Epic #146 tasks have landed on your current branch
# (replace <task-number> with any of #147-#174; empty output means not found on any branch)
git log --oneline --all | grep -E "#<task-number>\b"

# re-count kernel modules (should stay small — see weak point #3)
ls src/caliper/*.py

# re-count detectors (docs/detectors.md claims 22 as of 2026-07-02)
grep -c '^| CAL-' docs/detectors.md

# confirm caliper's own .caliper.yaml still does not self-configure CAL-022
grep -n "architecture" .caliper.yaml

# diff ARCHITECTURE.md §2 against CLAUDE.md's Architecture section by eye
# if they've been reconciled, delete "Known weak point #2" above
sed -n '107,177p' ARCHITECTURE.md
```
