---
name: caliper-failure-archaeology
description: >-
  Chronicle of caliper's major investigations, dead ends, superseded fixes, and
  stalled/parked branches — symptom to root cause to evidence to current status —
  so nobody re-fights a settled battle or re-diagnoses a known bug. Load this
  BEFORE starting any bug hunt, "why does X behave this way" investigation, or
  before resurrecting an old branch, to check whether the question is already
  answered in docs/solutions/** or docs/reviews/**. Trigger phrases: "has this
  been investigated before", "why was this reverted", "is this a known issue",
  "what happened to branch X", "dead end", "root cause", "postmortem", "why is
  this a no-op / silent failure", "fail-open erosion", "stalled work", "parked
  branch". Companion to caliper-fail-open-resilience (the forward-looking audit
  checklist for THIS project's specific fail-open recurrence) and
  adversarial-review (the mechanics of how docs/reviews/*.md reports are produced).
---

# Caliper Failure Archaeology

A record of settled battles. Every entry below is: **symptom → root cause →
evidence (file:line / commit) → status verified against the actual repo on
2026-07-02.** If your current task rhymes with an entry here, stop and read
the entry before writing new code — you may be about to re-diagnose (or worse,
re-break) something that was already fixed, or about to resurrect a branch
that was deliberately parked.

## When to use this skill

- Before investigating a bug that "smells familiar" (fail-open bypass, silent
  no-op, mock-masked test pass, constructor mismatch after a multi-agent build).
- Before touching `task/codeintel-mcp-spec` or `wip/debug-echo-session` or any
  other long-lived non-`main` branch — check whether it's a dead end here first.
- Before writing a new `docs/solutions/**` entry — check none of the 8 existing
  ones already cover your symptom.
- When a reviewer/agent flags something and you want to know "was this already
  found and fixed, and did the fix actually stick?"

## When NOT to use this skill

| If you need... | Use instead |
|---|---|
| A forward-looking checklist to audit new code for fail-open regressions | `caliper-fail-open-resilience` |
| To actually run a multi-agent adversarial review and produce a new `docs/reviews/*.md` | `adversarial-review` |
| The three-tier import-direction rules themselves (not their violation history) | `caliper-architecture-contract` |
| Step-by-step live debugging technique (how to attach, how to repro) | `caliper-debugging-playbook` |
| The commit-message/RED-GREEN/dogfood change-control rules | `caliper-change-control` |

This skill is a **history book**, not a **rulebook**. It tells you what
happened and whether it's settled; it does not define the rules going forward
(those live in the skills above and in `CLAUDE.md`).

## How this record was built (verify-before-trust)

Every claim below was checked against the live repo on 2026-07-02, not taken
from the source docs on faith:

```bash
# Re-run this to regenerate the investigation index from scratch:
bash .claude/skills/caliper-failure-archaeology/scripts/list_investigations.sh
```

Observed output at time of writing (2026-07-02):

```
FILE                                                                   STATUS     SEVERITY  TITLE
----                                                                   ------     --------  -----
docs/solutions/integration-issues/mock-masked-integration-wiring-failures.md diagnosed  high      Mock-Masked Integration Wiring Failures
docs/solutions/integration-issues/review-loop-resolution-pass1-to-pass2.md resolved   high      Review Loop Resolution — BLOCKED_CRITICAL to PASSED in One Fix Pass
docs/solutions/performance-issues/architecture-violations-coupling-and-sequential-scanners.md diagnosed  high      Architecture Violations — Coupling, Layer Inversion, and Sequential Scanners
docs/solutions/runtime-errors/missing-runtime-guards-fail-open-erosion.md diagnosed  high      Missing Runtime Guards — Fail-Open Erosion
docs/solutions/runtime-errors/silent-safety-rule-bypasses.md           diagnosed  high      Silent Safety Rule Bypasses
docs/solutions/security-issues/injection-and-secret-leaks-across-layers.md diagnosed  high      Injection and Secret Leaks Across Three Layers
docs/solutions/security/reject-detection-bypass.md                     n/a        n/a       Solution: Reject Detection Bypass in Agent Block Mode
docs/solutions/testing/deterministic-bug-detector-test-plan.md         n/a        n/a       Deterministic Bug Detector Test Plan
```

**Important caveat about the `status:` field**: 6 of 8 docs are frozen at
`diagnosed` in their YAML front matter, but the code has moved on — I spot
checked every fix claimed in this skill against current `src/` (commands in
each section below) and all except the reject-detection-bypass fix (see
[Special case](#special-case-a-fix-that-was-superseded-by-a-better-fix) below)
are present verbatim in `main` today. **Read `status:` as "diagnosed as of
2026-04-23," not "still open."** Don't trust the front matter alone — run the
verification command in each section.

Two more things worth knowing before you dig in:

- The `.wfc/reviews/REVIEW-main-001.md` / `REVIEW-main-002.md` and
  `issues.jsonl` files that every `docs/solutions/**` doc cites under
  "Related" **no longer exist in the repo** (`.wfc/reviews/` and the root
  `issues.jsonl` were pruned at some point — confirmed absent on 2026-07-02).
  The `docs/solutions/**` markdown files are now the *only* surviving record
  of that review. Don't go looking for the original review transcript; it's
  gone, and these docs are the compound/summary that was intentionally kept.
- `docs/reviews/*.md` (adversarial review reports) are a **different kind of
  evidence** — raw/challenger-confirmed findings from the `adversarial-review`
  skill's pipeline, not necessarily fixed yet. Treat a `docs/reviews/*.md`
  entry as "an audit found this" (worth checking current status yourself), and
  a `docs/solutions/**` entry as "an investigation ran to ground and there's a
  prevention writeup."

## The one the maintainer flagged: silent fail-open erosion

**This was the costliest failure class investigated on this project.** Full
treatment below; for the forward-looking recurrence checklist, use
`caliper-fail-open-resilience` — this section is the *history*, that skill is
the *guardrail*.

### Symptom

Caliper's entire value proposition is "no scanner failure blocks a build"
(`CLAUDE.md` § Critical Design Rules — fail-open). But a 2026-04-23 review
(`.wfc/reviews/REVIEW-main-001.md`, now pruned; summarized in
`docs/solutions/runtime-errors/missing-runtime-guards-fail-open-erosion.md`
and `docs/solutions/runtime-errors/silent-safety-rule-bypasses.md`) found that
the fail-open *design* was correct but had eroded into fail-open-for-everything
— including bugs, crashes, and silently-disabled policy rules that produced no
log, no warning, and no test failure. Three independent mechanisms, one shared
root cause.

### Root cause chain

1. **Fail-open was implemented as "catch broadly and continue," not "catch the
   specific expected degradation and continue."** `sys.exit(0)` was called
   unconditionally at the end of the CLI's `evaluate` command — even after an
   *unhandled* exception was logged. Jenkins therefore could not distinguish
   "ran clean" from "crashed before scanning a single package" (finding F-006).
2. **A wall-clock budget was configured but never enforced.**
   `config.pipeline_timeout` was loaded into `CaliperSettings` and never once
   compared against elapsed time anywhere in the per-package loop — so a slow
   scanner could not be interrupted, which is the opposite of fail-open (it's
   fail-*hang*) (finding F-007).
3. **A type mismatch (`str` vs `Path`) routed a config bug through the
   scanner's generic `except Exception` handler**, so it was recorded as "the
   scanner failed" (an *expected* degradation, correctly fail-opened) instead
   of "our wiring is broken" (a bug that should fail loudly) (finding F-014).
4. **Two of six OPA policy rules were structurally incapable of firing** because
   the Python code building `package_metadata` omitted two fields
   (`first_published_date`, `transitive_dep_count`) that the Rego rules read.
   In Rego, a missing field evaluates to `undefined`, which silently skips the
   rule body — no error, no OPA warning, nothing in the logs
   (finding F-012, `docs/solutions/runtime-errors/silent-safety-rule-bypasses.md`).
5. **A CVSS-severity fallback loop was a bare `pass`** — CVEs with a CVSS
   vector but no `database_specific.severity` were silently rated `info`,
   which meant the OPA "deny on critical/high" rule never triggered for a
   large class of real-world NVD-sourced CVEs (finding F-010, same doc).

The common thread across all five: **the fail-open design covered the
*expected* degradation paths (scanner timeout, DB down, OPA crash) but not the
*meta*-failures** — the pipeline's own bugs, its own timeout enforcement, and
silent `undefined`/no-op branches in the policy-input boundary. A `pass`
statement and a missing dict key are indistinguishable from "working as
designed" unless something asserts the positive case.

### How it was caught

A structured multi-pass review (documented as "Pass 1" in
`docs/solutions/integration-issues/review-loop-resolution-pass1-to-pass2.md`)
— NOT ad hoc debugging. Pass 1 returned `BLOCKED_CRITICAL` (30 findings, 7 at
severity 10). The fail-open findings specifically were caught by:

- **F-006/F-007** (exit-code, timeout): caught by a reliability-focused
  reviewer reasoning from `CLAUDE.md`'s own fail-open promise — i.e. the bug
  was found by taking the design doc seriously and checking the code against
  it, not by hitting the bug in production.
- **F-010/F-012** (CVSS no-op, missing OPA fields): caught by a
  correctness/security reviewer who traced data flow from `osv.py` through
  the normalizer into the OPA input builder and noticed the Rego schema
  (`policies/INPUT_SCHEMA.md`) required fields the Python code never
  populated. This is the "contract between producer and consumer never
  validated at the boundary" pattern — Rego's `undefined`-on-missing-field
  semantics is a deliberate composability feature that is also a silent
  footgun for the caller.

### How it was fixed

Verify these are still true against current `main` (all four commands below
were run on 2026-07-02 and returned non-empty matches):

```bash
# 1. Exit code differentiates crash (1) from clean/degraded run — no bare unconditional exit(0)
grep -n "SystemExit(1)" src/caliper/cli/main.py

# 2. Parallel scanners exist (the timeout-budget fix rode along with the
#    performance fix — see the companion architecture-violations doc)
grep -n "ThreadPoolExecutor" src/caliper/core/orchestrator.py

# 3. CVSS fallback is no longer a bare `pass` — it parses a numeric score
grep -n "_cvss_score_to_severity\|_map_severity" src/caliper/data/scanners/osv.py

# 4. Secrets never hit the log verbatim (the DSN-masking sibling of this fix)
grep -n "_safe_dsn" src/caliper/data/db.py
```

Each returns real matches in the current tree — the fixes landed and stuck.
`core/pipeline.py` now exists as the extracted service layer (see
"Architecture violations" below) and carries the timeout/exit-code discipline
that used to live loose inside `cli/main.py`.

### Status: fixed, but treat as a recurring risk class, not a one-time patch

The five bugs above were closed in the 2026-04-23 review-loop pass. That does
**not** mean "silent fail-open erosion" as a *class* of bug is closed — it's a
shape of bug (broad `except Exception`, unenforced config, `pass` in a
fallback branch, an optional dict key a downstream Rego/schema consumer
silently treats as `undefined`) that a new plugin or detector can reintroduce
at any time. **Use `caliper-fail-open-resilience` to audit new code against
this exact recurrence pattern** — it is the dedicated, forward-looking
checklist built specifically because this was the costliest failure class
found on this project.

## Other settled investigations (docs/solutions/**)

Each of these follows the same review-loop-pass-1 provenance as the fail-open
entry above (same 2026-04-23 review, same now-pruned `.wfc/reviews/` source) —
they are siblings, not separate incidents. Verified present in current `main`
unless noted.

### Mock-masked integration wiring failures

**Symptom:** 246 tests passed; the CLI crashed with `TypeError` on every real
invocation, before a single package was evaluated.
**Root cause:** 4 parallel agents each built modules correctly in isolation;
a 5th "wiring" agent guessed constructor signatures wrong 4 times
(`OsvScanner(evidence_dir=...)` when the real signature took no such kwarg,
`TrivyScanner(evidence_dir=...)` when `TrivyScanner` had no `__init__` at
all, etc.). The E2E test that should have caught this mocked
`ScanOrchestrator` at the **class** level, so it tested a different pipeline
than the one the CLI actually ran.
**Evidence:** `docs/solutions/integration-issues/mock-masked-integration-wiring-failures.md`.
**Status:** fixed — `src/caliper/cli/main.py` and `src/caliper/core/pipeline.py`
now instantiate scanners with their real signatures.
**Reusable lesson:** an E2E/integration test should mock at the *system*
boundary (subprocess, network, DB), never at the *application* boundary
(class constructors). If you have to mock a constructor to make an
integration test pass, the integration itself is broken — the test is telling
you something, not lying to you.

### Silent safety rule bypasses

Covered above as part of the fail-open entry (F-010, F-012). See that section.

### Architecture violations — coupling, layer inversion, sequential scanners

**Symptom:** changing a scanner's private helper broke the orchestrator;
`cli/main.py`'s `evaluate` command held ~150 lines of business logic; the
scanner phase burned 80% of the 300s pipeline timeout budget running
scanners one at a time when they're fully independent.
**Root cause:** the three-tier architecture was specified correctly in
`CLAUDE.md` but not enforced — `core/orchestrator.py` imported a private
(`_`-prefixed) symbol from `data/scanners/base.py` (a DIP violation), all
pipeline logic lived in the presentation layer instead of a service layer,
and scanners ran in a plain `for` loop instead of a thread pool.
**Evidence:** `docs/solutions/performance-issues/architecture-violations-coupling-and-sequential-scanners.md`.
**Status:** fixed and durably enforced — `core/pipeline.py` (extracted
`ReviewPipeline` service) and `core/orchestrator.py`
(`ThreadPoolExecutor`-based) both exist in current `main`, **and** the
architecture is now guarded by an AST-walking test
(`tests/unit/test_deterministic_architecture_guards.py`, see
`caliper-architecture-contract`) so a regression here fails CI, not just a
future manual review.
**Reusable lesson:** "run scanners in parallel where practical" as prose in a
design doc is not self-enforcing. The fix that stuck is the one with a test,
not the one with a paragraph.

### Injection and secret leaks across three layers

**Symptom:** no visible symptom — three latent vulnerabilities (Jenkins
Groovy shell injection via `team` param string interpolation, Postgres DSN
with password logged verbatim on every connect/fail, PyPI package
description concatenated unescaped into an LLM prompt) that would never
surface as a test failure because they were all functionally correct code.
**Root cause:** three different parallel agents each implemented their layer
correctly in isolation with zero cross-layer security review at the
trust-boundary crossings (Groovy string → shell, Python string → log line,
untrusted metadata → LLM prompt).
**Evidence:** `docs/solutions/security-issues/injection-and-secret-leaks-across-layers.md`.
**Status:** fixed — verify with `grep -n "_safe_dsn" src/caliper/data/db.py`
(masks the password before every log call) and
`grep -n "SecretStr" src/caliper/webhook/config.py` (the same `SecretStr`
discipline is now applied project-wide at trust boundaries, not just the DB
DSN this doc originally covered).
**Reusable lesson:** security bugs are orthogonal to functional correctness —
none of these three would ever fail a unit test. They need a
security-specific reviewer pass, which is exactly what a `focus: security`
`adversarial-review` run is for.

### Review-loop resolution: BLOCKED_CRITICAL → PASSED in one fix pass

This is the meta-document tying all four entries above together: Pass 1 found
30 findings (7 critical), Pass 2 (after a single fix pass) found 10 (0
critical). It also documents **3 regressions the fix pass itself introduced**
and caught by re-review — worth reading if you're about to do a large
multi-finding fix pass yourself:

| Regression | Root cause |
|---|---|
| `store_file()` missing the same path-traversal guard just added to `store()` | Fix agent patched one call site of a duplicated pattern, didn't grep for the sibling |
| Version comparison still used string ordering | Finding was assigned to an agent that stalled before reaching it |
| Config-failure message fixed in the log call but not the user-facing `click.echo` | Fix agent changed one of two places the same message was rendered |

**Reusable lesson (grep-for-pattern discipline):** after applying a fix to one
call site, `grep -n "<the pattern you just fixed>" <file and adjacent files>`
before considering the fix done. Every regression in this table is the same
shape: fixed once, not fixed everywhere the same bug existed.
**Evidence:** `docs/solutions/integration-issues/review-loop-resolution-pass1-to-pass2.md`.
**Status:** resolved (the only doc in `docs/solutions/**` whose front matter
says `resolved` rather than `diagnosed`).

### Special case: a fix that was superseded by a better fix

`docs/solutions/security/reject-detection-bypass.md` documents a real bug —
Foreman agent block mode determined whether to fail CI by regex-matching
reject markers (`"REJECTED"`, `"reject"`, `"🔴"`) in the LLM's free-text prose,
which prompt injection could dodge — and a fix:
`_extract_reject_from_tool_results()` reading the structured `decision` field
out of the `evaluate_change` tool call's return payload instead of the LLM's
prose.

**That specific function does not exist in current `main`** (confirmed via
`grep -n "_extract_reject_from_tool_results" src/caliper/agent/main.py` →
no match, 2026-07-02). It was superseded by a **stronger** fix, commit
`97a14d5` ("fix(agent): gate Foreman block mode on deterministic pipeline
verdict, not LLM response shape", closes #205, 2026-07-01): the original fix
still depended on the LLM actually *calling* the `evaluate_change` tool and
shaping its response correctly — a prose-only or tool-skipping LLM turn would
silently fall through to the default (approve). The superseding fix removed
that dependency entirely: `ForemanAgent` now calls a direct,
LLM-independent `_run_deterministic_pipeline()` and gates block/warn/log on
the typed `DecisionVerdict` it returns, regardless of what the LLM chose to
say or do. Verify:

```bash
grep -n "_run_deterministic_pipeline\|has_reject" src/caliper/agent/main.py
```

**Status:** fixed (current, stronger form). **Reusable lesson:** a
`docs/solutions/**` entry records the fix *that was believed sufficient at
the time it was written*. Always verify against current source before citing
one as settled — the doc is a snapshot, not a live contract. This is exactly
why this skill's investigation index script exists: to make "is this doc
still accurate" a one-command check instead of an assumption.

## Adversarial review reports (docs/reviews/**) — a different evidence class

`docs/reviews/*.md` are produced by the `adversarial-review` skill's
pipeline (Haiku reviewer fan-out → Sonnet/Haiku challenger → optional Opus
adjudication). Don't confuse these with `docs/solutions/**`:

| | `docs/solutions/**` | `docs/reviews/**` |
|---|---|---|
| What it is | A closed-loop investigation: symptom, root cause, fix, prevention | A funnel report from one review run: raw candidates → confirmed/false-positive/uncertain |
| Fixed? | Usually yes (verify per-entry as shown above) | Not necessarily — confirmed findings may still be open |
| Use for | "Has this exact bug been solved before" | "What did the last audit of this area find" |

As of 2026-07-02, `docs/reviews/` holds 6 reports (2,285 total lines):

```bash
wc -l docs/reviews/*.md
```

The two worth knowing about by name if you're deciding whether to trust a
`docs/reviews/*.md` finding at face value:

- **`adversarial-2026-06-22.md`** — full-codebase sweep, 20 partitions, Haiku
  reviewer + Haiku challenger (no separate verifier model). Funnel: 117 raw
  candidates → 69 confirmed (20 high / 32 medium / 17 low), 38 false
  positives, 10 uncertain. **This is raw audit output, not a fixed-bugs
  ledger** — confirmed findings here have not necessarily been triaged into
  `docs/solutions/**` or fixed. Treat a citation of this file as "an audit
  flagged this," not "this was resolved."
- **`grounding-conclusions-2026-06-22.md`** — a methodology finding, not a
  code finding: a cheap Haiku *verifier* (as opposed to the Sonnet/Opus
  challenger the current `adversarial-review` skill defaults to)
  over-confirmed 57% (39/69) of ungrounded candidates as real bugs, including
  rubber-stamping **documented, intentional fail-open code paths** as if they
  were defects. This is *why* `adversarial-review`'s default challenger model
  is Sonnet, never Haiku — see that skill for the current policy. Don't
  re-litigate "should the challenger be cheap" here; it's already answered.

## Stalled and parked branches

### `wip/debug-echo-session` — parked, not a dead end to silently delete, but not mergeable either

```bash
git log wip/debug-echo-session -1 --format='%H %s'
# 1d860c206f6c1464f787948f8a66959575817b71 wip: debug-echo session changes (parked; breaks 130 tests — see fix/lockfile-and-purge report)
```

**What it is:** a single commit (Dockerfile RTK-container integration + a
debug-echo flag threaded through `src/eedom/cli/main.py` and
`src/eedom/core/registry.py` + a `scripts/scan.sh` passthrough-args change),
authored 2026-06-11, self-labeled in its own commit message: *"Not for
merge — preserving session state."*

**Status: parked, confirmed dead relative to current `main`.** Two
independent signals confirm this, not just the commit message:

1. It sits 50 commits behind `main` and only 1 ahead (`git log
   main..wip/debug-echo-session --oneline | wc -l` → `1`;
   `git log wip/debug-echo-session..main --oneline | wc -l` → `50`, as of
   2026-07-02).
2. It still says `src/eedom/...` — this predates the project-wide
   eedom→caliper rename (`.wfc` memory note: "old dir/branches say eedom,
   current code/remote is caliper"). Any branch still referencing
   `src/eedom` is, by definition, pre-rename and cannot be merged as-is.

**Do not silently delete this branch** — it's explicitly a preserved debug
session, not abandoned work someone forgot about, and the commit message
points at a companion report (`fix/lockfile-and-purge`, not found as a
branch or file in this repo as of 2026-07-02 — likely itself pruned or was a
local-only note). If you need the RTK-container/debug-echo idea, treat this
branch as **prior art to read, not a branch to rebase and merge** — it breaks
130 tests by its own account and predates the current module layout entirely.

### `task/codeintel-mcp-spec` — a docs-only spec that was never implemented, also pre-rename

```bash
git log task/codeintel-mcp-spec --oneline
# e95d64e docs: add CodeIntel MCP capability spec
# b8e14e4 fix: Pydantic boundary contracts for solver module
# f1213a5 feat: add solver module — LLM-powered detector test generation via OpenRouter
# 49e7af0 fix: parallelize CI, switch to GH-hosted runners, eliminate push-to-main duplication
# ... (continues into shared history with main)
```

**What it is:** 3 commits ahead of the point it branched from, 50 behind
current `main` (same `git log A..B --oneline | wc -l` check as above, run on
2026-07-02: 3 ahead / 50 behind). The 3 commits are (newest first): a
246-line `docs/codeintel-mcp-capability-spec.md` design doc (status: `Draft`,
dated 2026-04-29, targeting issue #297) for a deterministic
(explicitly "zero-LLM-in-the-decision-path") code-intelligence MCP surface
built on top of caliper's existing `CodeGraph`/`blast-radius` primitives; a
Pydantic boundary-contracts fix; and a `solver.py` module (LLM-powered
detector-test generation via OpenRouter, with a model fallback ladder).

**Status: spec never implemented, module removed/superseded.** Confirmed:

```bash
find . -iname "*solver*" -not -path "./.git/*"
# (no output — src/eedom/core/solver.py and scripts/solve-issues.py do not exist anywhere in the current tree)
```

The spec doc itself is a legitimate design artifact — the *idea* (deterministic
code-intel MCP surface over the existing code graph) may still be worth
reading before starting similar work, since it pre-dates and conceptually
overlaps with capabilities the project has since grown independently
(`core/tier_map.py` guard resolution, the `blast-radius` plugin, and this
very tokensave-MCP-backed exploration workflow). But nothing on this branch
shipped: `src/eedom/core/solver.py` never made it past this one branch, and
the branch predates the eedom→caliper rename just like `wip/debug-echo-session`.
Treat the spec as **requirements-gathering that was superseded by organic
growth**, not as a blocked or in-progress feature.

## A stale planning doc worth knowing about: `TASKS.md`

Not a branch, but the same "looks live, isn't" trap. `TASKS.md` at repo root
describes "Epic #146 — Black-Box Architecture Refactoring," 28 tasks across
11 packets, every single one marked `TODO`:

```bash
grep -c '| TODO |' TASKS.md
# 28
git log --oneline -- TASKS.md
# b62838f chore: add TASKS.md for next branch architecture refactoring
```

`TASKS.md` was added in exactly one commit and never updated since — no
task's status was ever flipped from `TODO`. Taken at face value, this reads
as "none of this refactor happened." **That's misleading.** The `next`
branch it describes no longer exists (already merged/consolidated into
`main` at some point), and several of the packets' actual deliverables are
present in current `main` today:

```bash
ls src/caliper/composition/          # bootstrap.py — Packet 3's composition root
grep -l "ToolRunnerPort" src/caliper/core/*.py   # Packet 4's port, already defined and consumed
grep -l "RepoSnapshotPort" src/caliper/core/*.py # Packet 5's port
grep -l "PullRequestPublisherPort" src/caliper/core/*.py # Packet 6's port
```

**Lesson for this skill's own methodology:** a task-tracking doc's checkbox
state is not evidence of anything once nobody is maintaining it. The
ground truth is always "does the described artifact exist in `src/` today,"
never "what does the doc say." If you're ever asked to pick up "Epic #146,"
re-audit which of the 28 tasks are *actually* still undone before assuming
the doc's `TODO` markers are accurate — most of the architectural shape it
wanted already exists under different, undocumented effort.

## Quick lookup table

| You're investigating... | Go read |
|---|---|
| A scanner/plugin swallowing an error it shouldn't | Fail-open erosion, above, then `caliper-fail-open-resilience` |
| Tests all pass but the CLI crashes for real users | Mock-masked integration wiring failures |
| An OPA rule that never seems to fire | Silent safety rule bypasses (fail-open entry, F-012) |
| core/ importing something from data/ or plugins/ | Architecture violations entry, then `caliper-architecture-contract` |
| A secret/DSN/token showing up in logs | Injection and secret leaks across layers |
| Foreman agent block mode not blocking | Reject-detection bypass special case |
| Whether an old branch is safe to resurrect | Stalled and parked branches, above |
| Whether `TASKS.md` / Epic #146 is actually still open | The `TASKS.md` section, above — audit `src/`, don't trust the doc |

## Provenance & maintenance

Every fact above was verified against the repo on **2026-07-02**. Re-run
these when this skill starts to feel stale:

```bash
# Regenerate the investigation status table (also ships as scripts/list_investigations.sh)
bash .claude/skills/caliper-failure-archaeology/scripts/list_investigations.sh

# Re-check ahead/behind counts for the two archived branches
git log main..task/codeintel-mcp-spec --oneline | wc -l   # was 3
git log task/codeintel-mcp-spec..main --oneline | wc -l   # was 50
git log main..wip/debug-echo-session --oneline | wc -l    # was 1
git log wip/debug-echo-session..main --oneline | wc -l    # was 50

# Re-check that fail-open fixes are still present (see "How it was fixed" above)
grep -n "SystemExit(1)" src/caliper/cli/main.py
grep -n "ThreadPoolExecutor" src/caliper/core/orchestrator.py
grep -n "_cvss_score_to_severity" src/caliper/data/scanners/osv.py
grep -n "_safe_dsn" src/caliper/data/db.py

# Re-check the reject-detection-bypass supersession is still current
grep -n "_run_deterministic_pipeline" src/caliper/agent/main.py

# Re-check TASKS.md hasn't quietly been updated (would change the "stale doc" framing)
git log --oneline -- TASKS.md

# Re-count docs/reviews size (was 2,285 lines across 6 files)
wc -l docs/reviews/*.md

# Confirm .wfc/reviews/ and issues.jsonl are still absent (would change the "sole surviving record" claim)
find .wfc -iname "REVIEW-main*" 2>&1
find . -maxdepth 1 -iname "issues.jsonl"
```

If `caliper-fail-open-resilience` doesn't exist yet in
`.claude/skills/` when you read this, that's a sibling skill still being
authored in the same pass as this one — the cross-reference above is
forward-looking by design, not a broken link.
