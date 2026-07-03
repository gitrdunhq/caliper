---
name: caliper-fail-open-resilience
description: >-
  Forward-looking audit checklist and contract reference for caliper's
  fail-open guarantee ("no scanner failure blocks a build"). Load this BEFORE
  writing or reviewing any code that adds an external call (subprocess,
  HTTP, DB, LLM) to a plugin/scanner/scribe, BEFORE adding a new `except`
  block around a scanner call, BEFORE touching `core/sarif.py`,
  `core/pr_review.py`, `core/pipeline.py`, or `cli/main.py`'s exit-code
  paths, or when asked to "audit for fail-open erosion", "check scanner
  timeouts before I add this except block", or "does this new error handler
  swallow errors silently." For an *already-observed* silent timeout or
  plugin failure, use caliper-debugging-playbook's triage table instead —
  this skill is the pre-change audit checklist, not in-the-moment incident
  triage. The maintainer named silent fail-open erosion as the
  single costliest failure class investigated on this project — this skill
  exists specifically to stop it recurring. Companion to
  `caliper-failure-archaeology` (the historical narrative — root cause,
  how it was caught, how it was fixed) and `caliper-architecture-contract`
  (the tier-import rules this skill's contract lives inside).
---

# Caliper Fail-Open Resilience

**Load `caliper-failure-archaeology` first if you want the full incident
history** (symptom → root cause chain → how it was caught → how it was
fixed, with commit references). This skill does not re-narrate that story —
it gives you the **contract every external call must honor**, the **exact
erosion mechanism** in one paragraph, the **degraded-plugin sentinel
pattern**, and a **runnable audit checklist** you execute today, right now,
against the code you're about to write or review.

## When NOT to use this skill

| If you're... | Use instead |
|---|---|
| Investigating whether a bug was already diagnosed/fixed before | `caliper-failure-archaeology` |
| Checking whether new code crosses `core/` → `data/`/`plugins/` tier boundaries | `caliper-architecture-contract` |
| Writing a brand-new scanner plugin from scratch | `caliper-plugin-authoring-playbook` (then come back here for the timeout/error-typing checklist) |
| Running the multi-agent adversarial review pipeline itself | `adversarial-review` |
| Debugging OPA rules that never fire | `caliper-opa-policy-playbook` (the *policy* half of "silent bypass" — this skill covers the *plugin/scanner* half) |

## The fail-open contract (verbatim from `CLAUDE.md` § Critical Design Rules)

> **Fail-open**: No scanner failure blocks a build. Every external call has a
> timeout. Every failure returns a typed result.

Unpacked into three separate, independently-checkable obligations:

1. **Every external call has an explicit, bounded timeout.** Not "the OS
   default." Not "whatever the library ships with." A named number, ideally
   sourced from `CaliperSettings` so it's one config surface, not N hardcoded
   constants scattered across N plugins.
2. **Every failure returns a typed result, never an unhandled exception.**
   In caliper's plugin architecture that typed result is
   `PluginResult(plugin_name=..., error=str(exc))` — defined in
   `src/caliper/core/plugin.py`. A plugin that raises out of `run()` breaks
   the orchestrator's per-plugin isolation; a plugin that catches and
   returns `PluginResult(error=...)` degrades gracefully and the pipeline
   continues.
3. **A degradation must never look like "clean scan."** An empty findings
   list from a plugin that crashed is indistinguishable from an empty
   findings list from a plugin that ran and found nothing — unless the
   crash path populates `PluginResult.error` (which becomes a visible
   `caliper-plugin-error` SARIF sentinel, see below) rather than silently
   returning `PluginResult(plugin_name=..., findings=[])`.

### The taxonomy that makes the contract precise

Fail-open does **not** mean "swallow everything." Three categories, three
different responses — this taxonomy is the single most important idea in
this skill, and it's the exact thing that eroded (see next section):

| Category | Example | Response |
|---|---|---|
| **Expected degradation** | scanner subprocess times out, DB unreachable, OPA crashes | log, continue, `PluginResult(error=...)` or `NullRepository` fallback, pipeline exits 0 |
| **Config error** | missing/invalid env var, unparseable `CaliperSettings` | log, `sys.exit(0)` with a "skipped — fail-open" message (config errors are still fail-open at the CLI boundary — see `cli/main.py:236-245`) |
| **Bug in our code** | `TypeError`, `AttributeError` from a wiring mistake, an unhandled exception in pipeline orchestration itself | log with `exc_info=True`, **`raise SystemExit(1)`** — this must be loud, because it is not a scanner problem, it is caliper's own bug |

Catching category 3 with the same broad `except Exception: continue` you use
for category 1 is exactly how erosion happens — the type error looks like a
scanner failure and gets silently fail-opened away.

## The exact historical erosion mechanism (one paragraph — full story in `caliper-failure-archaeology`)

A 2026-04-23 review found the fail-open *design* was sound but had eroded
into fail-open-for-everything: an unconditional `sys.exit(0)` at the end of
the CLI's `evaluate` command hid crashes from Jenkins (couldn't tell "ran
clean" from "crashed before scanning anything"); `config.pipeline_timeout`
was loaded into settings and never once compared against elapsed time, so a
hung scanner had no wall-clock backstop; a `str`/`Path` type mismatch routed
a wiring bug through the generic `except Exception` handler so it looked
like "the scanner failed" (category 1) instead of "our code is broken"
(category 3); and on the policy side, a CVSS-severity fallback loop was a
bare `pass` (silently rating real critical CVEs as `info`), and the Python
code building OPA's `package_metadata` omitted two fields two Rego rules
needed — in Rego, a missing field evaluates to `undefined`, which silently
skips the rule body with no error, no warning, no log. Full detail,
commit-by-commit verification, and the "how it was caught" narrative:
`caliper-failure-archaeology` § "The one the maintainer flagged: silent
fail-open erosion". Source docs (read fully before touching this area):
`docs/solutions/runtime-errors/missing-runtime-guards-fail-open-erosion.md`,
`docs/solutions/runtime-errors/silent-safety-rule-bypasses.md`.

## The degraded-plugin sentinel finding pattern (commit `de0d921`, 2026-07-01)

**What a sentinel is.** When a plugin crashes, `core/sarif.py`'s
`_plugin_to_run()` (verified at `src/caliper/core/sarif.py:132-151` on
2026-07-02) synthesizes a fake SARIF result so the crash is *visible* in
tooling that reads SARIF — instead of the plugin's run silently vanishing:

```python
if result.error:
    sarif_results.append({
        "ruleId": "caliper-plugin-error",
        "level": "error",
        "message": {"text": result.error},
    })

if truncated > 0:
    sarif_results.append({
        "ruleId": "caliper-truncated",
        "level": "note",
        "message": {"text": f"{truncated} additional findings truncated. ..."},
    })
```

Two sentinel rule IDs exist: `caliper-plugin-error` (a plugin crashed —
`PluginResult.error` was non-empty) and `caliper-truncated` (a plugin's
findings list was cut off at `max_findings`, a resource-bound, not a bug).
Both carry `level="error"`/`level="note"` so they render visibly in any
SARIF consumer (GitHub code scanning UI, `sarif-summary` CLI, etc.).

**Why blocking on it was the wrong failure mode.** `core/pr_review.py`'s
`sarif_to_review()` used to *recount* SARIF results by `level` to derive the
PR-review verdict independently of the pipeline's own (correctly fail-open)
decision in `core/review_summary.py`. Because the sentinel carries
`level="error"`, that recount treated a **crashed plugin** — an expected
degradation, fail-open by design — as if it were a **real error-level
finding**, flipping the GitHub review event to `REQUEST_CHANGES`. A plugin
timing out (category 1: expected degradation) was blocking merges exactly
like a real critical vulnerability (a real finding) would. That inverts the
whole point of fail-open: the system was supposed to degrade gracefully and
let the human decide, not let an infrastructure hiccup in one plugin veto
the PR.

**The fix.** `SENTINEL_RULE_IDS = frozenset({"caliper-plugin-error",
"caliper-truncated"})` in `core/sarif.py`, and `sarif_to_review()` now skips
any result whose `ruleId` is in that set before it enters the blocking
recount (`src/caliper/core/pr_review.py:95-97`, verified 2026-07-02):

```python
rule_id = result.get("ruleId", tool_name)
if rule_id in SENTINEL_RULE_IDS:
    # Degraded-plugin sentinels (a crashed plugin, a truncated findings
    # list) are not real findings — fail-open means they never count
    # toward the blocking verdict recount (#211).
    continue
```

**The regression test** — `tests/unit/test_pr_review.py`,
`test_plugin_error_sentinel_does_not_block` (added in the same commit):
feeds `sarif_to_review()` a SARIF payload containing only a synthetic
`caliper-plugin-error` result and asserts the review event is `COMMENT`
(not `REQUEST_CHANGES`) and `comments == []`. If you touch `sarif_to_review`
or add a third sentinel rule ID, extend this test — don't just eyeball it.

**Rule of thumb going forward:** if you ever add a new synthetic/sentinel
SARIF `ruleId` (i.e. a result caliper itself generates to describe its own
degraded state, not something a real scanner found), add it to
`SENTINEL_RULE_IDS` in the same commit. A sentinel that isn't registered
there will silently re-introduce this exact bug.

## Known open gaps — read before you assume "timeout wiring" is done everywhere

Commit `45cff43` (2026-07-01, "honor CaliperSettings.scanner_timeout instead
of hardcoded defaults") wired **only three plugins** —
`ComplexityPlugin`, `CpdPlugin`, `SemgrepPlugin` — to accept an optional
`CaliperSettings` and thread `settings.scanner_timeout` into their
subprocess call. Its own commit message says explicitly: *"Wiring settings
through `ANALYZERS.create()`/`get_default_registry()` end-to-end
(registries.py, bootstrap.py, CLI call sites) is out of scope here."*

Verified 2026-07-02 — these plugins still hardcode their timeout instead of
reading `CaliperSettings.scanner_timeout`:

| Plugin | File | Current timeout source |
|---|---|---|
| gitleaks | `src/caliper/plugins/gitleaks.py` | function default `timeout: int = 60` |
| mypy / pyright | `src/caliper/plugins/mypy.py` | function default `timeout: int = 60` |
| osv-scanner | `src/caliper/plugins/osv_scanner.py` | function default `timeout: int = 60` |
| syft | `src/caliper/plugins/syft.py` | hardcoded `timeout=120` |
| trivy | `src/caliper/plugins/trivy.py` | module constant `_TIMEOUT = 60` |
| swiftlint, swiftformat, cdk_nag, cfn_nag, kube_linter, scancode, clamav, ls_lint, typos, blast_radius, supply_chain | respective files | not yet audited individually — assume hardcoded until you check |

This is **not** a new regression — it's a documented, in-progress, partial
remediation. Do not describe it as "fixed" or "done" in commit messages or
PR descriptions. If you're touching one of these plugins anyway, wiring it
to `CaliperSettings.scanner_timeout` following the `complexity.py`/`cpd.py`
pattern is in scope and welcome — but it is a separate, deliberate unit of
work per this project's one-commit-per-fix discipline (`CLAUDE.md` §
Commits), not something to bundle into an unrelated change.

## Audit checklist — run this before merging anything that touches a scanner/plugin/scribe

A copy-pasteable script ships with this skill. Run it from repo root:

```bash
bash .claude/skills/caliper-fail-open-resilience/scripts/audit_fail_open.sh
```

**Actual output observed on this repo, 2026-07-02** (regenerate if you
suspect drift — the script is idempotent and safe to re-run anytime):

```
== 1. Exit-code taxonomy (crash vs. clean/degraded run) ==
  [OK]   cli/main.py has an explicit SystemExit(1) path (unexpected crash != exit 0)

== 2. Pipeline wall-clock timeout is enforced (not just loaded) ==
  [OK]   core/pipeline.py compares elapsed time against config.pipeline_timeout

== 3. No bare 'except:' (swallows SystemExit/KeyboardInterrupt too) ==
  [OK]   no bare 'except:' clauses in src/caliper/

== 4. No silent 'pass' inside an except/fallback block ==
  [OK]   no 'except ...: pass' fallbacks found in src/caliper/

== 5. Degraded-plugin sentinel finding IDs are excluded from the PR-review blocking recount ==
  [OK]   SENTINEL_RULE_IDS defined in core/sarif.py and consumed in core/pr_review.py (commit de0d921 still applied)

== 6. Every scanner subprocess call passes an explicit timeout ==
  [INFO] gitleaks.py: subprocess call has a timeout, but it is a hardcoded/local default, NOT wired to CaliperSettings.scanner_timeout (open gap, see SKILL.md)
  [INFO] swiftformat.py: subprocess call has a timeout, but it is a hardcoded/local default, NOT wired to CaliperSettings.scanner_timeout (open gap, see SKILL.md)
  [INFO] swiftlint.py: subprocess call has a timeout, but it is a hardcoded/local default, NOT wired to CaliperSettings.scanner_timeout (open gap, see SKILL.md)
  [INFO] trivy.py: subprocess call has a timeout, but it is a hardcoded/local default, NOT wired to CaliperSettings.scanner_timeout (open gap, see SKILL.md)

== 7. Plugin exception handlers return a typed PluginResult(error=...), not a bare re-raise ==
  [OK]   _opa.py: except Exception returns PluginResult(error=...)
  [OK]   cdk_nag.py: except Exception returns PluginResult(error=...)
  [OK]   cfn_nag.py: except Exception returns PluginResult(error=...)
  [OK]   complexity.py: except Exception returns PluginResult(error=...)
  [OK]   cpd.py: except Exception returns PluginResult(error=...)
  [OK]   kube_linter.py: except Exception returns PluginResult(error=...)
  [OK]   semgrep.py: except Exception returns PluginResult(error=...)

RESULT: all REQUIRED checks passed. INFO lines above are known/open gaps, not regressions — see SKILL.md 'Known open gaps'.
```

The script exits non-zero only on a **REQUIRED** ([FAIL]) check — checks
1-5 and 7 are things that regressed once already and must never regress
again. Check 6's `[INFO]` lines are the known-open-gaps table above; they
are intentionally advisory, not blocking, because the codebase has not
finished migrating every plugin yet.

**Script limitation (read before trusting a clean run blindly):** check 6
only catches plugins that call `ToolInvocation(` directly in their own file.
Plugins that delegate to a shared `_runners/*.py` helper (e.g.
`osv_scanner.py`, `mypy.py`, `syft.py` route through helper functions) won't
show up in check 6's output even though they're in the "Known open gaps"
table above — the script under-reports, it never over-reports. Don't take
"no INFO line for plugin X" as proof X is fully wired; check the table.

### Manual checks the script can't automate

- **New `except` block around any scanner/subprocess/HTTP/DB/LLM call?**
  Confirm by eye which category (expected degradation / config error / bug)
  it's meant to catch, and that the response matches the taxonomy table
  above — not just "catch broadly and move on."
- **New synthetic/sentinel SARIF `ruleId`?** Add it to `SENTINEL_RULE_IDS`
  in `core/sarif.py` in the same commit (see sentinel section above).
- **New field caliper's Python code feeds into OPA input?** Cross-check it
  against `policies/INPUT_SCHEMA.md` — a field the Rego side expects but
  the Python side omits is `undefined` in Rego, which silently never fires
  the rule. This is the F-012 shape from the erosion history. See
  `caliper-opa-policy-playbook` for the OPA-side half of this check.
- **New severity-mapping or scoring fallback loop?** Grep it by hand for a
  branch that can fall through without assigning anything (the F-010 CVSS
  shape) — the script's check 4 only catches a literal `pass`, not every
  possible silent fallthrough (e.g. an `if/elif` chain with no `else`).

## Provenance & maintenance

Every fact in this skill was verified against the repo on **2026-07-02**.
Re-run these when the skill starts to feel stale:

```bash
# Re-run the full audit and diff against the "actual output observed" block above
bash .claude/skills/caliper-fail-open-resilience/scripts/audit_fail_open.sh

# Re-verify commit de0d921 (sentinel pattern) is still the shape described here
git show de0d921 --stat

# Re-verify commit 45cff43 (partial scanner_timeout wiring) is still the shape described here
git show 45cff43 --stat

# Re-check which plugins are (not) wired to CaliperSettings — update the open-gaps table if this list changes
grep -rLn "CaliperSettings" src/caliper/plugins/*.py | grep -v __init__.py

# Re-check the CLAUDE.md timeout table this skill's contract section quotes
grep -n "scanner_timeout\|combined_scanner_timeout\|opa_timeout\|llm_timeout\|scribe_timeout\|pipeline_timeout" src/caliper/core/config.py

# Re-check the regression test for the sentinel pattern still exists and still asserts COMMENT not REQUEST_CHANGES
grep -n "test_plugin_error_sentinel_does_not_block" -A12 tests/unit/test_pr_review.py
```

If any of these drift from what's documented above, update this file in the
same change — do not let the audit script and the prose disagree.
