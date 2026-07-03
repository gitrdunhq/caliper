---
name: caliper-diagnostics-and-tooling
description: >-
  How to MEASURE caliper's own health instead of eyeballing it: make
  quality-check / make dogfood / make preflight (what each actually runs,
  in what order, and why preflight is a superset), the DOGFOOD-FINDINGS.md
  workflow where every self-scan finding gets a row in a table and a
  deterministic regression test, `opa test policies/` for Rego policy unit
  tests, docs/CAPABILITIES.md as the living feature-count inventory (Quick
  Numbers table, LAST VERIFIED date, and how to recompute every count by
  hand or with the shipped verify script), and lizard as the sole JS/TS/
  cross-language complexity source of record (escomplex was deleted as dead
  code in commit 3382ad8 — do not resurrect it or reference it as current).
  Load this before running any quality gate, before editing
  docs/CAPABILITIES.md, before touching
  `src/caliper/plugins/_runners/complexity_runner.py`, or when asked "how do
  I check if the numbers in CAPABILITIES.md are still right", "is `opa test`
  as part of my `make preflight`/CI gate failing", "what does make preflight
  do", or "how do I log a dogfood finding". This skill only covers invoking
  the `opa test` runner as one step of the quality gate — for adding a new
  OPA rule test or debugging why a specific Rego rule/test fails, see
  caliper-opa-policy-playbook instead. Do NOT load this for how the dogfood
  *pipeline itself* self-heals from a bad self-scan (see
  caliper-failure-archaeology), for the two-agent
  RED/GREEN TDD split or commit-prefix rules (see caliper-change-control), for
  multi-agent adversarial code review orchestration with cheap-reviewer /
  challenger / adjudicator roles (see adversarial-review — this skill's
  dogfood table is a single deterministic self-scan, not that multi-agent
  process), for how to actually write/run pytest suites (see
  caliper-testing-and-tdd), or for OPA rule *semantics* — what each deny/warn
  rule means and when it fires (see caliper-opa-policy-playbook — this skill
  only covers the `opa test` unit-test invocation).
---

# Caliper: Diagnostics and Tooling

Measure, don't eyeball. This skill is the runbook for caliper's self-check
surface: the three `make` quality gates, the dogfood self-scan and its
regression-test contract, OPA's own test suite, the capability-count
inventory doc, and the one settled fact about JS/TS complexity tooling
(lizard, not escomplex). Every command below was run against this repo on
**2026-07-02** from repo root
(`/Volumes/Extra/repos/gitrdunhq/eedom`) — outputs shown are the actual
observed output, not guesses.

**Jargon, defined once:**
- **Dogfood** — running caliper's own `review` pipeline against caliper's own
  source tree, so the tool catches its own regressions before a human does.
- **Quick Numbers table** — the summary count table near the top of
  `docs/CAPABILITIES.md` (scanner plugins, detectors, semgrep rules, OPA
  rules, CLI commands, etc.) that must stay in sync with the actual code.
- **MI** — Maintainability Index, a 0-100 composite complexity score.

## When to use this skill vs. a sibling

| You want to... | Use |
|---|---|
| Run a quality gate before committing/handing off | this skill |
| Log a self-scan finding and give it a regression test | this skill |
| Run OPA's Rego unit tests | this skill |
| Check whether docs/CAPABILITIES.md counts are stale | this skill |
| Understand JS/TS complexity scoring internals | this skill |
| Understand *what a specific OPA rule means* | `caliper-opa-policy-playbook` |
| Understand how the dogfood pipeline fails open / recovers | `caliper-failure-archaeology` |
| Run a multi-agent Haiku→Sonnet→Opus adversarial review | `adversarial-review` |
| Write/organize pytest suites, hypothesis property tests | `caliper-testing-and-tdd` |
| Pick a commit prefix / structure a RED-GREEN TDD split | `caliper-change-control` |

## 1. The three quality gates

All three are `.PHONY` targets in the repo-root `Makefile`. They are
strictly nested: `preflight` runs `quality-check`, then `test`, then
`dogfood`, in that order.

| Target | Runs | Fails fast on |
|---|---|---|
| `make quality-check` | `format` (black) → `lint` (ruff) | any formatting diff or lint violation |
| `make test` | full pytest suite **inside a container** (see `caliper-build-and-env`) | any test failure |
| `make dogfood` | `bash scripts/dogfood.sh` | any SARIF `error`-level (critical/high) finding from self-scan |
| `make preflight` | `quality-check` → `test` → `dogfood` | first failing stage (make stops there) |

Verbatim Makefile source for the gate chain (confirmed 2026-07-02):

```makefile
quality-check: format lint
	@echo "All quality checks passed"

format:
	@uv run black src/ tests/

lint:
	@uv run ruff check src/ tests/

dogfood:
	bash scripts/dogfood.sh

preflight: quality-check test dogfood
	@echo "Preflight complete."
```

Run from repo root:

```bash
make quality-check
make test          # container-only -- see caliper-build-and-env for the podman/docker setup
make dogfood
make preflight      # runs all three, in order
```

Observed `make quality-check` sub-steps run directly (2026-07-02, host):

```bash
uv run ruff check src/ tests/
# All checks passed!

uv run black --check src/ tests/
# All done! ✨ 🍰 ✨
# 535 files would be left unchanged.
```

**Do not run `make test` or the pytest binary directly on host.** Per
`CLAUDE.md`, tests MUST run in a container; `make test` handles this
automatically and `CALIPER_ALLOW_HOST_TESTS=1` is a documented escape hatch
you should never reach for. See `caliper-build-and-env` for the container
mechanics `make test` wraps.

## 2. `scripts/dogfood.sh` — what it actually does

`make dogfood` is a one-line wrapper around `bash scripts/dogfood.sh`. Read
the script before assuming what "dogfood" means — it is a single
deterministic self-scan, not the multi-agent adversarial process (that's
`adversarial-review`). Confirmed behavior (2026-07-02, `scripts/dogfood.sh`):

1. Runs `caliper review --repo-path <repo> --all` twice: once to
   `.caliper/reports/dogfood-report-<timestamp>.md` (human-readable), once
   with `--format sarif` to `.caliper/reports/dogfood-<timestamp>.sarif`
   (machine-readable).
2. Counts SARIF results where `level == "error"` (critical + high severity).
3. Exits `1` ("BLOCKED") if that count is `> 0`; exits `0` ("CLEAR")
   otherwise.
4. Symlinks `dogfood-report-latest.md` / `dogfood-latest.sarif` to the new
   timestamped files.

```bash
bash scripts/dogfood.sh
# === Caliper Dogfood Run: <timestamp> ===
# Findings: <N> error-level (critical/high)
# Report: .caliper/reports/dogfood-report-<timestamp>.md
# SARIF:  .caliper/reports/dogfood-<timestamp>.sarif
# CLEAR: No blocking findings.        <- or BLOCKED + exit 1
```

Fail-open by design: each `caliper review` invocation is followed by
`|| true` — a crash in the review pipeline itself does not silently pass
the gate, but it also doesn't take down the whole script before the SARIF
count logic runs. If `dogfood-*.sarif` never gets written, the `if [ -f ... ]`
guard skips the count and the script falls through to "CLEAR" — treat a
missing SARIF file as a red flag to investigate manually, not as a pass.

## 3. DOGFOOD-FINDINGS.md — the finding → regression-test contract

`DOGFOOD-FINDINGS.md` at repo root is the log of everything caliper's
self-scan has ever found about itself. **The rule: every finding gets a row,
and every row that represents a real bug gets a named regression test.**
This is a manual log — `scripts/dogfood.sh` does not write to it. Add a row
by hand after reviewing a dogfood run's output.

Actual table format in use (verbatim columns, confirmed 2026-07-02):

```markdown
## Run N: <milestone label> (<date>)

Verdict: <PASS|PASS WITH WARNINGS|FAIL> | Security: <score>/100 | Quality: <score>/100

| # | Finding | Severity | Detail | Regression Test | Status |
|---|---------|----------|--------|-----------------|--------|
| D1 | OPA parse error on semgrep YAML | bug | OPA eval `-d ./policies` includes non-Rego files | `test_opa_ignores_non_rego_files` | **FIXED** (config.py → policy.rego) |
| D2 | Semgrep 2279 findings on self-scan | noise | Runs against entire repo | `test_semgrep_respects_file_scoping` | OPEN |
```

Column semantics:

| Column | Meaning |
|---|---|
| `#` | Stable id, `D1`, `D2`, ... — never renumber, only append |
| Finding | One-line description of what the self-scan flagged |
| Severity | Free text so far in practice: `bug`, `noise`, `info`, `env`, `good` |
| Detail | Why it happened / root cause, one line |
| Regression Test | The pytest test name that pins this behavior — `N/A` only for `env`-only findings (host tooling gaps that can't be a repo-level regression test) |
| Status | `OPEN`, `**FIXED**` (bold, with a one-line pointer to the fix), `KNOWN` (accepted, won't fix), or `OK` (confirms correct behavior, not a bug) |

Workflow when you get a new dogfood finding:

1. Run `make dogfood` (or `bash scripts/dogfood.sh`), read the generated
   `.caliper/reports/dogfood-report-latest.md`.
2. For each new bug-shaped finding: write a **failing** regression test
   first (RED — see `caliper-change-control` for the RED/GREEN split), name
   it descriptively (`test_<what_would_have_caught_this>`), confirm it fails
   against the current bug.
3. Fix the bug (GREEN).
4. Append a row to the current run's table in `DOGFOOD-FINDINGS.md` (or
   start a new `## Run N: ...` section for a fresh scan), status `**FIXED**`,
   pointing at the actual fix location.
5. Findings that are `env`-only (a host-only tool being absent, e.g.
   `cspell NOT_INSTALLED` when running outside the container) get
   `Regression Test: N/A` — there's nothing to regression-test, the
   container image is the fix.

## 4. `opa test` — Rego policy unit tests

Separate from the dogfood self-scan. This runs OPA's own unit test suite
against `policies/policy.rego` and its sibling `*_test.rego` files — it does
not invoke caliper at all.

```bash
opa test policies/ --ignore '*.yaml' --ignore '*.yml'
# PASS: 51/51
```

(51/51 confirmed 2026-07-02, `opa` v1.16.2.) The `--ignore` flags are
required — `policies/` also holds `semgrep/*.yaml` and `swiftlint/*.yaml`
config, which are not Rego and will otherwise be misparsed. Test files
present at time of writing: `policies/policy_test.rego` (main rule suite),
`policies/policy_supply_chain_test.rego` (supply-chain diff rules). For rule
*semantics* (what each `deny`/`warn` block checks and why), see
`caliper-opa-policy-playbook` — this skill only covers invoking the test
runner.

## 5. docs/CAPABILITIES.md — the living feature inventory

`docs/CAPABILITIES.md` is the canonical, LLM-ingestion-optimized feature
count for the whole project. `CLAUDE.md`'s "Capability Matrix" section is
the rule that makes updating it mandatory:

> Update it whenever you add, remove, or modify: a plugin, semgrep rule,
> code graph check, OPA policy rule, CLI command, output format, or
> integration. Keep counts accurate. Update the LAST VERIFIED date.

The file carries a machine-checkable convention at its top: an HTML comment
with `LAST VERIFIED: <date>` and a `VERIFICATION:` line stating exactly how
three of the headline counts were derived. Confirmed content 2026-07-02:

```
LAST VERIFIED: 2026-07-02
VERIFICATION: 19 auto-discovered scanner plugins (@ANALYZERS.register) + OPA policy
plugin (20 ScannerPlugin subclasses total); 22 detectors in src/caliper/detectors/;
67 semgrep rule ids in policies/semgrep/.
```

Below that is a "Quick Numbers" table (scanner plugins, detectors, semgrep
rules, code graph checks, OPA rules, NL query templates, Copilot agent
tools, finding scribes, CLI commands, parting taxonomy buckets, output
formats, SBOM ecosystems, CPD languages, complexity languages, semgrep file
extensions, gitleaks patterns, spell-check dictionaries) — this is the table
you edit whenever a count changes.

### Verifying the counts yourself

Don't trust the doc — recompute. This skill ships a script that recomputes
the four grep-able counts and prints them next to what the doc currently
claims:

```bash
bash .claude/skills/caliper-diagnostics-and-tooling/scripts/verify-capabilities-counts.sh
```

Observed output, 2026-07-02 (all four matched the doc at the time):

```
=== Recomputed counts ===
Scanner plugins (@ANALYZERS.register in src/caliper/plugins/*.py): 19
Deterministic detectors (unique CAL-0NN ids under src/caliper/detectors/): 22
Custom semgrep rules ('- id:' lines in policies/semgrep/*.yaml): 67
Semgrep rule files: 11
OPA Rego policy rules (policies/policy.rego): 16 (7 deny, 9 warn)
CLI commands (caliper --help): 16
```

**Known live discrepancy found while writing this skill (2026-07-02):** the
Quick Numbers table's `CLI commands` row currently says **11**, but the
script above (and a manual `uv run caliper --help` count) both show **16**
top-level commands registered (`audit, baseline, check-health, eval,
evaluate, gauge, ground, healthcheck, inspect, part, plugins, query,
reinstall, review, schema, supply-chain-diff`). This is real drift, not a
counting artifact — the doc has not been updated as commands were added.
Fix it the same way any other drift gets fixed: edit the `CLI commands` row
in `docs/CAPABILITIES.md`, bump `LAST VERIFIED`, re-run the script above to
confirm, and mention it in your commit as a `chore:` (per `CLAUDE.md`
commit-prefix rules — a doc-count fix is not a `feat:`).

The script only recomputes what's cleanly grep-able (plugins, detectors,
semgrep rules, OPA rules, CLI commands). For the rest of the Quick Numbers
table (code graph checks, NL query templates, output formats, SBOM
ecosystems, etc.) there's no single source-of-truth grep pattern yet —
verify those by reading the relevant registry/enum directly before editing
their row.

## 6. Complexity tooling: lizard is the source of record (JS/TS included)

**escomplex is dead. Do not reference it, install it, or resurrect its call
site.** It was removed in commit `3382ad8` (2026-07-01,
`chore(complexity): remove dead escomplex code path, lizard is the JS/TS
complexity source of record (#441)`). Confirmed via `git show 3382ad8`:

> Deletes `_apply_escomplex_mi` and the already-commented-out call site: the
> entire JS/TS maintainability-index tooling ecosystem (escomplex family,
> ts-complex, complexity-report/plato) is dead or unlicensed as of 2026, and
> the one actively maintained tool only computes cyclomatic complexity, not
> an MI. Lizard remains the cross-language complexity source of record, same
> as every other language caliper scans.

The change deleted 200 lines net (`src/caliper/plugins/_runners/
complexity_runner.py`: -74/+18; `tests/unit/test_complexity_runner.py`:
-144/+18) and left the file's own docstring stating the current contract
(confirmed still true 2026-07-02, `complexity_runner.py` lines 1-8):

```python
"""Lizard + Radon complexity subprocess runner.
# tested-by: tests/unit/test_complexity_runner.py

Lizard (CCN/NLOC/Halstead) is the complexity source of record for every
language caliper scans, JS/TS included: as of 2026 no actively maintained,
permissively-licensed CLI computes a JS/TS-specific maintainability index.
Revisit periodically (#441).
"""
```

What actually runs, per language:

| Language(s) | Tool | Metric |
|---|---|---|
| `.py`, `.ts`, `.js`, `.tsx`, `.jsx`, `.go`, `.java`, `.rs`, `.c`, `.cpp`, `.swift` (10 langs) | `lizard --csv <files>` | CCN, NLOC, token count, param count, function length |
| All of the above, MI grade | `_halstead_mi()` (in-process, `complexity_runner.py`) | Halstead-approximated MI, clamped 0-100, graded A (≥20) / B (≥10) / C (<10) |
| `.py` only, MI grade override | `radon mi -s <files>` | Replaces the Halstead approximation with radon's real MI score, keyed by matching file path |

So: every supported language gets a lizard-based cyclomatic score and a
Halstead-*approximated* MI; Python additionally gets its Halstead-approx MI
overwritten by radon's real MI. JS/TS never gets a "real" MI (per the
commit's rationale — no maintained tool computes one) — it gets the same
Halstead approximation as every other non-Python language. If you see a
grade-C MI score on a subprocess-heavy plugin file, that's expected — noted
as `D4` in `DOGFOOD-FINDINGS.md` Run 1 (`MI score 38/100 with 163 grade-C |
info | Expected for subprocess-heavy plugins | KNOWN`).

If you are asked to add JS/TS-specific MI tooling: don't, until you've
checked whether the "no actively maintained, permissively-licensed CLI"
premise from commit `3382ad8` has changed. If it has, that's a `feat:`
(new user-facing capability) with a fresh regression test, not a revert.

## When NOT to use this skill

| Situation | Use instead |
|---|---|
| You need to understand *why* an OPA rule denies/warns, not how to run its tests | `caliper-opa-policy-playbook` |
| You're orchestrating a multi-agent Haiku→Sonnet→Opus review, not a single self-scan | `adversarial-review` |
| You're debugging *why* the dogfood pipeline itself degraded (fail-open path) | `caliper-failure-archaeology` |
| You're deciding a commit prefix or splitting RED/GREEN TDD agents | `caliper-change-control` |
| You're building/rebuilding the container `make test` runs inside | `caliper-build-and-env` |
| You're writing new pytest suites or hypothesis property tests | `caliper-testing-and-tdd` |

## Provenance & maintenance

Every count and command in this file was verified 2026-07-02 from repo root
(`/Volumes/Extra/repos/gitrdunhq/eedom`). Re-verify with:

```bash
# quality gates still shaped the same way
grep -A2 '^preflight:' Makefile

# opa test suite pass count
opa test policies/ --ignore '*.yaml' --ignore '*.yml'

# CAPABILITIES.md counts (plugins, detectors, semgrep rules, OPA rules, CLI commands)
bash .claude/skills/caliper-diagnostics-and-tooling/scripts/verify-capabilities-counts.sh

# escomplex still dead (should return nothing under src/)
grep -ri escomplex -r src/ || echo "confirmed: no escomplex references in src/"

# dogfood script behavior unchanged
cat scripts/dogfood.sh
```

If any of these drift, update this file's examples in the same commit as
whatever caused the drift — this doc is subject to the same "keep it
accurate" rule as `docs/CAPABILITIES.md` itself.
