---
name: caliper-debugging-playbook
description: Load when a caliper scan or `make dogfood` run produces a surprising, wrong, or suspicious result — OPA parse errors, a wall of semgrep noise, a real code finding marked "blocked", a scanner that silently timed out, a scanner that reports 0 findings, or any "did my scan actually work?" question. Gives a symptom -> triage table mapping each observed behavior to its known root cause (grounded in DOGFOOD-FINDINGS.md D1-D9) plus a discriminating experiment (a command to run) that tells the real cause apart from lookalikes, before you start editing code. Not for the general fail-open/timeout design philosophy (use caliper-fail-open-resilience for that deep-dive) and not for writing new plugins (use caliper-plugin-authoring-playbook or caliper-plugin-architecture).
---

# Caliper Debugging Playbook

A symptom-first triage guide for caliper's actual, observed failure modes — not
hypothetical ones. Every row below traces to a real dogfooding run
(`DOGFOOD-FINDINGS.md`) or a real subprocess/config code path, verified against
the repo, not invented.

All facts were re-verified against the repo on **2026-07-02** at commit
`c78154b` (HEAD of branch `arch-review-fixes-and-enhancements`). Counts and
line numbers drift — see "Provenance & maintenance" at the bottom for the
exact commands to re-check them yourself.

## When NOT to use this skill

| You want to... | Use instead |
|---|---|
| Understand *why* caliper is architected fail-open, the timeout budget hierarchy, and the general silent-degradation philosophy | `caliper-fail-open-resilience` |
| Write a brand-new plugin or fix a bug inside one specific plugin's own logic | `caliper-plugin-authoring-playbook` / `caliper-plugin-architecture` |
| Understand OPA/Rego policy rule semantics in depth | `caliper-opa-policy-playbook` |
| Run the test suite, do RED/GREEN TDD | `caliper-testing-and-tdd` |
| Orchestrate a multi-agent adversarial code review pass | `adversarial-review` |
| Understand the ports-and-adapters tier boundaries generally | `caliper-architecture-contract` |
| Trace *historical* fixed bugs and their regression tests as an archive | `caliper-failure-archaeology` |

This skill is for **triage in the moment**: "my scan just did something weird,
which of the known failure modes is this, and what's the one command that
proves it." If the symptom below doesn't match anything, it's a *new* bug —
file it, don't force-fit it into this table.

## How to use this table

1. Find the row matching what you observed.
2. Run the **discriminating experiment** — it distinguishes the real cause
   from the "lookalikes" column (things that look the same on the surface but
   have a different fix).
3. Only then start editing code. Don't guess-fix based on the symptom alone —
   two of these rows (D2 vs D3, D7 vs a real hang) look identical from the CLI
   output and need the experiment to tell apart.

| # | Symptom | Story | Discriminating experiment | Lookalike (don't confuse with) |
|---|---------|-------|---------------------------|--------------------------------|
| T1 | `caliper review` errors out during OPA eval with a Rego parse error mentioning a `.yaml`/`.yml` file | **D1 (FIXED).** OPA's `-d ./policies` used to load the whole `policies/` dir, including non-Rego semgrep/swiftlint config YAML, and choked trying to parse it as Rego. Fixed by pointing OPA at `config.py`'s `opa_policy_path` (`./policies/policy.rego`, a single file) instead of the directory. | `opa test policies/ --ignore '*.yaml' --ignore '*.yml'` — verified 2026-07-02, output `PASS: 51/51`. If this fails on your checkout, you've regressed D1: check `opa_policy_path` in `src/caliper/core/config.py` still points at the single `policy.rego` file, not a directory. | A genuine Rego syntax error in `policy.rego` itself — that fails `opa test` even after scoping to one file. Read the actual error line; D1 only ever complained about YAML syntax, not Rego syntax. |
| T2 | `caliper review --all` returns thousands of semgrep findings, review feels like noise, hard to find the signal | **D2 (OPEN, noise not correctness).** Semgrep runs against the whole repo (`sg.run(str(repo_path), ...)` in `src/caliper/plugins/semgrep.py`), so every file in the tree gets scanned, not just the diff. On caliper's own repo this produced 2279 findings (run 1), then 2353 (run 2, +74 from new files). This is not a bug — verdict was still `PASS WITH WARNINGS`, security 100/100 — it is a signal-to-noise problem. | `caliper review --repo-path . --scanners semgrep --output .temp/semgrep-only.json` then `jq '.findings | length' .temp/semgrep-only.json` (adjust the jq path to your output schema). Compare the count to the number of files actually changed in your diff (`git diff --name-only <base> HEAD \| wc -l`) — if findings ≫ changed files, you're looking at whole-repo scope, confirmed D2. | Semgrep genuinely finding thousands of *new* real bugs — check the top severities; D2's findings are almost all low/info noise on unrelated files, not a spike in critical/high. |
| T3 | A finding that is clearly a **code** issue (semgrep hit, detector hit, secret leak — no upstream package to bump) shows up in the "blocked" bucket of the actionability summary instead of "actionable" | **D3 (OPEN).** `_is_actionable()` in `src/caliper/core/actionability.py` classifies purely on `fixed_version`: `bool(fv and fv.strip())`. Vulnerability findings have a `fixed_version` when a newer package release exists. Code findings (semgrep, detectors, secrets) never carry a `fixed_version` field at all — so every single one is misclassified "blocked", implying "nothing you can do, wait on upstream" when the real fix is "edit this line yourself." | Read `src/caliper/core/actionability.py:24-26` — `_is_actionable` has no branch for `finding.get("category")`; it is a single `fixed_version` check for every category. Any finding dict lacking `fixed_version` (code findings included) falls to `blocked`, confirmed. | A genuinely blocked *vulnerability* finding (no fix released upstream yet) — that one is legitimately blocked; the D3 bug is specifically about code-category findings being lumped into the same bucket, not about vuln findings being wrong. |
| T4 | `scancode` scanner result comes back as `timeout` status instead of findings, on a large/full-repo scan | **D7 (KNOWN, fail-open working correctly).** scancode's default timeout is 60s (`ScancodeScanner.__init__(..., timeout: int = 60)` in `src/caliper/data/scanners/scancode.py`); on caliper's own repo (dogfood run 2) it hit that wall and returned `ScanResult.timeout(...)` — this is the *intended* fail-open path, not a crash. Run 2's total finding count actually *dropped* 693 vs. run 1 specifically because scancode's timeout replaced 874 noisy license findings with a clean skip. | Check the scanner's `ScanResult.status` field in the JSON output — `status == "timeout"` with `duration_seconds ≈ 60` is D7 working as designed. `run_subprocess_with_timeout()` (`src/caliper/data/scanners/base.py:28-53`) never raises on timeout; it returns `(None, "", "timeout exceeded")` and the caller logs `scanner.timeout` and returns a typed timeout result — verified by reading the function. | A scanner that hangs the *whole pipeline* past `pipeline_timeout` (300s) — that's a `pipeline_timeout_reached` warning in `core/pipeline.py:211-217`, a different guard, one layer up. If your whole `caliper review` invocation never returns at all, you're past T4 into a pipeline-level bug — check whether `ThreadPoolExecutor`/`as_completed(..., timeout=remaining)` in `core/orchestrator.py` is actually being hit; a per-scanner timeout that isn't enforced would look like this. |
| T5 | `gitleaks` or `trivy` report **zero** findings and you expected some | **D8/D9 (GOOD, not a bug).** On caliper's own repo, gitleaks legitimately found 0 secrets (allowlist config working as intended) and trivy legitimately found 0 vulnerable dependencies. A clean scanner run is not evidence of a broken scanner. | Check the scanner's `ScanResult.status` — `success` with `findings: []` is a real clean run. Compare against `status == "failed"` or `status == "timeout"`, which would indicate the scanner didn't actually execute (see T6). If you need to confirm gitleaks/trivy binaries are even runnable, `caliper review --scanners gitleaks --output .temp/gitleaks.json` and inspect the raw `ScanResult.message`. | A scanner that's silently `NOT_INSTALLED` on your host (see D5: cspell) or skipped (D6: osv-scanner needs an env token) — those are environment gaps, not "the scanner ran clean." Read the `status` field; `not_installed`/`skipped` ≠ `success`. |
| T6 | Two scanners report the *same* underlying issue at *different* severities, and only one severity shows up in the final report | **Expected dedup behavior**, not a bug — `normalize_findings()` in `src/caliper/core/normalizer.py`. Non-license findings with an `advisory_id` are deduped on `(advisory_id, category, package_name, version)`; when two findings collide, **highest severity wins** (`_SEVERITY_RANK`: critical=5 > high=4 > medium=3 > low=2 > info=1). Findings *without* an `advisory_id` (secret scans, code-smell, detector hits) are deduped on a wider key that also includes `source_tool` and `description`, specifically so unrelated code findings from different tools don't collapse into one entry (see the `#234` comment in the source). | Read `src/caliper/core/normalizer.py:38-61` directly — the dedup key and the `_SEVERITY_RANK.get(f.severity, 0) > _SEVERITY_RANK.get(existing.severity, 0)` comparison is the entire algorithm, no LLM, no heuristics. If your two findings share every field in the key, only the higher-severity one survives by design. | A real duplicate-suppression bug where two *genuinely different* findings collapse into one because their keys accidentally match. Print both raw finding dicts and diff every field in the relevant key tuple — if `source_tool`/`description` truly differ but they still collapsed, that's a real bug (report it), not T6. |
| T7 | `caliper review` exits 0 (green) but you're pretty sure something crashed | **This is the design boundary, not a specific numbered finding.** Fail-open is deliberately scoped to *expected degradations* (scanner timeout, DB down, OPA down) — those log a warning and continue, exit 0. An *unexpected* crash (uncaught exception in caliper's own code) is a different code path and should exit non-zero. If you're seeing exit 0 after what looks like a genuine crash, check whether the exception path in `cli/main.py` is catching too broadly. | `grep -n "sys.exit" src/caliper/cli/main.py` and read the surrounding `try/except` — confirm the `except Exception` branch that precedes each `sys.exit(0)` is only reached for scanner/DB/OPA degradation, not a bare pipeline crash. Compare against `sys.exit(1)` call sites in the same file — those should be the crash paths. | A scanner legitimately failing open (T4/T5) — that's supposed to be exit 0. The distinguishing question is "did *caliper's own code* throw, or did a *subprocess* time out/fail?" Only the former should ever produce a non-zero-worthy situation with an exit-0 result. |

## Fail-open contract quick reference (verified against CLAUDE.md + code, 2026-07-02)

Full design rationale lives in `caliper-fail-open-resilience` — this is just
the numbers you need mid-triage:

| Budget | Value | Enforced where |
|---|---|---|
| Per-scanner timeout | 60s | `run_subprocess_with_timeout(cmd, timeout=...)`, e.g. `ScancodeScanner(timeout=60)` in `src/caliper/data/scanners/scancode.py` |
| Combined scanner phase | 180s | `ThreadPoolExecutor` + `as_completed(..., timeout=remaining)` in `src/caliper/core/orchestrator.py` |
| OPA eval | 10s | `src/caliper/core/config.py` |
| LLM call | 30s | `src/caliper/core/config.py` (Foreman agent / describer paths) |
| Scribe pass | 30s | `SCRIBES` registry, `core/port_registries.py` |
| Whole pipeline | 300s | `config.pipeline_timeout`, enforced per-request in `core/pipeline.py:208-217` (`pipeline_timeout_reached` warning, loop breaks — packages already processed keep their decisions) |

`run_subprocess_with_timeout()` (`src/caliper/data/scanners/base.py:28-53`)
never raises: `subprocess.TimeoutExpired` → `(None, "", "timeout exceeded")`,
`OSError` → `(None, "", str(exc))`. Every scanner caller turns that into a
typed `ScanResult` (`.timeout(...)` / `.failed(...)`), never an unhandled
exception. That typed-result-not-exception pattern is *the* mechanism fail-open
runs on — if you're debugging a scanner that behaves unexpectedly, start by
checking whether it's actually going through this helper or rolling its own
subprocess call.

## Historical fixes (do not re-diagnose as live bugs)

Two `docs/solutions/` writeups describe bugs that **have since been fixed** in
this codebase — re-verified 2026-07-02:

- `docs/solutions/runtime-errors/missing-runtime-guards-fail-open-erosion.md`
  (F-006 unconditional `sys.exit(0)`, F-007 unenforced `pipeline_timeout`,
  F-014 str/Path mismatch in `syft.py`). Current state: `sys.exit(1)` paths
  exist in `cli/main.py` alongside the `sys.exit(0)` paths, and
  `pipeline_timeout` is actively enforced in `core/pipeline.py:211`
  (`if elapsed >= config.pipeline_timeout: ... break`). If you're chasing one
  of these three symptoms and it looks unfixed, that's a *regression* — file
  it, don't assume the doc is describing current behavior.
- `docs/solutions/performance-issues/architecture-violations-coupling-and-sequential-scanners.md`
  (F-015 core→data private import, F-024 pipeline logic in `cli/main.py`,
  F-011 sequential scanners). Current state:
  `grep -rn "_make_failed_result\|from caliper.data" src/caliper/core/orchestrator.py`
  returns nothing (no violating import), and `core/orchestrator.py` runs
  scanners through a `ThreadPoolExecutor` (parallel), not a `for` loop.

These are kept as historical case studies — read them for the *pattern*
("fail-open covers expected degradation paths but not meta-failures like a
bug in caliper's own code"), not as a live bug list. `caliper-failure-archaeology`
is the sibling skill for browsing this class of resolved-finding archive in
depth.

## Copy-paste triage commands (run from repo root)

```bash
# Confirm OPA policy still parses clean (regression check for D1)
opa test policies/ --ignore '*.yaml' --ignore '*.yml'

# Run one scanner in isolation to inspect its raw ScanResult (T4/T5/T6 triage)
caliper review --repo-path . --scanners gitleaks --output .temp/gitleaks-only.json

# Run semgrep alone and count findings to quantify D2 noise (T2 triage)
caliper review --repo-path . --scanners semgrep --output .temp/semgrep-only.json

# Full self-scan, matching how dogfooding is actually run
make dogfood
```

`.temp/` is this repo's gitignored scratch dir for exactly this kind of
throwaway triage output (see the global "no `/tmp`" convention) — write
one-off scan JSON there, not to `/tmp`.

## Provenance & maintenance

Re-run these to catch drift before trusting a specific number in this file:

```bash
# Re-verify D1 is still fixed
opa test policies/ --ignore '*.yaml' --ignore '*.yml'

# Re-confirm no core -> data private import regression (F-015)
grep -rn "_make_failed_result\|from caliper.data" src/caliper/core/orchestrator.py

# Re-confirm pipeline_timeout is still enforced (F-007)
grep -n "pipeline_timeout" src/caliper/core/pipeline.py

# Re-confirm scanners still run in parallel, not sequential (F-011)
grep -n "ThreadPoolExecutor\|as_completed" src/caliper/core/orchestrator.py

# Re-confirm the D3 actionability bug is still open (fixed_version-only check)
sed -n '24,26p' src/caliper/core/actionability.py

# Re-confirm normalizer.py dedup key logic hasn't changed (T6)
sed -n '38,61p' src/caliper/core/normalizer.py

# Re-confirm scancode's default timeout (T4)
grep -n "timeout: int = 60" src/caliper/data/scanners/scancode.py

# Current HEAD this skill was verified against
git log -1 --format='%H %s'
```

Last verified: 2026-07-02, commit `c78154b`, branch
`arch-review-fixes-and-enhancements`. `opa test policies/` output at
verification time: `PASS: 51/51`.
