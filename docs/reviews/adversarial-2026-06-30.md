# Adversarial Review — `main..feat/part-web-frontend`

**Generated:** 2026-06-30
**Target:** `main..feat/part-web-frontend` (full web frontend for `caliper part`)
**Focus:** correctness, design, security
**Models:** reviewer=haiku, challenger=sonnet, verify=opus

## Summary

| Stage | Count |
|---|---|
| Raw findings (Stage 1, 5 partitions) | 3 |
| Challenger-confirmed (Stage 2, sonnet) | 1 |
| False positive (Stage 2) | 2 |
| Uncertain | 0 |
| **Opus-adjudicated (Stage 2.5)** | **1 confirmed (severity downgraded high → medium)** |

**By severity (final):** high 0, medium 1, low 0.

Three of five partitions (P03 real-jj e2e test, P04 TypeScript SPA, P05
packaging/build tooling) produced zero findings — reviewers found the new test
well-constructed, the frontend free of XSS/escaping/stale-state bugs, and the
build tooling free of packaging defects.

## Confirmed findings

### P02-1 — Stale apply-token/session survives a retarget (medium, security)

**File:** `src/caliper/cli/part_serve.py:274-497`

**Claim:** `PartingSession.retarget()`, `set_size_cap()`, and `set_target_pr()`
never clear `_apply_token` or `_last_run`. A CSRF token minted by `generate()`
(backing `POST /restack`) for one target remains valid for `POST /apply` after
the session is retargeted to a *different* target (different base..head range,
or — via `set_target_pr()` — a different repo entirely).

**Evidence:**
`retarget()` (`:274-296`), `set_size_cap()` (`:298-309`), and `set_target_pr()`
(`:311-356`) each save/restore only their own fields (`base`/`head`/`_cut`,
`size_cap`/`_cut`, or `repo_path`/`base`/`head`/`override_store`/`out_dir`/`_cut`)
around a try/except rollback-on-failure block — none touch `self._apply_token` or
`self._last_run`. `apply()` (`:459-497`) validates the token via
`hmac.compare_digest(token, self._apply_token)` (`:471`) and, on match, resolves
`last_run.restack_path` from the **old** `self._last_run` and runs it with
`cwd=str(self.repo_path)` — the **current**, possibly-changed repo path — via a
real subprocess (`:481-488`). `PartingSession` is a long-lived singleton per
`serve_part()` invocation, closed over by every request handler, so this is
reachable across real requests. The `set_target_pr()` case is worst: `repo_path`
is reassigned to a different (possibly throwaway-clone) filesystem location while
`last_run.restack_path`/`rescue_op_id`/`backup_bookmark` still describe the old
repo, so even `POST /rollback` (`jj op restore <old rescue_op_id>`) may not
recover the new target.

**Fix:** In `retarget()`, `set_size_cap()`, and `set_target_pr()`, invalidate any
pending apply on a target/config change: capture and null both `self._last_run`
and `self._apply_token` alongside the other saved fields, restoring all of them
together in the except-block on a failed re-part. Add a unit test on the real
`PartingSession` (not `FakeSession`) asserting `apply(old_token)` raises
`ValueError` after a `retarget`/`set_target_pr` that followed a `generate()`.

**Opus adjudication (authoritative):** CONFIRMED, severity downgraded from the
challenger's `high` to **medium**. The gap is real and reachable within the
sidecar's own supported retargeting workflow, but exploitation requires a
specific same-session sequence (generate → skip apply/rollback → retarget →
apply with the stale token) rather than being remotely triggerable — `/apply` is
loopback-only with an Origin/Host check, and the one-shot token still defeats the
primary cross-origin-CSRF threat model. No existing test
(`tests/unit/test_part_serve.py:574-653,869-922`) exercises retarget-then-apply
or asserts token invalidation; `FakeSession.apply()` only records the token
string and models no token/target coupling. Genuine, currently-uncovered gap in
code whose entire purpose is to make `/apply` safe.

## False positives (refuted by challenger)

| id | Original claim | Why refuted |
|---|---|---|
| P01-1 | `write_override` can raise unhandled `ValueError`/`OSError` | The only HTTP-reachable call sites (`/reclassify`, `/suggest/apply`) are wrapped in `except Exception as exc: return _json({...}, 400)` (`part_serve.py:710-713`, `:791-793`). The one unguarded call site (`part_pipeline.py:111-112`) is reached only via the CLI's `--suggest-apply` flag, where an uncaught exception surfacing as a normal Python traceback + non-zero exit is expected CLI behavior, not a fail-open violation. |
| P02-2 | `POST /restack` response missing `overrides` field breaks SPA panel refresh | `PartRunResult`/`types.ts` has no `overrides` field; `api.ts`'s `restack()` types the response as `PartRunResult`; `app.ts` stores it only as `lastRun` (script_text/cutlist/apply_token/rollback). The overrides panel is driven by a separate `cut: CutList` state populated by other endpoints. The frontend never reads an `overrides` key from `/restack` — no observed break. |

## Uncertain / needs human

None.

## Methodology

Two-pass adversarial review: 5 Haiku reviewers fanned out over diff partitions
(each ≲2,000 lines, grounded against `caliper ground` fact sheets where
available), incentivized to over-report. A single Sonnet challenger then
re-verified all 3 raw findings against the actual source, applying the skill's
universal + project-specific don't-flag ledgers and adversarially trying to
refute each claim. The lone high-severity `CONFIRMED` finding was passed to an
Opus delta-adjudicator for an independent, skeptical re-trace of the exact
control flow (including checking for existing test coverage that would
contradict the finding) before being accepted into this report — Opus downgraded
its severity from high to medium after weighing the loopback+Origin-check+
one-shot-token mitigations against the real, currently-untested invariant gap.

**Funnel:** 3 raw → 1 challenger-confirmed, 2 false-positive, 0 uncertain → 1
Opus-confirmed (severity high → medium).

**Blind spot:** partitioning by file/subsystem hides cross-file/emergent bugs;
this review found the one it found precisely because P02 partitioned
`part_serve.py`'s session-state and CSRF-token lifecycle together — a narrower
per-file partition would likely have missed the retarget/apply interaction.

## Partitions

| id | title | files | raw | confirmed |
|---|---|---|---|---|
| P01 | Pipeline & CLI orchestrator | `part_pipeline.py`, `part_cmd.py`, `test_part_pipeline.py` | 1 | 0 |
| P02 | Sidecar backend | `part_serve.py`, `test_part_serve.py` | 2 | 1 |
| P03 | Real-jj apply/rollback integration test | `test_part_e2e.py` | 0 | 0 |
| P04 | TypeScript SPA frontend | `scripts/part_ui/*.ts`, `index.html`, `styles.css` | 0 | 0 |
| P05 | Packaging & build tooling | `build_part_ui.sh`, `screenshots.ts`, `Makefile`, `pyproject.toml`, `.gitignore`, `tsconfig.json` | 0 | 0 |
