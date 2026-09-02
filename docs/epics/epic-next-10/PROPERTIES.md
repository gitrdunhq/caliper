# PROPERTIES.md — caliper next 10

Derived from `docs/epics/epic-next-10/SPEC.md` (Epic: caliper next 10). Every property below is a testable predicate mapped to one or more `task-NNN` entries in `TASKS.md`. Categories: SAFETY, LIVENESS, INVARIANT, BOUNDARY, IDEMPOTENT, ORDERING, ISOLATION, PERFORMANCE, SECURITY, OBSERVABILITY, COMPATIBILITY.

## 1. SAFETY — what must NEVER happen

- PROPERTY(SAFETY-001): `build_review_summary()` never returns a summary where `quality_score == 0` and `maintainability_grade == 'A'` simultaneously.
- PROPERTY(SAFETY-002): verdict text never contains the substring `'blocked'` unless `policy_verdict == 'reject'`.
- PROPERTY(SAFETY-003): `render_markdown()` never emits a path beginning with `/workspace/` (or any absolute container mount path).
- PROPERTY(SAFETY-004): `render_markdown()` output length never exceeds 65,536 characters.
- PROPERTY(SAFETY-005): `render_markdown()` never renders a row in the plugin table for a plugin whose status is `skipped`.
- PROPERTY(SAFETY-006): `load_ignore_patterns()` never silently accepts a malformed `!`-scoped line — it raises `ValueError` naming the offending line number.
- PROPERTY(SAFETY-007): the normalizer never drops a finding whose rule id does not start with a `RuleScope.rule_prefix` matching its file's glob (no over-broad suppression).
- PROPERTY(SAFETY-008): a below-floor semgrep finding (severity < configured `min_severity`) never counts toward the verdict or the quality/security score.
- PROPERTY(SAFETY-009): `caliper part` never accepts or is influenced by `--runner` — container-runner logic never executes on the `part` code path.
- PROPERTY(SAFETY-010): the `--lan` read-only server never executes a mutating route (`/reclassify`, `/repart`, `/range`, `/pr`, `/suggest/apply`, `/restack`, `/apply`, `/rollback`) — any non-GET request returns 501 (pre-existing invariant re-asserted for R8's new container-runner routes, none of which may be added to the LAN handler).
- PROPERTY(SAFETY-011): the scan cache never returns a cached verdict for a repo whose live-DB scanner `db_updated_at` changed since the cached entry was written.
- PROPERTY(SAFETY-012): no `.github/workflows/*.yml` sets `CALIPER_ALLOW_HOST_TESTS` outside the test's explicit sanctioned-jobs allowlist.
- PROPERTY(SAFETY-013): `install-scanners` without `--skip-present` never silently skips installing into `--bin-dir` merely because a same-named binary exists elsewhere on PATH.
- PROPERTY(SAFETY-014): the dogfood CI job never exits 0 when the review verdict is `blocked` or `incomplete`.
- PROPERTY(SAFETY-015): `test_adr_status` never passes for an ADR file lacking a `## Status` value in `{Accepted, Superseded, Proposed}`.

## 2. LIVENESS — what must eventually happen

- PROPERTY(LIVENESS-001): for a fully-successful scan (no incomplete `PluginResult`), `build_review_summary()` eventually returns a verdict without raising.
- PROPERTY(LIVENESS-002): when one or more plugins fail to complete (timeout/not_installed/crashed), the verdict string eventually contains `'incomplete'` plus every `(plugin_name, reason)` pair.
- PROPERTY(LIVENESS-003): `caliper init` eventually writes a config file containing both the `.caliperignore` rule-scope example and the `thresholds.semgrep.min_severity` example.
- PROPERTY(LIVENESS-004): `caliper review --runner auto` eventually falls back to native execution (with a one-line stderr notice) when neither podman nor docker is on PATH — it never hangs or errors instead.
- PROPERTY(LIVENESS-005): `install-scanners --skip-present` eventually completes with the present-elsewhere tool skipped and noted in the plan output.
- PROPERTY(LIVENESS-006): `scripts/dogfood.sh` eventually propagates a non-zero exit code when the underlying review verdict is blocked/incomplete (not always exit 0).
- PROPERTY(LIVENESS-007): every currently-blocking dogfood finding is eventually either fixed or present as a baselined entry in `.caliper-baseline.yaml`, so `make dogfood` eventually reaches verdict ≠ `blocked`.

## 3. INVARIANT — what must always be true

- PROPERTY(INVARIANT-001): quality score and maintainability grade are always derived from the same single shared function (or the score is omitted whenever the grade is present).
- PROPERTY(INVARIANT-002): the dependency-section grouping key is always the advisory id — every finding sharing an advisory id always renders under exactly one heading.
- PROPERTY(INVARIANT-003): every osv-scanner `Finding.metadata['dependency_kind']` is always one of `{direct, transitive, unknown}`.
- PROPERTY(INVARIANT-004): every trivy `Finding.metadata['dependency_kind']` is always one of `{direct, transitive, unknown}`.
- PROPERTY(INVARIANT-005): `classify_dependency_kind` always returns a value in `{direct, transitive, unknown}` for any (repo_path, package_name, manifest_path) input, across all six supported manifest ecosystems.
- PROPERTY(INVARIANT-006): `thresholds.semgrep.min_severity` always defaults to `'medium'` when absent from `.caliper.yaml`, and is always overridable.
- PROPERTY(INVARIANT-007): `compute_scan_cache_key(...)` called twice with identical inputs (including `db_versions`) always produces an identical key (determinism).
- PROPERTY(INVARIANT-008): a JSON report with no `db_updated_at` metadata always still validates against `docs/schema/report-v1.0.json` (field stays optional).
- PROPERTY(INVARIANT-009): `pyproject.toml [project.scripts]` always maps `caliper` to its entry point regardless of the distribution name.
- PROPERTY(INVARIANT-010): every `.caliper-baseline.yaml` entry always has a `reason` and a parseable expiry/TTL.
- PROPERTY(INVARIANT-011): within a rendered section, findings are always ordered critical → high → medium → low → info, then alphabetically by file (Hypothesis property, arbitrary Finding lists).

## 4. BOUNDARY — valid input ranges

- PROPERTY(BOUNDARY-001): `should_ignore` matches directory components exactly `*-tests`/`*_tests`/`*-test`/`*_test` and does not match `spec/`, `fixtures/`, or substring look-alikes `attest/`, `latest.ts`, `contest.py`.
- PROPERTY(BOUNDARY-002): a `.caliperignore` line with `!` but missing glob or missing rule-id text is rejected at the boundary (`ValueError`); a well-formed `<glob> !<prefix>` line is always accepted.
- PROPERTY(BOUNDARY-003): a semgrep finding at exactly the configured `min_severity` floor counts toward verdict/score; one severity step below does not (floor is inclusive of the configured value).
- PROPERTY(BOUNDARY-004): `Finding.line` is `None` when the OSV/trivy result carries no line number, and set to the exact provided integer otherwise — no default/sentinel value (e.g. `0` or `-1`) is substituted.
- PROPERTY(BOUNDARY-005): report truncation triggers exactly when serialized length would exceed 65,536 chars, never on shorter reports, and the `(N more findings omitted)` count matches the number of findings actually dropped.
- PROPERTY(BOUNDARY-006): `caliper install-scanners --skip-present` behavior only changes for tools actually found elsewhere on PATH; tools absent from PATH always install into `--bin-dir` regardless of the flag.

## 5. IDEMPOTENT — what is safe to run twice

- PROPERTY(IDEMPOTENT-001): rendering the same `list[PluginResult]` through `render_markdown()` twice produces byte-identical markdown (golden-file test).
- PROPERTY(IDEMPOTENT-002): `load_ignore_patterns()` invoked twice on the same `.caliperignore` file produces an identical set of `RuleScope` objects.
- PROPERTY(IDEMPOTENT-003): running `caliper baseline update --reason ...` for an entry that already exists with the same reason/TTL does not duplicate the entry in `.caliper-baseline.yaml`.
- PROPERTY(IDEMPOTENT-004): `/apply`'s one-shot CSRF token is consumed on first use — a replayed `/apply` request with the same token is rejected (existing invariant; re-verified untouched by R8's runner work since `caliper part` never routes through the container runner).
- PROPERTY(IDEMPOTENT-005): running `scripts/build-test.sh`-backed CI jobs twice against the same commit produces the same pass/fail outcome (no host-environment flakiness introduced by removing `CALIPER_ALLOW_HOST_TESTS`).

## 6. ORDERING — order invariants

- PROPERTY(ORDERING-001): sections in the rendered report are ordered by the highest severity finding they contain (most severe section first).
- PROPERTY(ORDERING-002): within the dependency section, the fix-first list orders minimal direct bumps deterministically (same input list always yields the same output order).
- PROPERTY(ORDERING-003): `RuleScope` filtering (normalizer) is applied post-detection and pre-policy — a finding dropped by a rule-scope never reaches the policy evaluation stage.
- PROPERTY(ORDERING-004): the semgrep severity floor is applied before verdict/score computation but after finding collection — a below-floor finding is present in the raw finding list yet absent from the score/verdict inputs.
- PROPERTY(ORDERING-005): dogfood baseline application happens before the fail-on-blocked wiring lands (task-024 before task-025) so CI never starts failing on pre-existing findings mid-rollout.

## 7. ISOLATION — what cannot leak between contexts

- PROPERTY(ISOLATION-001): a finding's `metadata['dependency_kind']` classification for one manifest ecosystem (e.g. pyproject.toml) never leaks into/affects classification of a package declared only in a different ecosystem's manifest (e.g. package.json) in the same repo.
- PROPERTY(ISOLATION-002): container-runner mode mounts the repo read-only at `/workspace` — the review process inside the container cannot mutate files outside its explicitly read-write `.temp` mount.
- PROPERTY(ISOLATION-003): the `--lan` TLS server and the loopback `127.0.0.1` server share one `PartingSession` under a single lock, but a GET-only LAN client can never trigger a state mutation that a loopback client didn't also request (verified via the do_GET-only handler).
- PROPERTY(ISOLATION-004): forwarded `CALIPER_*` env vars in container-runner mode are exactly those present in the invoking process's environment — no unrelated env vars leak into the container invocation.
- PROPERTY(ISOLATION-005): a `RuleScope` glob under one path (e.g. `compatibility-tests/**`) never suppresses findings for files outside that glob, even when they share the same rule-id prefix.

## 8. PERFORMANCE — latency/throughput/size bounds

- PROPERTY(PERFORMANCE-001): rendered markdown output is bounded at 65,536 chars regardless of input finding count.
- PROPERTY(PERFORMANCE-002): `install-scanners` plan generation for N PATH-checked tools completes without spawning more than one `shutil.which` (or equivalent) lookup per tool.
- PROPERTY(PERFORMANCE-003): `/apply`'s underlying `bash <restack_path>` invocation is bounded by the existing 300s `ToolRunnerPort` timeout (re-asserted unaffected by R8 container-runner additions).
- PROPERTY(PERFORMANCE-004): OPA policy evaluation timeout (10s) and scribe timeout (30s) remain unaffected by any new dependency-kind classification work (classification must not block the pipeline's 300s overall budget).
- PROPERTY(PERFORMANCE-005): `classify_dependency_kind` resolves for a package within a single manifest-discovery pass — it does not re-walk the filesystem per package lookup within one review run.

## 9. SECURITY — access controls

- PROPERTY(SECURITY-001): container-runner mode always runs as the image's non-root user, never root.
- PROPERTY(SECURITY-002): `/apply`-style mutating routes remain loopback/Origin-gated; none of R8's new container-runner CLI surface introduces a new HTTP route that bypasses `_is_loopback_request`.
- PROPERTY(SECURITY-003): forwarding `CALIPER_*` env vars into the container never forwards credentials outside that prefix (e.g. `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` are not `CALIPER_*` and must not be forwarded implicitly).
- PROPERTY(SECURITY-004): the PyPI trusted-publisher rename (R4) does not alter which GitHub environment (`pypi`) or workflow (`release-please.yml`) is authorized to publish — the security boundary for publishing is unchanged, only the artifact name changes.
- PROPERTY(SECURITY-005): `install-scanners` installing into `--bin-dir` even when a same-named binary exists elsewhere on PATH never silently executes the pre-existing PATH binary instead of the pinned one (pins win, per R9's premise).

## 10. OBSERVABILITY — what must be logged or measured

- PROPERTY(OBSERVABILITY-001): an incomplete scan's verdict text lists every non-completing plugin's name and reason (timeout/not_installed/crashed).
- PROPERTY(OBSERVABILITY-002): the report prints one `'vulnerability data as of <timestamp>'` line per live-DB scanner that reported a `db_updated_at`.
- PROPERTY(OBSERVABILITY-003): a truncated report section states exactly how many findings were omitted from that section.
- PROPERTY(OBSERVABILITY-004): `caliper review --runner auto` prints a one-line stderr notice when it falls back from container to native.
- PROPERTY(OBSERVABILITY-005): `install-scanners`' plan output states `'present elsewhere: <path> (version mismatch unknown)'` for a tool found elsewhere on PATH, plus a `path_hint` telling the user `--bin-dir` must precede the other PATH location.
- PROPERTY(OBSERVABILITY-006): the skipped-plugins summary line names every skipped plugin and its skip reason in one line.

## 11. COMPATIBILITY — existing behavior that must be preserved

- PROPERTY(COMPATIBILITY-001): semgrep- and detector-originated findings' existing SARIF `physicalLocation` behavior is unchanged by the new dependency-finding SARIF placement (task-012's control case).
- PROPERTY(COMPATIBILITY-002): raising `thresholds.semgrep.min_severity` back to `'low'` restores pre-R2 behavior (low-severity findings count toward verdict/score again) — the floor is fully backward-compatible via config.
- PROPERTY(COMPATIBILITY-003): the JSON report schema change (R5 AC3) is additive-only — reports produced before the change still validate against the updated schema.
- PROPERTY(COMPATIBILITY-004): the PyPI rename preserves the `caliper` console-script name and import package, so existing user invocations (`caliper review`, `pip install caliper[...]` extras referencing the import name) keep working.
- PROPERTY(COMPATIBILITY-005): `caliper part`'s behavior (always native, no `--runner`) is bit-for-bit unchanged by the R8 container-runner feature landing on `caliper review`.
- PROPERTY(COMPATIBILITY-006): existing `.caliperignore` glob-only lines (no `!` scoping) continue to parse and behave exactly as before R2 AC2's extension.
- PROPERTY(COMPATIBILITY-007): existing Accepted ADRs that still reference live `src/caliper/` paths continue to pass `test_adr_status` unchanged after R6's Superseded-status edits to 001/002/003/004/008.

---

## Traceability Table

| Property ID | Category | Predicate (short) | Task IDs |
|---|---|---|---|
| SAFETY-001 | SAFETY | never quality_score=0 with grade A | task-001 |
| SAFETY-002 | SAFETY | 'blocked' only on policy reject | task-001 |
| SAFETY-003 | SAFETY | never /workspace/ path in output | task-002 |
| SAFETY-004 | SAFETY | output ≤ 65536 chars | task-002, task-003 |
| SAFETY-005 | SAFETY | skipped plugins never get own row | task-002 |
| SAFETY-006 | SAFETY | malformed !-line raises ValueError w/ line no. | task-005 |
| SAFETY-007 | SAFETY | RuleScope never over-suppresses | task-005 |
| SAFETY-008 | SAFETY | below-floor semgrep excluded from verdict/score | task-006 |
| SAFETY-009 | SAFETY | `part` never uses container runner | task-022 |
| SAFETY-010 | SAFETY | LAN server never executes mutating route | task-022 |
| SAFETY-011 | SAFETY | cache never stale on DB timestamp change | task-016 |
| SAFETY-012 | SAFETY | no workflow sets CALIPER_ALLOW_HOST_TESTS outside allowlist | task-021 |
| SAFETY-013 | SAFETY | install-scanners doesn't silently skip bin-dir install | task-023 |
| SAFETY-014 | SAFETY | dogfood job never exits 0 on blocked/incomplete | task-025 |
| SAFETY-015 | SAFETY | every ADR has valid Status | task-018, task-019, task-020 |
| LIVENESS-001 | LIVENESS | successful scan returns verdict, no raise | task-001 |
| LIVENESS-002 | LIVENESS | incomplete scan verdict lists plugin+reason | task-001 |
| LIVENESS-003 | LIVENESS | init writes both new config knobs | task-007 |
| LIVENESS-004 | LIVENESS | runner auto falls back to native w/ notice | task-022 |
| LIVENESS-005 | LIVENESS | skip-present completes w/ tool skipped+noted | task-023 |
| LIVENESS-006 | LIVENESS | dogfood.sh propagates non-zero on blocked | task-025 |
| LIVENESS-007 | LIVENESS | dogfood eventually verdict != blocked | task-024, task-025 |
| INVARIANT-001 | INVARIANT | score/grade single shared derivation | task-001 |
| INVARIANT-002 | INVARIANT | dependency grouping key = advisory id | task-011 |
| INVARIANT-003 | INVARIANT | osv dependency_kind in enum | task-009, task-008 |
| INVARIANT-004 | INVARIANT | trivy dependency_kind in enum | task-010, task-008 |
| INVARIANT-005 | INVARIANT | classify_dependency_kind result in enum, all ecosystems | task-008 |
| INVARIANT-006 | INVARIANT | min_severity default medium, overridable | task-006 |
| INVARIANT-007 | INVARIANT | cache key deterministic on identical input | task-016 |
| INVARIANT-008 | INVARIANT | JSON report validates without db_updated_at | task-017 |
| INVARIANT-009 | INVARIANT | console script always 'caliper' | task-013 |
| INVARIANT-010 | INVARIANT | baseline entries have reason+TTL | task-024 |
| INVARIANT-011 | INVARIANT | severity ordering holds (property test) | task-003, task-002 |
| BOUNDARY-001 | BOUNDARY | TEST_PATTERNS dir-component matching | task-004 |
| BOUNDARY-002 | BOUNDARY | malformed vs well-formed !-line boundary | task-005 |
| BOUNDARY-003 | BOUNDARY | floor inclusive at exact configured severity | task-006 |
| BOUNDARY-004 | BOUNDARY | line None vs exact int, no sentinel | task-009, task-015 |
| BOUNDARY-005 | BOUNDARY | truncation triggers exactly at 65536 | task-002, task-003 |
| BOUNDARY-006 | BOUNDARY | skip-present only affects tools found on PATH | task-023 |
| IDEMPOTENT-001 | IDEMPOTENT | golden render is byte-identical on repeat | task-003 |
| IDEMPOTENT-002 | IDEMPOTENT | load_ignore_patterns stable across runs | task-005 |
| IDEMPOTENT-003 | IDEMPOTENT | baseline update doesn't duplicate entries | task-024 |
| IDEMPOTENT-004 | IDEMPOTENT | /apply token single-use (part unaffected by R8) | task-022 |
| IDEMPOTENT-005 | IDEMPOTENT | container-image CI jobs deterministic pass/fail | task-021 |
| ORDERING-001 | ORDERING | sections ordered by highest severity present | task-002, task-003 |
| ORDERING-002 | ORDERING | fix-first list deterministic order | task-011 |
| ORDERING-003 | ORDERING | RuleScope filter before policy | task-005 |
| ORDERING-004 | ORDERING | severity floor applied post-collection pre-score | task-006 |
| ORDERING-005 | ORDERING | baseline lands before fail-on-blocked wiring | task-024, task-025 |
| ISOLATION-001 | ISOLATION | dependency_kind classification per-ecosystem isolation | task-008 |
| ISOLATION-002 | ISOLATION | container read-only /workspace, rw .temp only | task-022 |
| ISOLATION-003 | ISOLATION | LAN GET-only cannot mutate shared session | task-022 |
| ISOLATION-004 | ISOLATION | only CALIPER_* env vars forwarded | task-022 |
| ISOLATION-005 | ISOLATION | RuleScope glob scoped strictly to its path | task-005 |
| PERFORMANCE-001 | PERFORMANCE | render bounded at 65536 chars | task-002 |
| PERFORMANCE-002 | PERFORMANCE | one PATH lookup per tool in install plan | task-023 |
| PERFORMANCE-003 | PERFORMANCE | /apply bounded by 300s timeout (unaffected) | task-022 |
| PERFORMANCE-004 | PERFORMANCE | OPA/scribe timeouts unaffected by dependency_kind work | task-008, task-009, task-010 |
| PERFORMANCE-005 | PERFORMANCE | classify_dependency_kind single manifest-discovery pass | task-008 |
| SECURITY-001 | SECURITY | container runs as non-root user | task-022 |
| SECURITY-002 | SECURITY | no new route bypasses loopback/Origin gate | task-022 |
| SECURITY-003 | SECURITY | only CALIPER_* forwarded, no credential leakage | task-022 |
| SECURITY-004 | SECURITY | PyPI trusted-publisher boundary unchanged by rename | task-013, task-014 |
| SECURITY-005 | SECURITY | pinned bin-dir binary wins over PATH binary at execution | task-023 |
| OBSERVABILITY-001 | OBSERVABILITY | incomplete verdict lists plugin+reason | task-001 |
| OBSERVABILITY-002 | OBSERVABILITY | 'vulnerability data as of' line per scanner | task-015 |
| OBSERVABILITY-003 | OBSERVABILITY | truncated section states omitted count | task-002 |
| OBSERVABILITY-004 | OBSERVABILITY | stderr notice on runner fallback | task-022 |
| OBSERVABILITY-005 | OBSERVABILITY | 'present elsewhere' + path_hint strings | task-023 |
| OBSERVABILITY-006 | OBSERVABILITY | skipped-plugins summary line | task-002 |
| COMPATIBILITY-001 | COMPATIBILITY | semgrep/detector SARIF location unchanged | task-012 |
| COMPATIBILITY-002 | COMPATIBILITY | lowering floor restores old behavior | task-006 |
| COMPATIBILITY-003 | COMPATIBILITY | schema change additive-only | task-017 |
| COMPATIBILITY-004 | COMPATIBILITY | console script/import name preserved | task-013, task-014 |
| COMPATIBILITY-005 | COMPATIBILITY | `part` behavior unchanged by R8 | task-022 |
| COMPATIBILITY-006 | COMPATIBILITY | existing glob-only ignore lines unaffected | task-005 |
| COMPATIBILITY-007 | COMPATIBILITY | untouched Accepted ADRs still pass status test | task-018, task-019, task-020 |

## Per-Task Property Assignments

- **task-001**: SAFETY-001, SAFETY-002, LIVENESS-001, LIVENESS-002, INVARIANT-001, OBSERVABILITY-001
- **task-002**: SAFETY-003, SAFETY-004, SAFETY-005, BOUNDARY-005, ORDERING-001, PERFORMANCE-001, OBSERVABILITY-003, OBSERVABILITY-006, INVARIANT-011
- **task-003**: SAFETY-004, BOUNDARY-005, IDEMPOTENT-001, ORDERING-001, INVARIANT-011
- **task-004**: BOUNDARY-001
- **task-005**: SAFETY-006, SAFETY-007, BOUNDARY-002, IDEMPOTENT-002, ORDERING-003, ISOLATION-005, COMPATIBILITY-006
- **task-006**: SAFETY-008, INVARIANT-006, BOUNDARY-003, ORDERING-004, COMPATIBILITY-002
- **task-007**: LIVENESS-003
- **task-008**: INVARIANT-005, ISOLATION-001, PERFORMANCE-004, PERFORMANCE-005
- **task-009**: INVARIANT-003, BOUNDARY-004, PERFORMANCE-004
- **task-010**: INVARIANT-004, PERFORMANCE-004
- **task-011**: INVARIANT-002, ORDERING-002
- **task-012**: COMPATIBILITY-001
- **task-013**: INVARIANT-009, SECURITY-004, COMPATIBILITY-004
- **task-014**: SECURITY-004, COMPATIBILITY-004
- **task-015**: BOUNDARY-004, OBSERVABILITY-002
- **task-016**: SAFETY-011, INVARIANT-007
- **task-017**: INVARIANT-008, COMPATIBILITY-003
- **task-018**: SAFETY-015, COMPATIBILITY-007
- **task-019**: SAFETY-015, COMPATIBILITY-007
- **task-020**: SAFETY-015, COMPATIBILITY-007
- **task-021**: SAFETY-012, IDEMPOTENT-005
- **task-022**: SAFETY-009, SAFETY-010, LIVENESS-004, ISOLATION-002, ISOLATION-003, ISOLATION-004, PERFORMANCE-003, SECURITY-001, SECURITY-002, SECURITY-003, OBSERVABILITY-004, COMPATIBILITY-005, IDEMPOTENT-004
- **task-023**: SAFETY-013, LIVENESS-005, BOUNDARY-006, PERFORMANCE-002, SECURITY-005, OBSERVABILITY-005
- **task-024**: INVARIANT-010, IDEMPOTENT-003, LIVENESS-007, ORDERING-005
- **task-025**: SAFETY-014, LIVENESS-006, LIVENESS-007, ORDERING-005

All 25 tasks have at least one testable property assigned — no task is flagged as untestable.
