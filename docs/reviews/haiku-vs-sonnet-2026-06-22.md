# Haiku vs Sonnet — Adversarial Code Review Head-to-Head

**Target:** `src/caliper` (entire codebase) · **Date:** 2026-06-22 · **Focus:** correctness, design

This is a controlled head-to-head of a multi-agent adversarial review run twice against the caliper codebase. Both arms used **identical 20 source partitions and identical reviewer prompts**; the *only* variable changed was the reviewer model — one arm staffed its 20 reviewer agents with **Haiku**, the other with **Sonnet**. The second-pass challenger (red-team refutation) stage used the **same Haiku model on both arms**, so its cost and bias cancel out. Where the two arms disagree or a finding is model-unique, an **Opus** adjudicator opened the cited source independently and returned the final verdict. The scientific payload is the count of Opus-confirmed *unique* real bugs each arm found that the other missed.

## Scoreboard

| Metric | Haiku | Sonnet |
|---|---|---|
| Raw candidate findings | 117 | 134 |
| Confirmed (by its own challenger) | 69 | 106 |
| Confirm rate | 59.0% | 79.1% |
| False positives | 38 | 26 |
| FP rate | 32.5% | 19.4% |
| Uncertain | 10 | 2 |
| Severity mix (confirmed: high/med/low) | 20/32/17 | 36/54/16 |
| Reviewer tokens | 1,068,618 | 909,690 |

Sonnet produced more raw candidates (134 vs 117), confirmed far more of them (106 vs 69), at a notably **higher confirm rate (79% vs 59%)** and **lower false-positive rate (19% vs 33%)** — and used **~15% fewer reviewer tokens** doing it.

## Overlap

Cross-arm matching: two confirmed findings are the "same" when they share a file basename, fall within ±5 lines, and describe the same underlying defect.

| Bucket | Count |
|---|---|
| Both arms | 30 |
| Haiku only | 39 |
| Sonnet only | 74 |

The arms agree on a 30-finding core (largely the high-severity fail-open / dedup / timeout-message bugs). Beyond that core, Sonnet's unique set is nearly twice the size of Haiku's.

## The deltas that matter

Opus opened every model-unique confirmed finding in the real source and ruled on it. The counts below are the *adjudicated* unique-bug deltas — the real payload of this experiment.

- **Sonnet-only, Opus-CONFIRMED real bugs Haiku missed: 54**
- **Haiku-only, Opus-CONFIRMED real bugs Sonnet missed: 16**

### Sonnet-only real bugs Haiku missed (54)

- **src/caliper/composition/bootstrap.py:420** [high] — The OPA policy path is computed relative to bootstrap.py's location using four ".." traversals, but this assumes bootstrap.py lives exact...
  - *Opus:* policy_path four-.parent traversal assumes source layout, resolves wrong in site-packages install
- **src/caliper/core/concern_review.py:453** [high] — The canary-fail guard tests `canary_verdict.error` which is set to a non-empty string for ANY error, but `_review_one` also sets `error="...
  - *Opus:* canary guard treats any truthy error (incl empty-response) as fatal, skips all clusters
- **src/caliper/core/normalizer.py:33-46** [high] — Only `FindingCategory.license` findings are excluded from dedup; the remaining non-vulnerability categories (`copyright`, `code_smell`, `...
  - *Opus:* dedup key with advisory_id=None collapses distinct non-vuln detector findings, drops findings
- **src/caliper/core/opa_adapter.py:98** [high] — `_build_opa_input` emits only `id`, `severity`, and `message` for each finding, but the Rego policy rules for `critical_vuln`, `forbidden...
  - *Opus:* _build_opa_input emits only id/severity/message but rego reads category/advisory_id/etc
- **src/caliper/core/pipeline.py:309** [high] — `evaluate_sbom` never stamps `commit_sha` onto its `ReviewRequest` objects, so every request produced by the SBOM path stores `commit_sha...
  - *Opus:* evaluate_sbom never stamps req.commit_sha unlike evaluate() at 151, SBOM requests persist commit_sha=None
- **src/caliper/core/registry.py:169** [high] — `run_all` runs plugins in parallel via `ThreadPoolExecutor` even though `_topological_sort` establishes a strict execution order for `dep...
  - *Opus:* run_all topo-sorts then ThreadPoolExecutor.map concurrent, depends_on ordering defeated for plugins sharing no edge
- **src/caliper/core/taskfit.py:206** [high] — _call_and_validate loops `range(max_retries)` (0, 1) so it makes exactly max_retries=2 calls but the docstring says "Retries up to max_re...
  - *Opus:* range(max_retries=2) only 2 attempts (1 retry), contradicts docstring "retries up to max_retries"
- **src/caliper/data/catalog.py:254** [high] — `ingest_lockfile` deletes ALL packages for a repo (`DELETE FROM repo_packages WHERE repo_name = %s`) before re-inserting, but the delete ...
  - *Opus:* catalog DELETE FROM repo_packages WHERE repo_name repo-scoped not lockfile-scoped, no lockfile_path col, wipes other lockfiles
- **src/caliper/data/pypi.py:115** [high] — `_compute_first_published` returns the earliest upload timestamp across **all versions ever published**, not the upload date of the reque...
  - *Opus:* _compute_first_published returns earliest across all releases, new version of old pkg bypasses 30d gate
- **src/caliper/detectors/reliability/cache_eviction.py:76** [high] — False negative — `@lru_cache(maxsize=None)` is not detected; `maxsize=None` is explicitly unbounded but the guard only checks key presenc...
  - *Opus:* _has_unbounded_cache only checks key presence, @lru_cache(maxsize=None) treated as bounded
- **src/caliper/detectors/reliability/cache_eviction.py:83** [high] — False negative — `@lru_cache` (bare, without parentheses) is not detected; only `@lru_cache()` with a call node is checked.
  - *Opus:* _has_unbounded_cache handles bare @cache and @lru_cache() but not bare @lru_cache, inconsistent detection gap
- **src/caliper/detectors/reliability/circuit_breaker.py:154** [high] — False positive crash risk — `_has_half_open_config` iterates `call.keywords` and calls `keyword.arg.lower()` without guarding for `keywor...
  - *Opus:* _has_half_open_config calls keyword.arg.lower() no None guard, **kwargs arg crashes AttributeError
- **src/caliper/detectors/reliability/subprocess_timeout.py:114** [high] — False positive — `_needs_timeout` matches ANY function call whose name contains `"run"`, `"call"`, etc., not just subprocess calls; combi...
  - *Opus:* find_function_calls subprocess.* relies on dotted name, bare-imported run() missed (FP-claim actually FN, real defect)
- **src/caliper/plugins/gitleaks.py:56** [high] — `tempfile.mktemp()` is a TOCTOU race — the file path is reserved but never created, so another process can create a file at the same path...
  - *Opus:* gitleaks uses tempfile.mktemp(), TOCTOU-prone deprecated API
- **src/caliper/cli/inspect_cmds.py:79** [medium] — `check_health` imports directly from `caliper.data.db` (the data layer), violating the cli→core→data import direction rule; the CLI layer m...
  - *Opus:* inspect_cmds imports from caliper.data.db in CLI layer, violates cli->core->data direction
- **src/caliper/core/actionability.py:11** [medium] — _CRITICAL_HIGH is a plain set of raw strings rather than using the severity Enum that CLAUDE.md mandates for all state fields, breaking t...
  - *Opus:* _CRITICAL_HIGH raw-string set vs severity values, contravenes enum-for-state convention
- **src/caliper/core/concern_remediate.py:118-135** [medium] — `Remediator.remediate_finding` does not implement retry logic, unlike the shared `post_with_retry` used in `HolisticReviewer`, creating a...
  - *Opus:* remediate uses bare post with no retry while concern_review uses _post_with_retry
- **src/caliper/core/scribe.py:106** [medium] — merge_scribe overwrites all existing scribe fields with the new fields unconditionally via scribe.update(fields), so a second...
  - *Opus:* scribe.update(fields) unconditionally overwrites shared keys, later scribe clobbers earlier
- **src/caliper/core/file_source.py:40** [medium] — `vendor` is in `_ALWAYS_SKIP_DIRS` but not in `DEFAULT_PATTERNS`, so `GitLsFilesSource` enumerates tracked files under `vendor/` while `W...
  - *Opus:* vendor in _ALWAYS_SKIP_DIRS but absent from DEFAULT_PATTERNS, GitLsFilesSource enumerates tracked vendor files, source divergence
- **src/caliper/core/llm_client.py:45** [medium] — LlmClient constructs a single shared httpx.Client with a fixed timeout baked in at __init__ time, but the timeout value stored in self._t...
  - *Opus:* LlmClient has only close(), no context manager/__del__, short-lived instance leaks pool
- **src/caliper/core/manifest_discovery.py:180** [medium] — The lockfile search `break` statement fires whenever the first candidate lockfile name is present in the directory, even when `_is_within...
  - *Opus:* lockfile loop break fires unconditionally once name in sibling_set even if _is_within_repo rejects, no alternate tried
- **src/caliper/core/memo.py:75-76** [medium] — `needs_explanation` is False for `approve_with_constraints`, so a memo for a constrained approval renders the "### Constraints" section (...
  - *Opus:* needs_explanation excludes approve_with_constraints, Constraints block renders without preceding Why explanation
- **src/caliper/core/nl_query.py:369** [medium] — `query_code` opens a SQLite connection (`sqlite3.connect`) but does not set a busy-timeout or WAL mode, and — more critically — if `conn....
  - *Opus:* nl_query catches only sqlite3.OperationalError, other sqlite exceptions propagate (fail-open break)
- **src/caliper/core/orchestrator.py:50** [medium] — `ThreadPoolExecutor` is never shut down if any exception other than `TimeoutError` escapes the `as_completed` loop, leaking threads for t...
  - *Opus:* as_completed loop only handles TimeoutError, no finally, non-TimeoutError leaks executor
- **src/caliper/core/ports.py:173** [medium] — `ReviewReport.verdict` is typed as a bare `str` instead of an enum, violating the project invariant "enums for all state fields, never ra...
  - *Opus:* ReviewReport.verdict typed bare str (ports.py:173), violates enum-for-state invariant
- **src/caliper/core/renderer.py:83-95** [medium] — `calculate_quality_score` classifies any plugin that is NOT in `_SECURITY_PLUGINS` as a quality plugin, meaning unknown/new plugins (e.g....
  - *Opus:* calculate_quality_score includes any plugin not in _SECURITY_PLUGINS, unknown new plugin inflates quality score
- **src/caliper/core/sarif.py:57-60** [medium] — Absolute file URIs are never percent-encoded, so paths with spaces or non-ASCII characters produce malformed `artifactLocation.uri` value...
  - *Opus:* _make_locations sets uri=str(file_path) no percent-encoding, paths with spaces produce bad uri
- **src/caliper/core/solver.py:394-401** [medium] — When `_looks_like_python` returns False (model returned non-Python output), `_try_model` immediately returns `None, attempts` without con...
  - *Opus:* solver returns (None,attempts) on non-Python output inside retry loop, abandons retries
- **src/caliper/core/solver.py:537-547** [medium] — `_clean_code` only removes the *first* opening fence encountered and only the single trailing fence; it does not handle multiple fenced b...
  - *Opus:* _clean_code strips only first opening fence and single trailing fence, intermediate ``` survive break ast.parse
- **src/caliper/data/evidence.py:179** [medium] — `list_artifacts` only enumerates top-level files in the evidence key directory, but `create_seal` in `seal.py` hashes all files recursive...
  - *Opus:* list_artifacts uses iterdir() top-level only while seal hashes via rglob; nested SBOM keys diverge
- **src/caliper/detectors/ast_utils.py:281** [medium] — `get_annotation_text` calls `get_call_name` to stringify an `ast.Attribute` annotation, but `get_call_name` requires an `ast.Call` node a...
  - *Opus:* get_annotation_text passes Attribute to get_call_name which returns None for non-Call, annotations stringify None
- **src/caliper/detectors/config/config_merge.py:59** [medium] — `target_files` declares `("*.py", "*.yaml", "*.yml", "*.json")` but the detector only performs Python AST analysis; YAML and JSON files a...
  - *Opus:* detect() uses Python AST but declares yaml/yml/json targets, those yield zero findings (misleading scope)
- **src/caliper/detectors/framework.py:108** [medium] — `is_suppressed` reads the entire file from disk on every call, which is called per-finding in the scanner outer loop (scanner.py:143). Fo...
  - *Opus:* is_suppressed does f.readlines() every call, scanner calls per-finding no caching, O(N) re-reads
- **src/caliper/detectors/reliability/cache_eviction.py:67** [medium] — False positive in message — the function name is used instead of the decorator name, making the message misleading.
  - *Opus:* message uses decorated function name not decorator name, misleading
- **src/caliper/detectors/reliability/cache_ttl.py:140** [medium] — False negative / false positive mix — `_has_ttl_check` uses a ±5 line proximity heuristic on line numbers derived from an AST walk of the...
  - *Opus:* _has_ttl_check walks whole-file tree with ±5 line proximity not scope-bounded, cross-function suppression
- **src/caliper/detectors/reliability/non_atomic_write.py:84** [medium] — False negative — the window-based check allows an atomic marker anywhere within ±10 lines, including in a completely unrelated code block...
  - *Opus:* ±window scan accepts atomic marker anywhere in window incl unrelated block (FN)
- **src/caliper/detectors/reliability/non_atomic_write.py:18** [medium] — False negative — `.write_text(` in a string literal or comment triggers the marker check; lines like `# Use path.write_text(...)` or `doc...
  - *Opus:* non_atomic_write line 76 raw-text substring marker in line no AST, .write_text( in comments/strings triggers (real defect)
- **src/caliper/detectors/reliability/nullable_dedup_key.py:42** [medium] — False negative — `_IF_GUARD_RE` matches `if.*advisory_id` on a preceding line but does not verify the `if` guard is a non-None check; `if...
  - *Opus:* _IF_GUARD_RE matches any if mentioning advisory_id incl non-None checks, suppresses though None possible
- **src/caliper/detectors/security/arch_boundary.py:29** [medium] — Path-segment check `"/agent/"` and `"/cli/"` uses simple substring matching on the full path string, causing false positives for files in...
  - *Opus:* _PRESENTATION_SEGMENTS substring match seg in path_str on /agent//cli/, matches any path regardless of tier
- **src/caliper/detectors/security/fixed_output_delimiter.py:20** [medium] — `_HEREDOC_RE` requires the delimiter to start with an uppercase letter (`[A-Z]`) and contain only uppercase letters, digits, and undersco...
  - *Opus:* _HEREDOC_RE requires [A-Z], lowercase delimiters never matched despite being valid
- **src/caliper/detectors/security/rate_limiting.py:103** [medium] — False positive — any function decorated with an attribute whose name contains "route", "get", "post", etc. (e.g., `@metrics.get_counter`,...
  - *Opus:* API_ENDPOINT_PATTERNS substring match, @metrics.get_counter matches via "get" (FP)
- **src/caliper/detectors/security/secret_str.py:66** [medium] — `file_path.read_text()` at line 66 is called outside the `try/except SyntaxError` block (lines 67–70), so an `OSError` (file not readable...
  - *Opus:* read_text() outside try (only catches SyntaxError), OSError propagates, violates detector fail-open
- **src/caliper/plugins/_opa.py:25** [medium] — `OpaPlugin.description` hard-codes "6 Rego rules" but the policy contains 8 rules (5 deny + 3 warn per CLAUDE.md and policy.rego), making...
  - *Opus:* description hard-codes "6 Rego rules" while policy has 8
- **src/caliper/plugins/clamav.py:46** [medium] — ClamAV's default timeout is 120s (double the project-mandated 60s scanner timeout from CLAUDE.md), and this default is hardcoded in the m...
  - *Opus:* clamav hardcodes default timeout=120, double the 60s mandate, not config-driven
- **src/caliper/plugins/osv_scanner.py:167-176** [medium] — `_resolve_severity` CVSS score parsing treats the score as a plain float, but OSV `severity[].score` is a CVSS *vector string* (e.g., `"C...
  - *Opus:* OSV score is CVSS vector string, float() raises suppressed ValueError, numeric branch dead
- **src/caliper/plugins/swiftlint.py:134** [medium] — SwiftLint severity values in the JSON output are title-case (e.g. "Warning", "Error") but `_SEV_MAP` uses only lowercase keys, so `.lower...
  - *Opus:* _SEV_MAP passes error/warning/info unchanged while codebase uses critical/high/medium/low/info, non-standard severity
- **src/caliper/core/memo.py:82-84** [low] — The "### Why" section unconditionally re-renders `pol.triggered_rules[:5]`, which is a subset of the same rules already listed verbatim u...
  - *Opus:* reject/needs_review memo "### Why" triggered_rules[:5] duplicates rules under "### Triggered Policy Rules"
- **src/caliper/core/models.py:18** [low] — `_orjson_dumps` is defined and `orjson` is imported but the function is never referenced anywhere in the codebase; the docstring's promis...
  - *Opus:* _orjson_dumps defined but never referenced, orjson round-trip promise unimplemented dead code
- **src/caliper/core/solver.py:172** [low] — `_RETRYABLE_STATUS = {429, 500, 502, 503, 504}` includes 429, but the 429 case is explicitly handled earlier at line 318 and never reache...
  - *Opus:* 429 handled at 318 with continue, never reaches _RETRYABLE_STATUS at 330, dead/misleading
- **src/caliper/core/telemetry.py:152** [low] — The field `scan_time_bucket` is named to imply a time/duration bucket but actually stores a file-count bucket, creating a persistent nami...
  - *Opus:* field named scan_time_bucket but docstring says file-count bucket, Literal values are file ranges
- **src/caliper/detectors/config/docker_pin_drift.py:87** [low] — `_LATEST_TAG_RE` fires on `:latest` occurrences in Dockerfile comments, `RUN echo` strings, and `ENV` assignments that are not image refe...
  - *Opus:* _LATEST_TAG_RE searched every line no FROM/comment/ENV filtering, fires on any :latest
- **src/caliper/plugins/supply_chain.py:262** [low] — Unpinned-dependency findings for `requirements*.txt` files use `req.name` (the bare filename) as the `"file"` field, while `package.json`...
  - *Opus:* npm findings use file=rel but requirements use file=req.name, monorepo reqs indistinguishable
- **src/caliper/plugins/supply_chain.py:62** [low] — `_image_is_floating` misidentifies private-registry images of the form `registry.host:5000/image` (no version tag) as pinned, because the...
  - *Opus:* _image_is_floating splits registry:port on colon, tag "5000/image"!=latest, wrongly returns pinned
- **src/caliper/plugins/swiftlint.py:30** [low] — The `_make_relative` helper function is duplicated verbatim between swiftlint.py (lines 52-56) and swiftformat.py (lines 28-32), with no ...
  - *Opus:* _make_relative byte-identical in swiftlint and swiftformat, no shared utility

### Haiku-only real bugs Sonnet missed (16)

- **src/caliper/core/diff.py:218** [medium] — Both-versions-None case (old_ver is None and new_ver is None) defaults to "upgraded" action but should never occur — indicates the logic ...
  - *Opus:* both-None case inside elif old_ver!=new_ver, final else unreachable dead/defensive code
- **src/caliper/core/diff.py:212** [medium] — _compute_diff hardcodes "upgraded" when Version parsing fails, ignoring actual version ordering — inconsistent with sbom_diff.py fallback...
  - *Opus:* diff.py:212 hardcodes upgraded on InvalidVersion while sbom_diff:145 uses lexicographic fallback, loses downgrade
- **src/caliper/core/opa_adapter.py:86** [medium] — PolicyDecision verdict field expects string enum but constructed with raw string literals, fragile against enum changes.
  - *Opus:* PolicyDecision.verdict typed PolicyVerdict StrEnum but constructed with raw "needs_review" literals, bypasses enum
- **src/caliper/detectors/findings.py:49-69** [medium] — DetectorFinding.to_finding() loses line_number and column information, breaking traceability to source code location.
  - *Opus:* to_finding() omits line_number/column; core Finding model has no such fields, location lost
- **src/caliper/detectors/reliability/health_check_db.py:156** [medium] — False negative: The detector will miss database checks that use variable names instead of string literals for SQL.
  - *Opus:* _get_string_content only resolves ast.Constant strings, SQL via variable name not detected
- **src/caliper/detectors/security/fixed_output_delimiter.py:84-86** [medium] — False negative when GITHUB_OUTPUT reference appears > 3 lines before heredoc
  - *Opus:* context window lines[max(0,i-4):i], GITHUB_OUTPUT >3 lines before heredoc not seen (FN)
- **src/caliper/detectors/security/sql_injection.py:105-109** [medium] — False positive on f-strings without interpolation (literal strings)
  - *Opus:* f-string with no interpolation parses to JoinedStr, flagged as dangerous formatting (FP in detector)
- **src/caliper/detectors/security/sql_injection.py:117-119** [medium] — False positive on .format() with no arguments (safe parameterized queries)
  - *Opus:* flags any .format attribute call regardless of args, no-arg q.format() is FP
- **src/caliper/plugins/clamav.py:69** [medium] — Timeout error message passes 0 instead of actual timeout value.
  - *Opus:* clamav line 69 passes literal timeout=0 into TIMEOUT error instead of in-scope timeout param (default 120)
- **src/caliper/plugins/complexity.py:32-35** [medium] — ComplexityPlugin.run() catches all exceptions generically without differentiating timeout from crashes; hard-coded timeout=60 in runner c...
  - *Opus:* ComplexityPlugin.run() calls _run without timeout, default 60 never overridden by config; blanket except
- **src/caliper/core/actionability.py:37-39** [low] — Severity bucket counts computed via three separate iterations over blocked list, O(3n) instead of O(n)
  - *Opus:* actionability 37-39 three separate sum() passes over blocked, O(3n) accurate
- **src/caliper/core/fake.py:24-25** [low] — FakePolicyEngine.evaluate() returns bare verdict string, not DecisionVerdict enum
  - *Opus:* FakePolicyEngine returns verdict="approve" bare string where field typed PolicyVerdict StrEnum, violates enum convention
- **src/caliper/core/use_cases.py:33-34** [low] — ReviewOptions.categories field is typed as list with no element type annotation, while scanners field is typed as list[str].
  - *Opus:* categories annotated list
- **src/caliper/detectors/config/config_merge.py:159-171** [low] — _is_config_key() uses substring matching ("port" in "exported") which is overly broad and will match unintended keys
  - *Opus:* _is_config_key uses any(k in key.lower()), "port" in "exported" True, substring over-broad
- **src/caliper/detectors/reliability/cache_eviction.py:95-96** [low] — False negative: The detector checks for @lru_cache() without maxsize, but will miss @lru_cache(maxsize=None) which is semantically unboun...
  - *Opus:* @lru_cache(maxsize=None) has maxsize kwarg so not flagged yet unbounded (real FN)
- **src/caliper/plugins/mypy.py:76-94** [low] — _run_mypy() and _run_pyright() are duplicated code paths with nearly identical structure (subprocess.run, timeout handling, JSON parsing ...
  - *Opus:* _run_mypy/_run_pyright duplicate filter+subprocess+TimeoutExpired boilerplate (minor DRY)

## Cost

- Haiku reviewers (20 agents): **1,068,618** subagent tokens.
- Sonnet reviewers (20 agents): **909,690** subagent tokens.
- The challenger (refutation) stage used the same Haiku model on both arms, so its cost is equal and cancels.

**Price caveat:** Sonnet used ~15% *fewer* reviewer tokens, but Sonnet's per-token price is materially higher than Haiku's, so the **dollar** cost of the reviewer stage still favors Haiku despite the lower token count. Token counts are the objective, model-agnostic figure reported here; the dollar comparison depends on current per-token pricing and is left qualitative. The decision is therefore: pay materially more per run to get 3.4x the unique real bugs and roughly half the false-positive noise.

## Verdict

Sonnet found materially more real bugs: of the model-unique confirmed findings, Opus confirmed 54 sonnet-only bugs Haiku missed versus 16 haiku-only bugs Sonnet missed, and Sonnet did so at a far lower false-positive rate (19% vs 33%) AND ~15% fewer reviewer tokens. Sonnet's per-token price is higher, but on this codebase its 3.4x advantage in unique real bugs and lower noise make it clearly worth the higher price for a high-stakes review. Haiku remains a credible cheaper sweep that still surfaced 16 unique real bugs Sonnet overlooked, so the two arms are partly complementary.

## Caveats

- **n=1.** This is a single run per arm. There is no variance estimate; rerunning either arm would shift the exact counts. Treat the deltas as directional, not precise.
- **Fuzzy cross-arm matching.** Bucketing into both/haiku-only/sonnet-only relies on file+line+claim judgment. A handful of near-miss pairs could legitimately be classified either way, nudging the overlap triple by a few findings.
- **Haiku-verifier bias, mitigated not eliminated.** Both arms were verified by the *same* Haiku challenger, so any systematic leniency or harshness applies equally. Opus re-adjudicated every model-unique finding to correct for verifier error, but the 30-finding shared core and the in-arm confirm/FP totals still carry the Haiku verifier's judgment.
- **Partitioned review misses cross-file bugs.** Reviewers see one partition at a time, so defects that only manifest across partition boundaries (multi-module data-flow, cross-file invariants) are invisible to **both** arms equally — this experiment says nothing about that class of bug.
