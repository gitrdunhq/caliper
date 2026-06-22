# Adversarial Code Review — eedom

_Generated 2026-06-22 · target: `src/eedom (entire codebase)` · focus: correctness, design_

This report is the synthesis of a two-pass adversarial review of the eedom codebase. In the first pass, a fleet of cheap Haiku **reviewer** agents was fanned out across 20 partitions of `src/eedom`, each surfacing candidate correctness and design findings. In the second pass, Haiku **challenger** agents red-teamed every candidate, attempting to refute it and assigning a final verdict (CONFIRMED, FALSE_POSITIVE, or UNCERTAIN) and severity. Both the reviewer and challenger roles ran on Haiku; there was no separate verifier model. Only CONFIRMED findings are treated as actionable; UNCERTAIN findings are retained for human review, and FALSE_POSITIVE candidates are dropped. Of 117 raw candidates, 69 were confirmed.

## Funnel

- **Raw candidates:** 117
- **Confirmed:** 69
- **False positives:** 38
- **Uncertain (needs human review):** 10
- **False-positive rate:** 32.5% (38/117)

Confirmed by severity: high 20, medium 32, low 17.

## Confirmed findings

| ID | Severity | Category | File:line | Claim |
|----|----------|----------|-----------|-------|
| P02-1 | high | correctness | `src/eedom/core/normalizer.py:40` | Dedup key includes advisory_id which may be None, causing unrelated findings to silently collide and disappear. |
| P03-1 | high | correctness | `src/eedom/core/opa_adapter.py:65-74` | OPA command argument order differs from policy.py, placing --format before data.policy instead of after, breaking CLI parsing. |
| P03-2 | high | correctness | `src/eedom/core/opa_adapter.py:107-109` | Config merge uses shallow update(), losing rules_enabled defaults when caller passes a rules_enabled dict override. |
| P01-5 | high | correctness | `src/eedom/core/pipeline.py:240-254` | Exception handler builds ReviewDecision with scan_results variable from outer loop scope, which may be stale if orchestrator.run has not completed or has failed. |
| P05-5 | high | correctness | `src/eedom/core/repo_config.py:69` | Falsy-value merge bug in load_merged_config causes empty list overrides to fall back to root config |
| P05-6 | high | correctness | `src/eedom/core/repo_config.py:68` | SemgrepConfig from package-level .eagle-eyed-dom.yaml is completely ignored during merge |
| P04-1 | high | correctness | `src/eedom/core/seal.py:202` | Timestamp sorting for seal chain is vulnerable to lexicographic ordering bugs, not RFC3339 temporal ordering. |
| P10-1 | high | correctness | `src/eedom/core/subprocess_runner.py:27-43` | UnicodeDecodeError not caught when subprocess outputs binary data with text=True |
| P10-2 | high | correctness | `src/eedom/core/version.py:14-16` | get_version() does not handle PackageNotFoundError, causing module import to fail |
| P14-1 | high | correctness | `src/eedom/detectors/config/config_merge.py:115-134` | _is_dangerous_merge() logic is contradictory—returns True on line 134 if unpacking exists, even when config-key check on lines 128-132 finds nothing |
| P14-4 | high | correctness | `src/eedom/detectors/process/tested_by.py:82-88` | Path resolution logic is unreliable—tries relative-to-parent first, then falls back to resolve() with no actual path discovery or existence check before using candidate |
| P13-3 | high | correctness | `src/eedom/detectors/reliability/subprocess_timeout.py:132-138` | False negative: The _popen_has_communicate_timeout() method has fundamentally broken logic. It looks for communicate() calls anywhere in the tree with timeout, not necessarily tied to the specific Popen call being analyzed. |
| P13-4 | high | correctness | `src/eedom/detectors/reliability/transaction_rollback.py:127-135` | False negative: The _is_looped_insert() method has inverted scoping logic. It iterates through ALL nodes and checks if the call is in a loop, but uses ast.walk(parent) which traverses all descendants, making it impossible to verify that a given call is actually inside that specific loop. |
| P15-4 | high | correctness | `src/eedom/plugins/_runners/cfn_nag_runner.py:76` | NameError when exception handler uses result.returncode but result is not in scope. |
| P15-1 | high | correctness | `src/eedom/plugins/_runners/graph_builder.py:392` | Unchecked .fetchone() dereference causes crash when symbol lookup finds no match. |
| P17-1 | high | correctness | `src/eedom/plugins/cdk_nag.py:32-34` | CdkNagPlugin.run() catches all exceptions generically without differentiating timeout/not-installed from other errors, violating fail-open contract that requires specific error handling. |
| P17-4 | high | correctness | `src/eedom/plugins/ls_lint.py:47` | LsLintPlugin.run() reports timeout with timeout=0 instead of the actual timeout value (30 seconds), making error messages useless for debugging. |
| P18-1 | high | correctness | `src/eedom/plugins/supply_chain.py:292-304` | Lockfile integrity check has broken variable scope — `manifest_changed` computed in loop but used outside, causing only the last directory's result to be checked instead of all directories. |
| P20-1 | high | correctness | `src/eedom/webhook/config.py:24` | WebhookSettings.secret is a required non-Optional field, but _load_app() calls WebhookSettings() without catching MissingConfigError for missing EEDOM_WEBHOOK_SECRET. |
| P20-2 | high | design | `src/eedom/webhook/server.py:181-189` | Webhook enumerates files via rglob() directly instead of using the file_source seam (FileSourcePort), violating the architectural rule "consumers never call rglob/os.walk/git directly." |
| P20-3 | medium | correctness | `src/eedom/agent/main.py:169-182` | _extract_reject_from_tool_results() early-returns at line 180 when the first reject is found, preventing examination of subsequent tool results if the agent response structure contains multiple tool invocation results. |
| P18-2 | medium | correctness | `src/eedom/core/diff.py:212` | _compute_diff hardcodes "upgraded" when Version parsing fails, ignoring actual version ordering — inconsistent with sbom_diff.py fallback which uses lexicographic comparison. |
| P18-5 | medium | correctness | `src/eedom/core/diff.py:218` | Both-versions-None case (old_ver is None and new_ver is None) defaults to "upgraded" action but should never occur — indicates the logic path is unreachable or the code is defensive against an impossible condition without documenting why. |
| P02-3 | medium | correctness | `src/eedom/core/memo.py:116-117` | Memo truncation slices at a hard character offset, ignoring line/paragraph boundaries, violating Markdown format. |
| P03-3 | medium | design | `src/eedom/core/opa_adapter.py:86` | PolicyDecision verdict field expects string enum but constructed with raw string literals, fragile against enum changes. |
| P01-6 | medium | correctness | `src/eedom/core/pipeline.py:267-270` | pypi_client.close() is wrapped in contextlib.suppress(Exception), silently swallowing all close errors and preventing visibility into resource-cleanup issues. |
| P01-7 | medium | correctness | `src/eedom/core/pipeline.py:432-434` | Identical silent close error suppression for pypi_client in evaluate_sbom method mirrors the same transparency loss as in evaluate(). |
| P15-7 | medium | correctness | `src/eedom/core/registry.py:149` | Topological sort does not validate that a plugin's depends_on name actually exists; silently drops unknown deps. |
| P04-4 | medium | design | `src/eedom/core/seal.py:94` | Timestamp precision may not be sufficient for seal uniqueness in rapid successive runs on the same machine. |
| P10-3 | medium | design | `src/eedom/core/subprocess_runner.py:54-63` | OSError not caught, violates fail-open invariant for permission/resource errors |
| P09-2 | medium | design | `src/eedom/core/taskfit_validator.py:185-206` | Unsafe pattern: recommendation variable set to None outside conditional, then used in TaskFitAssessment construction only when errors is empty, violating explicit type contract |
| P11-3 | medium | correctness | `src/eedom/detectors/ast_utils.py:659-670` | BatchVisitor.visit() breaks the standard NodeVisitor contract by calling generic_visit unconditionally, causing nodes to be visited twice. |
| P14-2 | medium | correctness | `src/eedom/detectors/config/docker_pin_drift.py:18-19` | _PIP_PIN_RE regex requires word boundary after "pip" but not "install", causing false negatives on multi-word situations |
| P11-2 | medium | design | `src/eedom/detectors/findings.py:49-69` | DetectorFinding.to_finding() loses line_number and column information, breaking traceability to source code location. |
| P14-3 | medium | correctness | `src/eedom/detectors/metrics/high_cardinality.py:151-159` | _get_high_cardinality_label_kwargs() allows None keyword.arg to pass through, causing potential crash on NoneType comparison |
| P13-8 | medium | correctness | `src/eedom/detectors/reliability/health_check_db.py:156` | False negative: The detector will miss database checks that use variable names instead of string literals for SQL. |
| P13-7 | medium | correctness | `src/eedom/detectors/reliability/path_construction.py:123-136` | False negative: The detector will not flag path construction in certain common patterns because the heuristic for identifying "path-related strings" is weak and can be bypassed. |
| P12-3 | medium | correctness | `src/eedom/detectors/security/fixed_output_delimiter.py:84-86` | False negative when GITHUB_OUTPUT reference appears > 3 lines before heredoc |
| P12-1 | medium | correctness | `src/eedom/detectors/security/secret_str.py:76-96` | False negative on secrets assigned without type annotations at module/class scope |
| P12-6 | medium | correctness | `src/eedom/detectors/security/sql_injection.py:75-76` | Redundant deduplication logic may mask multiple violations on same line |
| P12-7 | medium | correctness | `src/eedom/detectors/security/sql_injection.py:117-119` | False positive on .format() with no arguments (safe parameterized queries) |
| P12-8 | medium | correctness | `src/eedom/detectors/security/sql_injection.py:105-109` | False positive on f-strings without interpolation (literal strings) |
| P15-3 | medium | correctness | `src/eedom/plugins/_runners/cpd_runner.py:297` | Scanned file count double-counts when PMD breaks and fallback processes same files. |
| P15-2 | medium | correctness | `src/eedom/plugins/_runners/graph_builder.py:400-403` | COUNT(*) queries assume rows always exist; will crash on empty database. |
| P16-3 | medium | correctness | `src/eedom/plugins/clamav.py:69` | Timeout error message passes 0 instead of actual timeout value. |
| P17-2 | medium | correctness | `src/eedom/plugins/complexity.py:32-35` | ComplexityPlugin.run() catches all exceptions generically without differentiating timeout from crashes; hard-coded timeout=60 in runner call is never overridden by config. |
| P17-3 | medium | correctness | `src/eedom/plugins/cpd.py:50-68` | CpdPlugin.run() catches all exceptions generically; runner call receives no timeout parameter; both error paths return PluginResult but generic Exception case doesn't include error_msg(). |
| P17-9 | medium | correctness | `src/eedom/plugins/cspell.py:54-72` | CspellPlugin.run() relies on contextlib.suppress() to silently ignore JSON/KeyError/TypeError during parsing (line 77), then falls back to regex parsing. If the JSON reporter produces valid JSON but with unexpected schema (e.g. missing 'issues' key in future versions), plugin returns empty findings without logging, violating fail-open with diagnostics. |
| P17-5 | medium | correctness | `src/eedom/plugins/kube_linter.py:29-40` | KubeLinterPlugin.run() catches all exceptions generically without differentiating error types; runner (kube_linter_runner.py) is a black box whose error structure is unknown, risking silent failures. |
| P16-1 | medium | correctness | `src/eedom/plugins/osv_scanner.py:106` | Timeout error message passes 0 instead of actual timeout value, breaking error diagnostics. |
| P16-6 | medium | design | `src/eedom/plugins/semgrep.py:59-62` | Timeout hardcoded to 120 instead of using scanner_timeout from config (60s). |
| P16-2 | medium | correctness | `src/eedom/plugins/syft.py:69` | Timeout error message passes 0 instead of actual timeout value. |
| P20-6 | low | correctness | `src/eedom/agent/main.py:238-271` | main() does not validate pr_number > 0 after conversion, allowing pr_number=0 to reach GatekeeperAgent.run() which uses it in API calls, potentially causing silent failures or incorrect routing. |
| P09-3 | low | design | `src/eedom/core/actionability.py:37-39` | Severity bucket counts computed via three separate iterations over blocked list, O(3n) instead of O(n) |
| P06-3 | low | design | `src/eedom/core/enrich.py:40` | Budget exhaustion logs once per enricher per finding, creating excessive log spam when timeout occurs early in multi-finding batch. |
| P10-5 | low | design | `src/eedom/core/fake.py:24-25` | FakePolicyEngine.evaluate() returns bare verdict string, not DecisionVerdict enum |
| P03-6 | low | design | `src/eedom/core/opa_adapter.py:80-86` | Exception handler catches BLE001 (all exceptions) but logs at error level, contradicting fail-open philosophy. |
| P18-3 | low | design | `src/eedom/core/sbom_diff.py:136-145` | Lexicographic string comparison for non-semver versions yields wrong ordering (e.g., "10" < "2"), creating silent misclassifications. Warning is logged but finding is still emitted with potentially wrong direction. |
| P18-4 | low | design | `src/eedom/core/supply_chain_diff.py:140-150` | Fail-open on source unavailable embeds error detail only in message string, not as a separate field, making it hard for automated tools to distinguish error types (404 vs timeout vs extraction failure). |
| P01-10 | low | design | `src/eedom/core/use_cases.py:45` | ReviewResult.results field is typed as bare list with no element type, violating strict Pydantic typing. |
| P01-9 | low | design | `src/eedom/core/use_cases.py:33-34` | ReviewOptions.categories field is typed as list with no element type annotation, while scanners field is typed as list[str]. |
| P14-6 | low | design | `src/eedom/detectors/config/config_merge.py:159-171` | _is_config_key() uses substring matching ("port" in "exported") which is overly broad and will match unintended keys |
| P13-10 | low | correctness | `src/eedom/detectors/reliability/cache_eviction.py:95-96` | False negative: The detector checks for @lru_cache() without maxsize, but will miss @lru_cache(maxsize=None) which is semantically unbounded in older Python versions. |
| P12-5 | low | design | `src/eedom/detectors/security/rate_limiting.py:135-143` | Pattern matching uses inconsistent glob implementation instead of shared utility |
| P15-5 | low | design | `src/eedom/plugins/_runners/kube_linter_runner.py:66` | Hardcoded timeout value in error message ignores the timeout parameter. |
| P17-10 | low | correctness | `src/eedom/plugins/blast_radius.py:68-73` | BlastRadiusPlugin.run() assumes CodeGraph.stats() always returns a dict with 'symbols' key (line 70), but if CodeGraph is uninitialized or crashes, stats() may return empty dict or raise, causing unhandled exception. |
| P16-5 | low | correctness | `src/eedom/plugins/clamav.py:84-87` | stderr concatenated twice in redundant output parsing. |
| P17-6 | low | design | `src/eedom/plugins/mypy.py:76-94` | _run_mypy() and _run_pyright() are duplicated code paths with nearly identical structure (subprocess.run, timeout handling, JSON parsing logic). Violation of DRY; makes future bug fixes require changes in two places. |
| P16-8 | low | correctness | `src/eedom/plugins/scancode.py:56-64` | Timeout error message hardcoded to 60 even though no timeout parameter exists. |

### P02-1 — Dedup key includes advisory_id which may be None, causing unrelated findings to silently collide and disappear.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/normalizer.py:40`  
- **Partition:** P02

**Evidence**

Line 38-45: The dedup logic uses `key = (f.advisory_id, f.category, f.package_name, f.version)`. 
When advisory_id is None (valid for findings from detectors, e.g., EED-019), two distinct 
code smell findings collapse under the same key. The higher-severity one wins (line 42-45), 
but the dedup is silent and incorrect — they should not deduplicate at all.

Per models.py line 137: `advisory_id: str | None = None` — advisory_id is nullable.
Per EED-019 detector: This exact pattern is flagged as a reliability issue in production code.

**Fix**

Use `advisory_id or ""` to ensure None advisory_ids produce distinct keys. 
Change line 40 to: `key = (f.advisory_id or "", f.category, f.package_name, f.version)`

**Verdict reason**

Line 40 of normalizer.py uses `key = (f.advisory_id, f.category, f.package_name, f.version)` for deduplication. When advisory_id is None (valid for code-smell findings from detectors like EED-019 per line 137 of models.py), two distinct findings collapse under the same key because None is hashable. The higher-severity one wins (line 42-45), but the dedup is incorrect — unrelated findings should not merge. Using `f.advisory_id or ""` ensures None values produce distinct keys.

### P03-1 — OPA command argument order differs from policy.py, placing --format before data.policy instead of after, breaking CLI parsing.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/opa_adapter.py:65-74`  
- **Partition:** P03

**Evidence**

opa_adapter.py cmd=["opa","eval","-d",policy_path,"-i",tmp.name,"--format","json","data.policy"] vs policy.py cmd=[..., "data.policy","--format","json"]. OPA CLI expects data.policy to come after all flags.

**Fix**

Reorder opa_adapter.py cmd to match policy.py: ["opa", "eval", "-d", policy_path, "-i", tmp.name, "data.policy", "--format", "json"]

**Verdict reason**

opa_adapter.py cmd (lines 65-74) places "--format" before "data.policy", while policy.py cmd (lines 184-193) places "data.policy" before "--format". OPA CLI expects positional arguments after flags, making policy.py's order correct.

### P03-2 — Config merge uses shallow update(), losing rules_enabled defaults when caller passes a rules_enabled dict override.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/opa_adapter.py:107-109`  
- **Partition:** P03

**Evidence**

opa_adapter.py _build_opa_input uses dict.update(input.config) which replaces entire rules_enabled key. policy.py lines 82-85 correctly deep-merge rules_enabled by checking isinstance and merging. If caller passes {"rules_enabled":{"critical_vuln":False}} to disable one rule, opa_adapter will lose all other default rules instead of disabling just that one.

**Fix**

Replace line 109 with proper deep merge like policy.py: if "rules_enabled" in input.config and isinstance(input.config["rules_enabled"], dict), merge rules instead of replace.

**Verdict reason**

Line 109 uses dict.update(input.config) which replaces the entire "rules_enabled" key. If a package config overrides a single rule with {"rules_enabled":{"critical_vuln":False}}, all other default rules are lost instead of merging. Policy.py lines 81-85 correctly implements deep-merge by checking isinstance.

### P01-5 — Exception handler builds ReviewDecision with scan_results variable from outer loop scope, which may be stale if orchestrator.run has not completed or has failed.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/pipeline.py:240-254`  
- **Partition:** P01

**Evidence**

At lines 186-254, the try-except catches exceptions during per-package evaluation. If an exception occurs, lines 241-254 create a fallback ReviewDecision using scan_results (from line 169). However, scan_results is the result of orchestrator.run(repo_path) executed once before the loop. If the orchestrator itself fails (e.g., all scanners timeout or crash), scan_results may be a list of ScanResult.skipped or ScanResult.failed objects, and the fallback decision will reuse this potentially invalid scan data. The decision should use an empty list or a clearly marked "scan data unavailable" indicator instead of reusing outer-loop state.

**Fix**

Initialize an empty scan_results_fallback list before the per-package try-except and use it in the exception handler: scan_results_fallback = [] or a dedicated placeholder. Pass this to the fallback ReviewDecision so the decision reflects that scan data was unavailable during the error.

**Verdict reason**

The finding correctly identifies that the exception handler at lines 239-254 reuses scan_results from line 169, which is the result of orchestrator.run(repo_path) executed before the per-package loop. If an exception occurs during package evaluation (lines 186-238), the fallback ReviewDecision (lines 241-254) uses this scan_results value. However, if orchestrator.run() itself failed or returned skipped/timeout results, those stale results are reused in the fallback decision, which may be misleading about the cause of the error.

### P05-5 — Falsy-value merge bug in load_merged_config causes empty list overrides to fall back to root config

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/repo_config.py:69`  
- **Partition:** P05

**Evidence**

Line 69-70: disabled=pkg_config.plugins.disabled or root_config.plugins.disabled
This uses Python's or operator, which treats empty list [] as falsy. If a package config
explicitly sets disabled: [] (meaning "disable nothing at package level"), the merge
incorrectly falls back to root_config.plugins.disabled because [] evaluates to False.
Example: root has disabled: ["trivy"], package has disabled: [] (override),
but merged result gets ["trivy"] instead of [].
Same bug applies to enabled field on line 69.

**Fix**

Use explicit None checks instead of or: "disabled = pkg_config.plugins.disabled if pkg_config.plugins.disabled is not None else root_config.plugins.disabled"

**Verdict reason**

Lines 69-70 use "or" operator which treats empty list [] as falsy. If package config explicitly sets disabled: [] to override root disabled: ["trivy"], the merge incorrectly falls back to root value because [] evaluates to False. Same bug on enabled field. Requires explicit None checks.

### P05-6 — SemgrepConfig from package-level .eagle-eyed-dom.yaml is completely ignored during merge

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/repo_config.py:68`  
- **Partition:** P05

**Evidence**

In load_merged_config(), the merged PluginConfig is constructed on line 68-71 
with only enabled and disabled fields. The semgrep field defaults to 
SemgrepConfig() (empty lists), completely discarding pkg_config.plugins.semgrep.
If a package provides extra_config_dirs or exclude_rules in its .eagle-eyed-dom.yaml,
they are silently lost during the merge. The docstring (lines 54-59) does not mention
that semgrep config is NOT merged, suggesting this is unintentional.

**Fix**

Merge semgrep config: create merged_semgrep = SemgrepConfig(...) that combines root and package values, then pass it to PluginConfig

**Verdict reason**

Lines 68-71 construct merged_plugins with only enabled/disabled fields. SemgrepConfig defaults to empty SemgrepConfig() on line 31, completely discarding pkg_config.plugins.semgrep. Package-level extra_config_dirs or exclude_rules are silently lost during merge, contradicting the docstring intent.

### P04-1 — Timestamp sorting for seal chain is vulnerable to lexicographic ordering bugs, not RFC3339 temporal ordering.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/seal.py:202`  
- **Partition:** P04

**Evidence**

Line 202: `seals.sort(key=lambda x: x[0], reverse=True)`

The timestamp string x[0] is sorted lexicographically, not by temporal value.
Timestamps in ISO8601/RFC3339 format (e.g., "2026-04-23T14:30:00Z") happen to sort
correctly lexicographically only within a single day and timezone. Across days/zones:
- "2026-04-23T23:59:00+00:00" sorts AFTER "2026-04-24T00:01:00+00:00" (wrong)
- "2026-04-23T14:30:00+05:00" vs "2026-04-23T14:30:00-05:00" produce incorrect order

Test line 202 uses only same-day timestamps, masking the bug. Real runs crossing
day/zone boundaries will select wrong previous_seal_hash, breaking the integrity chain.

**Fix**

Parse timestamp to datetime before sorting:
```python
from datetime import datetime
seals_with_dt = []
for ts, sh in seals:
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        seals_with_dt.append((dt, sh))
    except ValueError:
        continue
if not seals_with_dt:
    return ""
seals_with_dt.sort(key=lambda x: x[0], reverse=True)
return seals_with_dt[0][1]
```

**Verdict reason**

Line 202 sorts timestamps lexicographically using seals.sort(key=lambda x: x[0]). While RFC3339 sorts correctly within days, cross-day and cross-timezone scenarios produce incorrect order (e.g., "2026-04-23T23:59:00Z" sorts after "2026-04-24T00:01:00Z"). This breaks seal chain integrity in CI pipelines crossing day boundaries.

### P10-1 — UnicodeDecodeError not caught when subprocess outputs binary data with text=True

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/subprocess_runner.py:27-43`  
- **Partition:** P10

**Evidence**

Line 27-43:
```python
completed = subprocess.run(
    invocation.cmd,
    capture_output=True,
    text=True,
    cwd=invocation.cwd,
    timeout=invocation.timeout,
    env=invocation.env,
)
```
When text=True, subprocess.run() decodes stdout/stderr as UTF-8. If a tool outputs non-UTF-8 binary data (e.g., binary SBOM, corrupted output), subprocess.run raises UnicodeDecodeError. This is not caught by the existing exception handlers (only TimeoutExpired and FileNotFoundError are caught), so the exception propagates instead of returning a typed ToolResult. This violates the project invariant: "every external call has a timeout; every failure returns a typed result" (CLAUDE.md).

**Fix**

Wrap the subprocess.run() call in an additional except clause for UnicodeDecodeError and OSError, returning a ToolResult with exit_code=-1, with an appropriate error message in stdout or stderr field.

**Verdict reason**

Lines 27-43 use text=True which decodes subprocess output as UTF-8. If a tool outputs invalid UTF-8 (e.g., binary SBOM, corrupted data), subprocess.run() raises UnicodeDecodeError. This exception is not caught by the existing handlers (only TimeoutExpired and FileNotFoundError are caught), violating the fail-open invariant: "every external call has a timeout; every failure returns a typed result."

### P10-2 — get_version() does not handle PackageNotFoundError, causing module import to fail

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/core/version.py:14-16`  
- **Partition:** P10

**Evidence**

Line 14-16:
```python
def get_version() -> str:
    """Return the installed eedom version from importlib.metadata."""
    return importlib.metadata.version("eedom")
```
This function is called at module level in src/eedom/core/renderer.py:27:
```python
_VERSION = get_version()
```
If the "eedom" package is not installed (or not findable by importlib.metadata), importlib.metadata.version() raises PackageNotFoundError. This exception is not caught, causing the entire renderer module (and any module importing it) to fail to load. This is a fail-open violation: the pipeline should degrade gracefully, not crash during initialization.

**Fix**

Catch importlib.metadata.PackageNotFoundError in get_version() and return a sensible default (e.g., "dev" or "unknown") instead of raising.

**Verdict reason**

Line 16 calls get_version() at module level in renderer.py. Line 14-16 in version.py does not catch importlib.metadata.PackageNotFoundError. If "eedom" package is not installed, this raises PackageNotFoundError during module import, crashing the entire renderer module. Violates fail-open: should degrade gracefully, not crash at initialization.

### P14-1 — _is_dangerous_merge() logic is contradictory—returns True on line 134 if unpacking exists, even when config-key check on lines 128-132 finds nothing

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/config/config_merge.py:115-134`  
- **Partition:** P14

**Evidence**

Lines 115-134:
```python
def _is_dangerous_merge(self, node: ast.Dict) -> bool:
    """Check if dict literal with unpacking is a dangerous merge."""
    # Look for {**base, **override} pattern
    has_unpacking = False
    for key in node.keys:
        if key is None:  # None key indicates dict unpacking (**dict)
            has_unpacking = True
            break

    if not has_unpacking:
        return False

    # Check if keys look like config-related
    for key in node.keys:
        if key is not None:
            key_str = self._get_key_name(key)
            if key_str and self._is_config_key(key_str):
                return True

    return has_unpacking  # BUG: always True if any **dict, regardless of config keys
```

Example: `{**base, **override, "host": "localhost"}` will report unpacking=True, skip config-key check (only finds "host"), then unconditionally return has_unpacking=True on line 134. This generates false positives for any dict unpacking, not just config merges dropping telemetry.

**Fix**

Change line 134 from `return has_unpacking` to `return False`—only return True if a config key is found. Or restructure: track whether a config key was seen and only return True in that case.

**Verdict reason**

config_merge.py _is_dangerous_merge() (lines 115-134) returns `has_unpacking` unconditionally on line 134 even if no config key is found. If dict is {**base, **override, "host": "localhost"}, has_unpacking=True, the config-key loop finds nothing, and line 134 returns True regardless. This flags ANY dict unpacking as dangerous, not just config merges.

### P14-4 — Path resolution logic is unreliable—tries relative-to-parent first, then falls back to resolve() with no actual path discovery or existence check before using candidate

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/process/tested_by.py:82-88`  
- **Partition:** P14

**Evidence**

Lines 82-88:
```python
test_path_str = match.group(1)
root = file_path.resolve().parent
candidate = (root / test_path_str).resolve()
if not candidate.is_relative_to(root) or not candidate.exists():
    # Try relative to cwd (repo root)
    candidate = Path(test_path_str).resolve()

if not candidate.exists():  # Only checked again here
```

Problem 1: If test_path_str is absolute (e.g., "/absolute/path/to/tests/file.py"), then `(root / test_path_str)` will resolve to `/absolute/path/to/tests/file.py` (parent is ignored), but the `.is_relative_to(root)` check will fail, incorrectly triggering the fallback.

Problem 2: Line 87 resolves test_path_str with no context (cwd), which may or may not match the repo root depending on where detect() is called from.

Example: annotate file `/repo/src/main.py` with `# tested-by: tests/unit/test_main.py`. If cwd is `/repo`, both attempts work by luck. If cwd is `/tmp`, line 87 resolves to `/tmp/tests/unit/test_main.py` (wrong), and the check passes incorrectly.

**Fix**

Rewrite path resolution to: (1) try `(root / test_path_str).resolve()` if relative; (2) try absolute if starts with `/`; (3) check existence only once. Use Path.is_relative_to() only after ensuring the path was computed from root.

**Verdict reason**

tested_by.py lines 82-92 resolve paths with multiple issues. Line 84 `candidate = (root / test_path_str).resolve()` concatenates relative to parent but does not handle absolute paths—if test_path_str is "/abs/path", pathlib concatenation ignores root and resolves to absolute, making is_relative_to(root) always fail incorrectly. Line 87's fallback Path(test_path_str).resolve() depends on cwd, creating non-deterministic behavior.

### P13-3 — False negative: The _popen_has_communicate_timeout() method has fundamentally broken logic. It looks for communicate() calls anywhere in the tree with timeout, not necessarily tied to the specific Popen call being analyzed.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/reliability/subprocess_timeout.py:132-138`  
- **Partition:** P13

**Evidence**

Lines 136-138 search the entire tree for ANY communicate() call with timeout. If file has: p1 = subprocess.Popen(...) # no timeout on line 10; ... later p2.communicate(timeout=30) on line 50, the detector will return True for p1 even though p1's communicate() has no timeout. This is a scope bug—it matches ANY communicate in the file, not the one related to the specific Popen.

**Fix**

Track the variable name of the Popen call (e.g., p1 = subprocess.Popen(...)) and search only for communicate() calls on that same variable within the same function scope.

**Verdict reason**

subprocess_timeout.py _popen_has_communicate_timeout() (lines 132-139) searches the entire tree (line 136) for ANY communicate() call with timeout via find_function_calls(tree, "*.communicate"). If file has p1 = Popen(...) without timeout on line 10 and p2.communicate(timeout=30) on line 50, the detector returns True for p1 even though p1's communicate lacks timeout. The method should track the variable name (e.g., matching p1.communicate(), not any communicate()).

### P13-4 — False negative: The _is_looped_insert() method has inverted scoping logic. It iterates through ALL nodes and checks if the call is in a loop, but uses ast.walk(parent) which traverses all descendants, making it impossible to verify that a given call is actually inside that specific loop.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/reliability/transaction_rollback.py:127-135`  
- **Partition:** P13

**Evidence**

Lines 127-135. The logic: for parent in ast.walk(func): if isinstance(parent, (For, While)): for child in ast.walk(parent): if child is call. The problem: ast.walk is unordered and includes ALL nested nodes. If there are nested loops, a call could match an inner loop's ast.walk even if the original loop check was on an outer one. The method returns True for ANY loop in the function if the call exists anywhere in the function. It should check if the call is actually a descendant of that specific loop node (use ast.walk on loop, not parent in walk).

lines 129-134 logic is circular—checking if call is descendant of loop by walking the loop body, but already in ast.walk(func), so redundant. Correct approach: for loop in ast.walk(func): if isinstance(loop, (For, While)) and call in ast.walk(loop): return True.

**Fix**

Replace the nested walk with: `for node in ast.walk(func): if isinstance(node, (ast.For, ast.While)) and any(child is call for child in ast.walk(node)):`

**Verdict reason**

transaction_rollback.py _is_looped_insert() (lines 122-135) uses nested ast.walk calls. Line 127 iterates parent in ast.walk(func), then line 129 checks for child in ast.walk(parent). If func has multiple loops, ast.walk is unordered and may match ANY loop in the function when the call exists anywhere, not necessarily inside that specific loop. The logic conflates "loop exists in func" with "call is in this loop."

### P15-4 — NameError when exception handler uses result.returncode but result is not in scope.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/_runners/cfn_nag_runner.py:76`  
- **Partition:** P15

**Evidence**

Line 73-76: The except ValueError clause tries to access result.returncode in the error_msg call, 
but if a ValueError is raised (from _parse_output line 125) on the FIRST iteration of the loop, 
result may not yet be bound. The variable result is scoped to the try block (lines 31-72), 
so line 76 referencing result.returncode will raise NameError. This is a fail-open violation.

**Fix**

Store returncode before the try block, or catch ValueError outside the per-file loop and return early.

**Verdict reason**

Line 76 in cfn_nag_runner.py references result.returncode in except ValueError clause, but result is not in scope if ValueError is raised on first loop iteration.

### P15-1 — Unchecked .fetchone() dereference causes crash when symbol lookup finds no match.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/_runners/graph_builder.py:392`  
- **Partition:** P15

**Evidence**

Line 388-392: self._walk_upstream recursively calls itself, but the recursive call at line 389-392 
does: `.fetchone()["id"]` without null-checking. When a symbol (name, file) pair doesn't exist, 
fetchone() returns None, and None["id"] raises TypeError. In a complex graph with missing 
cross-references or stale metadata, this will crash the blast_radius walk mid-traversal.

**Fix**

Add null-check before dereference. Replace `.fetchone()["id"]` with code like `result = .fetchone(); if result is None: return; result["id"]`

**Verdict reason**

Line 392 in graph_builder.py dereferences .fetchone()["id"] without null-check. When a symbol lookup finds no match, fetchone() returns None and causes TypeError.

### P17-1 — CdkNagPlugin.run() catches all exceptions generically without differentiating timeout/not-installed from other errors, violating fail-open contract that requires specific error handling.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/cdk_nag.py:32-34`  
- **Partition:** P17

**Evidence**

Exception handler at line 33-34 catches Exception, converts to string error, returns PluginResult. Contrast: cfn_nag.py lines 55-70 explicitly handle FileNotFoundError and subprocess.TimeoutExpired with proper error_msg() codes. cdk_nag runner (cdk_nag_runner.py) returns dicts with error messages; plugin doesn't validate structure before accessing .get('error', '').

**Fix**

Split exception handling in CdkNagPlugin.run() to explicitly catch subprocess.TimeoutExpired and FileNotFoundError before the generic Exception handler, returning typed error codes via error_msg().

**Verdict reason**

cdk_nag.py line 33-34 catches all Exception generically without differentiating subprocess.TimeoutExpired or FileNotFoundError. The runner contract expects typed error handling per fail-open design; generic str(exc) violates this.

### P17-4 — LsLintPlugin.run() reports timeout with timeout=0 instead of the actual timeout value (30 seconds), making error messages useless for debugging.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/ls_lint.py:47`  
- **Partition:** P17

**Evidence**

Line 47 calls error_msg(ErrorCode.TIMEOUT, 'ls-lint', timeout=0) instead of timeout=30. Subprocess timeout is 30 seconds at line 36.

**Fix**

Change line 47 to: `error=error_msg(ErrorCode.TIMEOUT, "ls-lint", timeout=30)`

**Verdict reason**

ls_lint.py line 47 passes timeout=0 to error_msg() despite actual subprocess timeout being 30 seconds (line 36). Error message reports "0s" instead of "30s", breaking debuggability.

### P18-1 — Lockfile integrity check has broken variable scope — `manifest_changed` computed in loop but used outside, causing only the last directory's result to be checked instead of all directories.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/supply_chain.py:292-304`  
- **Partition:** P18

**Evidence**

Line 291: `lock_dirs = [d for d, names in changed_dirs.items() if lock in names]`
Lines 292-294: 
  ```python
  for lock_dir in lock_dirs:
      dir_files = changed_dirs.get(lock_dir, set())
      manifest_changed = any(m in dir_files for m in manifests)
  ```
Line 295: `if not manifest_changed:` — used AFTER the loop
When multiple lock_dirs exist (e.g., apps/web/ and apps/api/ both have package-lock.json), only the LAST directory's manifest_changed value is checked. With 2 dirs where first lacks manifest and second has it, the check sees only the second result and skips the finding for the first.

**Fix**

Move the `if not manifest_changed:` block INSIDE the for loop so each lock_dir gets its own finding when the manifest is missing.

**Verdict reason**

supply_chain.py lines 292-304: manifest_changed computed inside loop (line 294) but checked outside loop (line 295). With multiple lock directories, only the last iteration's result is validated; earlier directories' missing manifests are skipped silently.

### P20-1 — WebhookSettings.secret is a required non-Optional field, but _load_app() calls WebhookSettings() without catching MissingConfigError for missing EEDOM_WEBHOOK_SECRET.

- **Severity:** high  
- **Category:** correctness  
- **Location:** `src/eedom/webhook/config.py:24`  
- **Partition:** P20

**Evidence**

Lines 16-26 define secret: str (no default, no Optional); lines 246-247 construct WebhookSettings() and _bootstrap(EedomSettings()) without error handling for missing env vars; pydantic raises ValidationError if required fields are absent.

**Fix**

Either (a) provide a default empty string for secret and validate non-empty in webhook handler, or (b) wrap WebhookSettings() in try-except to catch ValidationError and provide a clear error message, or (c) make secret Optional with a validation check before use.

**Verdict reason**

Line 246 constructs WebhookSettings() without catching ValidationError for missing EEDOM_WEBHOOK_SECRET. If env var is absent, Pydantic raises ValidationError on startup. Error is mitigated by deferred loading (lines 252-265) but still unfriendly.

### P20-2 — Webhook enumerates files via rglob() directly instead of using the file_source seam (FileSourcePort), violating the architectural rule "consumers never call rglob/os.walk/git directly."

- **Severity:** high  
- **Category:** design  
- **Location:** `src/eedom/webhook/server.py:181-189`  
- **Partition:** P20

**Evidence**

Lines 181-189 construct a hardcoded file list with Path.rglob(_ext) + ignore_patterns. CLAUDE.md states "consumers enumerate via the resolved source — never call rglob/os.walk/git directly"; bootstrap.py imports and uses file_source adapters (GitLsFilesSource, WalkFileSource); the webhook bypasses this seam entirely, creating inconsistency.

**Fix**

Import the file source selector from core/file_source.py, call select_file_source(_repo_path), and enumerate via the returned adapter's list_files() method. This ensures consistency with CLI and agent.

**Verdict reason**

Line 187 uses _repo_path.rglob() directly instead of invoking the file_source seam (FileSourcePort). CLAUDE.md explicitly prohibits direct rglob/os.walk calls; webhook violates architectural rule that CLI, agent, and webhook must use consistent file enumeration.

### P20-3 — _extract_reject_from_tool_results() early-returns at line 180 when the first reject is found, preventing examination of subsequent tool results if the agent response structure contains multiple tool invocation results.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/agent/main.py:169-182`  
- **Partition:** P20

**Evidence**

Lines 169-182: when a dict in decisions matches reject/needs_review, the method returns immediately (line 180). If response.value aggregates results from multiple tool calls (evaluate_change, check_package, scan_code), and some tools execute after the first reject-producing tool, those results are never examined. The method name suggests it extracts from tool results (plural), but early return cuts short the iteration.

**Fix**

Refactor to not return early: continue iterating through all decisions to determine if ANY reject exists, only returning after all decisions are examined, or document that response.value is guaranteed to contain results from only the final tool call.

**Verdict reason**

Line 180 returns early on first reject found. If decisions list contains multiple items and a later one also has reject, it's never examined. Method name suggests singular extraction, but skipping subsequent decisions is logically wrong.

### P18-2 — _compute_diff hardcodes "upgraded" when Version parsing fails, ignoring actual version ordering — inconsistent with sbom_diff.py fallback which uses lexicographic comparison.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/core/diff.py:212`  
- **Partition:** P18

**Evidence**

Line 204-212:
  ```python
  try:
      action = "upgraded" if Version(old_ver) < Version(new_ver) else "downgraded"
  except InvalidVersion:
      logger.warning(...)
      action = "upgraded"  # HARDCODED REGARDLESS OF ORDERING
  ```
For non-semver versions (e.g., "2024-01-build" → "2024-02-build"), the exception handler always assigns "upgraded" instead of comparing old_ver < new_ver. This breaks determinism: "old" > "new" lexicographically would be misclassified as upgraded when it's actually a downgrade.

**Fix**

Use lexicographic fallback: `action = "upgraded" if old_ver < new_ver else "downgraded"` (line 145 in sbom_diff.py does this correctly).

**Verdict reason**

diff.py line 212 hardcodes "upgraded" on InvalidVersion exception, ignoring actual version ordering. Inconsistent with sbom_diff.py line 145 which uses lexicographic fallback. Breaks determinism for non-semver packages.

### P18-5 — Both-versions-None case (old_ver is None and new_ver is None) defaults to "upgraded" action but should never occur — indicates the logic path is unreachable or the code is defensive against an impossible condition without documenting why.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/core/diff.py:218`  
- **Partition:** P18

**Evidence**

Line 200-218:
  ```python
  elif old_ver != new_ver:  # Only enters if versions differ
      if old_ver is not None and new_ver is not None:
          ...
      elif old_ver is None and new_ver is not None:
          action = "upgraded"
      elif old_ver is not None and new_ver is None:
          action = "downgraded"
      else:
          action = "upgraded"  # line 218: old_ver is None AND new_ver is None
  ```
The else clause on line 218 is unreachable: if `old_ver != new_ver` is True and both preceding elif conditions are False, then one of the two must be non-None. The hardcoded "upgraded" is dead code or defensive against logic errors; no comment explains the intent.

**Fix**

Either (a) remove the unreachable else clause and add an assertion, or (b) if defensive, add a comment + log explaining why this case should never occur and why "upgraded" is chosen.

**Verdict reason**

diff.py line 218 else clause (both versions None) is unreachable: if old_ver != new_ver is True and first two elif's are False, one must be non-None by logic. Dead code or unexplained defensive pattern with no comment.

### P02-3 — Memo truncation slices at a hard character offset, ignoring line/paragraph boundaries, violating Markdown format.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/core/memo.py:116-117`  
- **Partition:** P02

**Evidence**

Lines 116-117: `memo = memo[: _MAX_MEMO_LENGTH - 20] + "\n\n*[truncated]*"`
This truncates at a raw character position, which can split a word mid-stream or break Markdown 
table/list syntax. The test at test_memo.py:262-283 explicitly expects "truncation at a paragraph 
boundary" and checks that `before_marker.endswith("\n\n")`.

The test comment at line 265-267 states: "Before fix: truncation sliced at a raw character 
offset, which could land mid-word or mid-line. After fix: truncation stops at the last 
paragraph break". The code has not been fixed.

**Fix**

Truncate at the last paragraph boundary before the limit:
```python
if len(memo) > _MAX_MEMO_LENGTH:
    truncated = memo[: _MAX_MEMO_LENGTH - 20]
    # Find the last paragraph break (\n\n) before the limit
    last_para = truncated.rfind("\n\n")
    if last_para > 0:
        truncated = truncated[:last_para]
    memo = truncated + "\n\n*[truncated]*"
```

**Verdict reason**

Line 117 of memo.py truncates at a hard character offset: `memo = memo[: _MAX_MEMO_LENGTH - 20] + "\n\n*[truncated]*"`. This can split words mid-stream or break Markdown syntax. The test at test_memo.py:262-283 explicitly expects truncation at paragraph boundaries (double newline), but the code does not implement this. The code needs to use `rfind("\n\n")` to truncate at the last paragraph break before the limit, as described in the test's "After fix" comment.

### P03-3 — PolicyDecision verdict field expects string enum but constructed with raw string literals, fragile against enum changes.

- **Severity:** medium  
- **Category:** design  
- **Location:** `src/eedom/core/opa_adapter.py:86`  
- **Partition:** P03

**Evidence**

Line 86 returns PolicyDecision(verdict="needs_review") using raw string. PolicyVerdict is an enum (policy_port.py lines 49-55). Should use PolicyVerdict.needs_review to ensure type safety. Same issue at lines 94, 122, 128, 130, 131.

**Fix**

Replace all raw strings with PolicyVerdict enum values: PolicyDecision(verdict=PolicyVerdict.needs_review), etc.

**Verdict reason**

Lines 86, 94, 122, 128, 130, 131 construct PolicyDecision with raw string literals (e.g., "needs_review") instead of using PolicyVerdict enum values. PolicyVerdict is defined as a StrEnum on policy_port.py lines 49-55. Using raw strings breaks type safety and is fragile against enum changes.

### P01-6 — pypi_client.close() is wrapped in contextlib.suppress(Exception), silently swallowing all close errors and preventing visibility into resource-cleanup issues.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/core/pipeline.py:267-270`  
- **Partition:** P01

**Evidence**

Lines 269-270 suppress all exceptions from pypi_client.close(). If the PyPI client holds network connections or file handles and close() fails (e.g., network timeout, file system error), that failure is silently lost. This violates the fail-open principle by converting a potential recoverable close error into an invisible silent failure. The log should record the exception at least at debug level.

**Fix**

Replace contextlib.suppress(Exception) with explicit exception logging: wrap in try/except, log the error at debug or warning level, and continue. E.g., "try: pypi_client.close() except Exception: log.debug('pypi_client_close_failed', ...)"

**Verdict reason**

Lines 269-270 suppress all exceptions from pypi_client.close() with contextlib.suppress(Exception). If the client holds network connections and close() fails (e.g., timeout, network error), that failure is silently lost. This violates fail-open transparency — cleanup errors should be logged at debug level so operators can diagnose resource leaks or connection issues.

### P01-7 — Identical silent close error suppression for pypi_client in evaluate_sbom method mirrors the same transparency loss as in evaluate().

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/core/pipeline.py:432-434`  
- **Partition:** P01

**Evidence**

Lines 433-434 in evaluate_sbom() repeat the contextlib.suppress(Exception) pattern from line 269 in evaluate(). This compounds the visibility issue across both entry points. Resource cleanup failures are invisible to operators.

**Fix**

Apply the same logging-enabled cleanup fix to lines 433-434.

**Verdict reason**

Lines 433-434 in evaluate_sbom() repeat the identical contextlib.suppress(Exception) pattern from line 269 in evaluate(). Same issue as P01-6: resource cleanup failures are invisible. Both locations need explicit exception logging instead of silent suppression.

### P15-7 — Topological sort does not validate that a plugin's depends_on name actually exists; silently drops unknown deps.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/core/registry.py:149`  
- **Partition:** P15

**Evidence**

Lines 54-56 in _topological_sort: When a plugin lists a non-existent dependency in depends_on, 
the line `known_deps = {d for d in p.depends_on if d in by_name}` silently filters it out. 
A typo in a plugin's depends_on (e.g., "opa" vs "ofa") will be accepted but violated, leading to 
silent out-of-order execution. No warning or error is logged.

**Fix**

After building known_deps, compare its length to p.depends_on length and emit a warning if they differ.

**Verdict reason**

Line 55 in registry.py silently filters out unknown dependencies with `{d for d in p.depends_on if d in by_name}` and logs no warning when a plugin typos a dependency name.

### P04-4 — Timestamp precision may not be sufficient for seal uniqueness in rapid successive runs on the same machine.

- **Severity:** medium  
- **Category:** design  
- **Location:** `src/eedom/core/seal.py:94`  
- **Partition:** P04

**Evidence**

Line 94: `"timestamp": datetime.now(UTC).isoformat(),`

datetime.isoformat() without microseconds specified returns seconds precision:
"2026-04-23T14:30:00+00:00" (no fractional seconds by default in Python's isoformat()).

If two runs execute in the same second, they produce identical timestamps.
In find_previous_seal_hash (line 202), lexicographic sort will be unstable:
if run2 and run3 both have timestamp "2026-04-23T14:30:00Z", the sort order is undefined.
The comment at line 181-182 says "most recent one" but doesn't guarantee which one
is returned when timestamps collide.

In a CI pipeline with parallel jobs or rapid re-scans, colliding timestamps could
cause find_previous_seal_hash to return the wrong previous seal, breaking chain integrity.

**Fix**

Include microseconds in timestamp to ensure uniqueness:
```python
"timestamp": datetime.now(UTC).isoformat(timespec="microseconds"),
```
Or store an incrementing sequence number as a tiebreaker in the seal structure.

**Verdict reason**

Line 94 uses datetime.now(UTC).isoformat() without timespec argument, returning second-level precision only. Two runs in the same second produce identical timestamps, and lexicographic sort at line 202 becomes unstable with colliding timestamps, risking wrong previous_seal_hash selection in rapid CI pipelines.

### P10-3 — OSError not caught, violates fail-open invariant for permission/resource errors

- **Severity:** medium  
- **Category:** design  
- **Location:** `src/eedom/core/subprocess_runner.py:54-63`  
- **Partition:** P10

**Evidence**

The except clause at line 54-63 only catches FileNotFoundError:
```python
except FileNotFoundError:
    duration_ms = int((time.monotonic() - start) * 1000)
    return ToolResult(...)
```
However, subprocess.run() can raise other OSError subclasses (PermissionError, IsADirectoryError, etc.) in edge cases. These are not caught and will propagate. CLAUDE.md states "every external call has a timeout; every failure returns a typed result." The design should catch all OSError and its subclasses, not just FileNotFoundError.

**Fix**

Change line 54 from `except FileNotFoundError:` to `except OSError:` to catch all OS-level failures (FileNotFoundError is a subclass of OSError).

**Verdict reason**

Line 54-63 only catches FileNotFoundError, but subprocess.run() can raise other OSError subclasses (PermissionError, IsADirectoryError, etc.). These propagate instead of returning a typed ToolResult. CLAUDE.md states "every external call has a timeout; every failure returns a typed result" — the fix should catch all OSError, not just FileNotFoundError.

### P09-2 — Unsafe pattern: recommendation variable set to None outside conditional, then used in TaskFitAssessment construction only when errors is empty, violating explicit type contract

- **Severity:** medium  
- **Category:** design  
- **Location:** `src/eedom/core/taskfit_validator.py:185-206`  
- **Partition:** P09

**Evidence**

Lines 177-189: recommendation is set to None (line 185) if rec_match is None. Lines 201-206: TaskFitAssessment is constructed with recommendation=recommendation. However, TaskFitAssessment.recommendation (line 57) is typed as `recommendation: Recommendation` not Optional. The logic is correct (early return at line 197 if errors exist, which includes the case where recommendation=None), but the code structure is misleading: the type system suggests recommendation could be None at construction, when in fact the early-return guard makes it impossible. This violates the principle of 'type = precondition'.

**Fix**

Move lines 199-206 (sorted + TaskFitAssessment construction) into an explicit `if not errors:` block to make the type contract explicit in the code structure. Add explicit assertion before construction: `assert recommendation is not None`.

**Verdict reason**

Lines 176-189 set recommendation=None when rec_match is None, then lines 201-206 construct TaskFitAssessment with recommendation=recommendation. The early return at line 197 prevents None from reaching construction when errors exist (which includes the case where recommendation is None). However, the type system at line 57 declares `recommendation: Recommendation` not Optional, creating misleading code structure where the type contract doesn't match the control-flow guarantee.

### P11-3 — BatchVisitor.visit() breaks the standard NodeVisitor contract by calling generic_visit unconditionally, causing nodes to be visited twice.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/ast_utils.py:659-670`  
- **Partition:** P11

**Evidence**

Line 659-670 override visit() to call _run_visitors() then generic_visit(). But ast.NodeVisitor.visit() normally dispatches to visit_<NodeType> if defined; those visit_* methods call generic_visit(). The override at line 659 calls generic_visit() directly, which traverses children. Then visit_Call/visit_FunctionDef/etc. (lines 672-720) also call generic_visit(). So if a registered visitor for "Call" fires, the node's children are visited twice: once via generic_visit() in visit(), once more when visit_Call calls generic_visit(). This breaks determinism and can cause detectors to see duplicate nodes.

**Fix**

Line 670 should be removed; let the visit_* methods handle generic_visit(). Or redesign: call super().visit(node) after _run_visitors() instead of calling generic_visit() directly, to invoke standard dispatch.

**Verdict reason**

BatchVisitor.visit() at line 670 calls generic_visit() unconditionally, bypassing normal ast.NodeVisitor dispatch. This means visit_Call/visit_FunctionDef/etc. (lines 672-720) are never invoked for top-level nodes of those types, causing detectors to miss top-level Call/FunctionDef/ClassDef nodes entirely.

### P14-2 — _PIP_PIN_RE regex requires word boundary after "pip" but not "install", causing false negatives on multi-word situations

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/config/docker_pin_drift.py:18-19`  
- **Partition:** P14

**Evidence**

Lines 18-19:
```python
_PIP_PIN_RE = re.compile(r"pip\s+install\b.*==")
```

The regex matches `pip install` with word boundary after "install", not after "pip". This means:
- `RUN pip install package==1.0` ✓ matches
- `RUN mypip install package==1.0` ✓ INCORRECTLY matches (mypip not pip)
- Variable names like `pip_runner` or `pipeline_setup` containing "pip" followed by whitespace and "install" would match.

The \b is in the wrong position. Should be `r"pip\b\s+install\b.*=="` to anchor both "pip" and "install" as word boundaries.

**Fix**

Change regex to `_PIP_PIN_RE = re.compile(r"pip\b\s+install\b.*==")` or more strictly `r"\bpip\s+install\b.*=="`

**Verdict reason**

docker_pin_drift.py _PIP_PIN_RE regex (line 18) is `r"pip\s+install\b.*=="`. The word boundary \b after "install" means patterns like "mypip install package==1.0" would match because "pip" is followed by whitespace (satisfying the pattern match), while "mypip" is just a substring. The regex should have `\bpip\b` to anchor "pip" as a word, not just a substring.

### P11-2 — DetectorFinding.to_finding() loses line_number and column information, breaking traceability to source code location.

- **Severity:** medium  
- **Category:** design  
- **Location:** `src/eedom/detectors/findings.py:49-69`  
- **Partition:** P11

**Evidence**

DetectorFinding stores line_number (int) and column (int|None) on lines 25-26. Finding model (core.models.Finding) has no line_number or column fields. to_finding() conversion (lines 49-69) maps only detector_id→source_tool, category→FindingCategory, message→description, issue_reference→advisory_id, confidence→confidence. Line and column metadata are silently dropped. This breaks the ability to render findings in SARIF or PR comments with precise source location links.

**Fix**

Either (a) add line_number and column fields to core.models.Finding, or (b) add them to a new fields dict in Finding via a metadata/context field, or (c) return a richer type from to_finding() that preserves detector-specific fields.

**Verdict reason**

DetectorFinding preserves line_number and column (lines 25-26), but to_finding() (lines 49-69) converts only to Finding model, which has no line/column fields. Traceability information is lost in core.models.Finding, breaking precision needed for SARIF/PR rendering.

### P14-3 — _get_high_cardinality_label_kwargs() allows None keyword.arg to pass through, causing potential crash on NoneType comparison

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/metrics/high_cardinality.py:151-159`  
- **Partition:** P14

**Evidence**

Lines 151-159:
```python
def _get_high_cardinality_label_kwargs(self, call: ast.Call) -> list[str]:
    """Get high cardinality label names from .labels() call."""
    high_card_labels = []

    for keyword in call.keywords:
        if self._is_high_cardinality(keyword.arg):  # keyword.arg can be None
            high_card_labels.append(keyword.arg)

    return high_card_labels
```

In Python AST, `keyword.arg` can be None for `**kwargs`-style unpacking (e.g., `metric.labels(**config_dict)`). Line 156 will pass None to _is_high_cardinality(), which calls `label.lower()` on line 163, causing AttributeError.

**Fix**

Add guard on line 156: `if keyword.arg and self._is_high_cardinality(keyword.arg):`

**Verdict reason**

high_cardinality.py _get_high_cardinality_label_kwargs() (lines 151-159) at line 156 calls `if self._is_high_cardinality(keyword.arg)` without checking if keyword.arg is None. In Python AST, keyword.arg is None for **kwargs unpacking (e.g., `metric.labels(**config_dict)`), so passing None to _is_high_cardinality would call label.lower() on None at line 163, causing AttributeError.

### P13-8 — False negative: The detector will miss database checks that use variable names instead of string literals for SQL.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/reliability/health_check_db.py:156`  
- **Partition:** P13

**Evidence**

Lines 168-171. The check `arg_str = self._get_string_content(child.args[0])` only extracts strings if they are ast.Constant nodes. If code is: `query = "SELECT 1"; cursor.execute(query)`, the argument is a Name node (query), not a Constant, so _get_string_content returns None and the check fails. The detector misses this common pattern.

**Fix**

Extend _get_string_content to also track variable assignments or accept that the detector only catches literal SQL strings and document this limitation.

**Verdict reason**

health_check_db.py _has_db_verification() (lines 159-177) at line 169 calls _get_string_content(child.args[0]), which only extracts ast.Constant strings. If code is `query = "SELECT 1"; cursor.execute(query)`, the argument is ast.Name node, not Constant, so _get_string_content returns None and the check fails. The detector misses variable-based SQL queries.

### P13-7 — False negative: The detector will not flag path construction in certain common patterns because the heuristic for identifying "path-related strings" is weak and can be bypassed.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/reliability/path_construction.py:123-136`  
- **Partition:** P13

**Evidence**

Lines 121-136. The _is_path_concatenation() checks: (1) if left or right is a path-related name, or (2) if the string contains "/" or "\\" or ".". The second check is too broad and brittle. Strings like "http://example.com" contain "/" and would be flagged even though they're URLs, not paths. And strings like "user.email" would match because they contain ".", leading to false positives. The method is unreliable.

**Fix**

Use AST-based tracking to see if operands are actually Path objects or strings known to be file paths (e.g., from os.path.join or Path constructor). Or document that URL and other non-path strings may be false positives.

**Verdict reason**

path_construction.py _is_path_concatenation() (lines 121-136) checks line 134-135: strings containing "/" or "\\" or "." are flagged. This will incorrectly flag "http://example.com" (contains "/") and "user.email" (contains ".") as path operations. The heuristic is too loose and conflates URL/attribute access patterns with file path concatenation.

### P12-3 — False negative when GITHUB_OUTPUT reference appears > 3 lines before heredoc

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/security/fixed_output_delimiter.py:84-86`  
- **Partition:** P12

**Evidence**

At lines 84-86, the detector only looks 3 lines back from the heredoc line: `context_start = max(0, i - 4)` captures lines up to line i-1 (since range is exclusive at the end). If a job sets `GITHUB_OUTPUT="/tmp/output"` at line 10, then defines a heredoc at line 15, they're only 5 lines apart. But if the reference is on line 10 and the heredoc is on line 20, they're 10 lines apart. The context window of 3 lines will miss this. The detector will skip the heredoc, creating a false negative. Example: a multi-step job that exports GITHUB_OUTPUT once at the top, then uses it in a heredoc 20 lines later.

**Fix**

Either remove the line-distance heuristic and always check the entire file for GITHUB_OUTPUT/GITHUB_ENV when a heredoc is found, or document this limitation and increase the window to 10+ lines.

**Verdict reason**

At line 84, context_start = max(0, i - 4) limits lookback to 4 lines. If GITHUB_OUTPUT is referenced 10+ lines before the heredoc, it's missed. Real false negative for multi-step workflows that export once at top then use later. Comment and code suggest intentional heuristic but it's still a limitation.

### P12-1 — False negative on secrets assigned without type annotations at module/class scope

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/security/secret_str.py:76-96`  
- **Partition:** P12

**Evidence**

The detector only checks `ast.AnnAssign` nodes (annotated assignments like `api_key: str = "..."`) at lines 76-96. It does NOT check bare `ast.Assign` nodes like `api_key = "hardcoded_secret"` (without a type annotation). This is a false negative: module-level assignments of secret-named variables without annotations are still exposed. Example: `api_key = "my_secret"` at module scope will not trigger a finding because there's no annotation. Tests cover only annotated cases (e.g., line 24 in test_secret_str.py), not bare assignments.

**Fix**

Also scan `ast.Assign` nodes where all targets are Names matching secret patterns. Check if the assignment is at module or class scope (to avoid flagging loop variables). Add tests for bare assignments like `api_key = "secret"`.

**Verdict reason**

Detector only checks ast.AnnAssign nodes (type-annotated assignments) at lines 76-96. Bare ast.Assign nodes like `api_key = "secret"` at module scope are never detected. True false negative for unannotated secret variable assignments.

### P12-6 — Redundant deduplication logic may mask multiple violations on same line

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/security/sql_injection.py:75-76`  
- **Partition:** P12

**Evidence**

At lines 65-73, the detector uses a `seen_lines` set to deduplicate findings by line number. This is intended to avoid reporting the same line multiple times when multiple SQL_EXECUTE_PATTERNS match the same call. However, this means if a line has TWO separate execute calls, each with dangerous formatting, only the first will be reported. Example: `cursor.execute(f"x={x}"); cursor.execute(f"y={y}")` on the same line will only flag the first. This is a correctness issue: the detector reports fewer findings than exist.

**Fix**

Include the column offset or call node id in the dedup key, not just the line number. Or remove the dedup and let find_function_calls() return unique calls only.

**Verdict reason**

seen_lines dedup at lines 65-73 skips all calls on already-seen line numbers. If a line has two cursor.execute() calls, only the first is reported. Correctness bug: multiple violations per line are reduced to one, underreporting actual issues.

### P12-7 — False positive on .format() with no arguments (safe parameterized queries)

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/security/sql_injection.py:117-119`  
- **Partition:** P12

**Evidence**

At lines 116-119, the detector checks if the query argument is a Call node with func.attr == "format". But this flags ANY .format() call on a string, even `"SELECT * FROM users WHERE id = ?".format()` (no arguments). The detector doesn't distinguish between safe and unsafe cases: `"SELECT * FROM users WHERE id = ?".format()` is SAFE (no injection), while `"SELECT * FROM users WHERE id = ?".format(user_id)` is UNSAFE (injects value). The current code at line 118 only checks `func.attr == "format"` without inspecting whether .format() has arguments. An empty .format() on a literal query is harmless but will be flagged as SQL injection.

**Fix**

Check if the .format() call has arguments before flagging. If `call.args or call.keywords` exist, it's injecting values and should be flagged; otherwise, it's safe.

**Verdict reason**

At lines 116-119, detector flags ANY .format() call, even `"SELECT * FROM users".format()` with no arguments (safe). Does not check if call.args or call.keywords exist. False positive on safe parameterized queries called with empty .format().

### P12-8 — False positive on f-strings without interpolation (literal strings)

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/security/sql_injection.py:105-109`  
- **Partition:** P12

**Evidence**

At line 108, `isinstance(query_arg, ast.JoinedStr)` returns True for ANY f-string, including `f"SELECT * FROM users"` (no interpolation). The detector assumes all f-strings are dangerous, but an f-string with no FormattedValue children is just a literal string. Example: `cursor.execute(f"SELECT")` has an f-string but no FormattedValue children and is safe (equivalent to `cursor.execute("SELECT")`). The current code will flag both `f"SELECT {col}"` (dangerous) and `f"SELECT"` (safe).

**Fix**

Check if the JoinedStr node has any FormattedValue children. If it has no interpolation, it's safe and should not be flagged. Only flag f-strings that actually contain formatted values.

**Verdict reason**

At line 108, isinstance(query_arg, ast.JoinedStr) returns True for all f-strings. f"SELECT" with no FormattedValue children is safe (equivalent to literal "SELECT") but will be flagged. Does not check if JoinedStr has any formatted values before flagging.

### P15-3 — Scanned file count double-counts when PMD breaks and fallback processes same files.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/_runners/cpd_runner.py:297`  
- **Partition:** P15

**Evidence**

Lines 280-297: When PMD is unavailable, pmd_missing=True and loop breaks after FileNotFoundError. 
Line 301-303: All by_lang files are then added to fallback. Line 307: scanned += len(fallback), 
counting them twice (once skipped in the PMD loop, once in jscpd). This inflates files_scanned 
metric and violates fail-open semantics (metrics should reflect actual scanning work).

**Fix**

Track two separate counts or add len(files) to scanned before the break at line 297 so double-counting doesn't occur.

**Verdict reason**

Lines 280-307 in cpd_runner.py: files scanned by PMD (line 297) are counted, then added to fallback (lines 302-303) and counted again at line 307, causing double-counting.

### P15-2 — COUNT(*) queries assume rows always exist; will crash on empty database.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/_runners/graph_builder.py:400-403`  
- **Partition:** P15

**Evidence**

Lines 400-403 in stats(): Four COUNT queries use .fetchone()["c"] directly without null-checking. 
Per SQLite docs, COUNT always returns exactly one row, so this is technically safe — but violates 
the pattern established elsewhere in the code (see symbol_at line 342 which does check). 
Defensively, if the connection is corrupt or closed, .fetchone() returns None and crashes.

**Fix**

For consistency and robustness, add guard: `row = self.conn.execute(...).fetchone(); return 0 if row is None else row["c"]`

**Verdict reason**

Lines 400-403 in graph_builder.py use .fetchone()["c"] directly on COUNT queries without null-checking, violating defensive coding pattern seen elsewhere.

### P16-3 — Timeout error message passes 0 instead of actual timeout value.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/clamav.py:69`  
- **Partition:** P16

**Evidence**

Line 69: `error_msg(ErrorCode.TIMEOUT, "clamav", timeout=0)`
Should reference the `timeout` parameter from line 45 (default 120).
Fail-open preserved but error message is incomplete.

**Fix**

Pass actual timeout: `error_msg(ErrorCode.TIMEOUT, "clamav", timeout=timeout)`

**Verdict reason**

Line 69 in clamav.py passes timeout=0 instead of timeout=timeout parameter in error message.

### P17-2 — ComplexityPlugin.run() catches all exceptions generically without differentiating timeout from crashes; hard-coded timeout=60 in runner call is never overridden by config.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/complexity.py:32-35`  
- **Partition:** P17

**Evidence**

Line 33-35 catches Exception, returns generic error. Runner call at line 33 (_run) receives no timeout parameter — defaults to runner's hard-coded 60s (complexity_runner.py:102). No way for config timeout to propagate.

**Fix**

(a) Accept timeout parameter in run() signature matching other plugins (e.g. mypy.py:63, swiftlint.py:84). (b) Pass timeout to _run() call. (c) Explicitly catch subprocess.TimeoutExpired before Exception handler.

**Verdict reason**

complexity.py run() method has no timeout parameter despite complexity_runner.py accepting one (line 102). Hard-coded 60s default cannot be overridden by config; plugin should accept timeout like mypy.py does.

### P17-3 — CpdPlugin.run() catches all exceptions generically; runner call receives no timeout parameter; both error paths return PluginResult but generic Exception case doesn't include error_msg().

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/cpd.py:50-68`  
- **Partition:** P17

**Evidence**

Line 50-68: catches Exception at line 52, returns generic str(exc). Also has a secondary check at 55-58 for data.get('error') which assumes runner returns well-formed dict. Like complexity.py, cpd runner call at line 51 (_run) has no timeout passed.

**Fix**

(a) Accept timeout parameter in signature and pass to _run(). (b) Catch subprocess.TimeoutExpired and FileNotFoundError before Exception. (c) Use error_msg() for consistent error reporting.

**Verdict reason**

cpd.py run() has no timeout parameter and generic Exception handler at line 52. Runner call at line 51 receives no timeout override; hard-coded default cannot be config-driven.

### P17-9 — CspellPlugin.run() relies on contextlib.suppress() to silently ignore JSON/KeyError/TypeError during parsing (line 77), then falls back to regex parsing. If the JSON reporter produces valid JSON but with unexpected schema (e.g. missing 'issues' key in future versions), plugin returns empty findings without logging, violating fail-open with diagnostics.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/cspell.py:54-72`  
- **Partition:** P17

**Evidence**

Lines 77-91 wrap JSON parsing in contextlib.suppress(), catching exceptions silently. If data structure changes, no findings are extracted and no error is logged. Fallback regex (lines 96-112) may or may not capture issues depending on output format. Two parsing paths create inconsistency.

**Fix**

Replace contextlib.suppress() with explicit exception handling that logs the error (structlog) before falling back to regex. This ensures visibility into schema changes.

**Verdict reason**

cspell.py line 77 uses contextlib.suppress() to silently swallow JSON/KeyError/TypeError. If JSON schema changes in future versions, no error is logged; fallback regex may miss issues. Violates visibility into failures.

### P17-5 — KubeLinterPlugin.run() catches all exceptions generically without differentiating error types; runner (kube_linter_runner.py) is a black box whose error structure is unknown, risking silent failures.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/kube_linter.py:29-40`  
- **Partition:** P17

**Evidence**

Line 32-33 catches Exception, converts to string error. Unlike cfn_nag.py which explicitly handles FileNotFoundError/TimeoutExpired at plugin level, kube_linter delegates to runner and trusts it returns valid dict with 'error' key. If runner crashes or returns malformed dict, plugin propagates generic exception.

**Fix**

(a) Add explicit exception handling in plugin for subprocess.TimeoutExpired and FileNotFoundError. (b) Validate runner dict structure before accessing keys. (c) Add logging for unexpected error conditions.

**Verdict reason**

kube_linter.py lines 32-33 catch Exception generically without explicit FileNotFoundError/subprocess.TimeoutExpired handling. Runner structure unknown; no dict validation before accessing keys.

### P16-1 — Timeout error message passes 0 instead of actual timeout value, breaking error diagnostics.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/osv_scanner.py:106`  
- **Partition:** P16

**Evidence**

Line 106: `error_msg(ErrorCode.TIMEOUT, "osv-scanner", timeout=0)`
Should use `timeout=timeout` parameter from line 88.
Fail-open preserved but error message is incorrect.

**Fix**

Change `timeout=0` to `timeout=timeout` to use the actual timeout parameter.

**Verdict reason**

Line 106 in osv_scanner.py passes timeout=0 instead of timeout=timeout parameter in error message.

### P16-6 — Timeout hardcoded to 120 instead of using scanner_timeout from config (60s).

- **Severity:** medium  
- **Category:** design  
- **Location:** `src/eedom/plugins/semgrep.py:59-62`  
- **Partition:** P16

**Evidence**

Lines 59-62: timeout hardcoded to 120 in RULE_RUNNERS.create("semgrep").run()
EedomSettings.scanner_timeout defaults to 60 (core/config.py:73).
Inconsistent with other plugins and CLAUDE.md timeout=60s invariant.

**Fix**

Accept scanner_timeout from EedomSettings or config injection instead of hardcoded 120.

**Verdict reason**

Line 62 in semgrep.py hardcodes timeout=120 instead of using EedomSettings.scanner_timeout (default 60s), inconsistent with CLAUDE.md timeout invariant.

### P16-2 — Timeout error message passes 0 instead of actual timeout value.

- **Severity:** medium  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/syft.py:69`  
- **Partition:** P16

**Evidence**

Line 69: `error_msg(ErrorCode.TIMEOUT, "syft", timeout=0)`
The `timeout=120` hardcoded at line 60 should be referenced in error message.
Fail-open preserved but error message is incomplete.

**Fix**

Pass the hardcoded timeout value: `error_msg(ErrorCode.TIMEOUT, "syft", timeout=120)`

**Verdict reason**

Line 69 in syft.py passes timeout=0 instead of the hardcoded 120 in error message.

### P20-6 — main() does not validate pr_number > 0 after conversion, allowing pr_number=0 to reach GatekeeperAgent.run() which uses it in API calls, potentially causing silent failures or incorrect routing.

- **Severity:** low  
- **Category:** correctness  
- **Location:** `src/eedom/agent/main.py:238-271`  
- **Partition:** P20

**Evidence**

Lines 242-245: pr_number is converted via int() and checked == 0 to raise an error. However, if conversion succeeds but pr_number is negative or invalid (e.g., pr_number=-1), no error occurs. Line 261 passes the unchecked value to agent.run(). GitHub PR numbers are always positive; a negative or zero value should trigger an error.

**Fix**

Change line 243 to `if pr_number <= 0:` or add a validation guard in GatekeeperAgent.run() to reject invalid pr_number values before use.

**Verdict reason**

Line 243 checks pr_number == 0 but not pr_number < 0. Negative values (e.g., -1) bypass validation and reach agent.run(). Should validate pr_number > 0 instead.

### P09-3 — Severity bucket counts computed via three separate iterations over blocked list, O(3n) instead of O(n)

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/actionability.py:37-39`  
- **Partition:** P09

**Evidence**

Lines 37-39: `crit_high_blocked = sum(1 for f in blocked if ...)` (line 37 iterates), `crit_blocked = sum(1 for f in blocked if ...)` (line 38 iterates), `high_blocked = sum(1 for f in blocked if ...)` (line 39 iterates). Each generator expression iterates the entire blocked list independently, making this O(3n) when a single pass with counters is O(n).

**Fix**

Refactor to single iteration: `crit_blocked = high_blocked = 0; crit_high_blocked = len(blocked); for f in blocked: if f.get('severity') == 'critical': crit_blocked += 1; elif f.get('severity') == 'high': high_blocked += 1; crit_high_blocked = crit_blocked + high_blocked`.

**Verdict reason**

Lines 37-39 iterate the blocked list three times independently: each generator expression `sum(1 for f in blocked if ...)` walks the entire list. This is O(3n) when a single pass with counters would be O(n). While lists are typically small, the inefficiency is real and the fix is straightforward.

### P06-3 — Budget exhaustion logs once per enricher per finding, creating excessive log spam when timeout occurs early in multi-finding batch.

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/enrich.py:40`  
- **Partition:** P06

**Evidence**

Lines 39-41:
```python
if time.monotonic() > deadline:
    logger.warning("enrich.budget_exhausted", enricher=getattr(enricher, "name", "?"))
    break
```

When enrichment_timeout is short or a single enricher is slow (e.g., code_graph build), 
the deadline can be exceeded on the first enricher of the first finding. Then for every subsequent 
finding and enricher, this warning fires again. With 100 findings × 2 enrichers and 30s timeout, 
you could see 200 identical warnings.

**Fix**

Track whether we've already logged budget exhaustion for this pass:
```python
budget_exhausted_logged = False
for finding in findings:
    current = finding
    for enricher in enrichers:
        if time.monotonic() > deadline:
            if not budget_exhausted_logged:
                logger.warning("enrich.budget_exhausted", enrichers_remaining=len(enrichers) - enrichers.index(enricher))
                budget_exhausted_logged = True
            break
```
Or log once at the start of the outer loop when budget is detected as exceeded.

**Verdict reason**

Lines 39-41 of enrich.py log "budget_exhausted" on EVERY finding/enricher pair after deadline, not just once. With 100 findings × 2 enrichers, creates ~200 identical log entries. Design issue, not correctness (enrichment still works).

### P10-5 — FakePolicyEngine.evaluate() returns bare verdict string, not DecisionVerdict enum

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/fake.py:24-25`  
- **Partition:** P10

**Evidence**

Line 24-25:
```python
def evaluate(self, input: PolicyInput) -> PolicyDecision:
    return PolicyDecision(verdict="approve")
```
The method returns `PolicyDecision(verdict="approve")` as a string literal. Callers that expect `PolicyDecision.verdict` to be an enum or require strict type checking may break. The project invariant requires "enums for all state fields, never raw strings" (CLAUDE.md). The fake should match real implementation behavior exactly, including type strictness.

**Fix**

Check PolicyDecision model definition and ensure FakePolicyEngine.evaluate() returns the correct type (likely a DecisionVerdict enum or proper constant).

**Verdict reason**

Line 24-25 returns `PolicyDecision(verdict="approve")` as a raw string literal. PolicyDecision.verdict (line 62 of policy_port.py) is typed as `verdict: PolicyVerdict` enum, not a string. The fake should match the real implementation and use `verdict=PolicyVerdict.approve` to satisfy strict type checking. The project CLAUDE.md mandates "enums for all state fields, never raw strings."

### P03-6 — Exception handler catches BLE001 (all exceptions) but logs at error level, contradicting fail-open philosophy.

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/opa_adapter.py:80-86`  
- **Partition:** P03

**Evidence**

Lines 80-86 catch Exception as exc with noqa:BLE001 and log.error(). Fail-open design (CLAUDE.md) says degradations are not errors. Should be log.warning() to match policy.py line 159, which uses log.warning for OPA failures.

**Fix**

Change line 81 from log.error() to log.warning() to align with CLAUDE.md fail-open pattern.

**Verdict reason**

Lines 80-81 catch Exception and call log.error(). CLAUDE.md fail-open philosophy states degradations are not errors. Policy.py line 159 correctly uses log.warning() for OPA failures, making this inconsistent.

### P18-3 — Lexicographic string comparison for non-semver versions yields wrong ordering (e.g., "10" < "2"), creating silent misclassifications. Warning is logged but finding is still emitted with potentially wrong direction.

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/sbom_diff.py:136-145`  
- **Partition:** P18

**Evidence**

Lines 136-145:
  ```python
  def _classify_version_change(old_ver: str, new_ver: str) -> str:
      try:
          return "upgraded" if Version(old_ver) < Version(new_ver) else "downgraded"
      except InvalidVersion:
          logger.warning("version_string_comparison_fallback", ...)
          return "upgraded" if old_ver < new_ver else "downgraded"
  ```
Non-semver versions like "pkg-10" vs "pkg-2" are compared lexicographically: "pkg-10" < "pkg-2" is True, so a downgrade is reported as an upgrade. The warning tells operators there's a fallback but operators cannot tell from the warning which direction is actually wrong.

**Fix**

Either use natural-sort ordering or document that non-semver classification is unreliable; consider adding the direction to the warning event name.

**Verdict reason**

sbom_diff.py line 145 uses lexicographic string comparison ("10" < "2" is True) as fallback for non-semver versions. Warning is logged but finding still emitted with potentially wrong direction. Non-semver classification is unreliable.

### P18-4 — Fail-open on source unavailable embeds error detail only in message string, not as a separate field, making it hard for automated tools to distinguish error types (404 vs timeout vs extraction failure).

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/supply_chain_diff.py:140-150`  
- **Partition:** P18

**Evidence**

Lines 140-150:
  ```python
  if not vd.available:
      return [_finding(..., message=(...f"{{vd.error}}"...),)]
  ```
The error is buried in the `message` field; no structured `error_code` or `error_type` exists in metadata. Downstream tools like GATEKEEPER PR comments or log aggregation systems cannot easily filter by "this was a timeout, please retry" vs "this was a 404, package doesn't exist".

**Fix**

Add `error_type` to metadata with values like "not_found", "timeout", "extract_failed", "network_error", enabling structured error handling.

**Verdict reason**

supply_chain_diff.py lines 140-150 embeds error detail only in message string, not as structured metadata. No error_type field exists; downstream tools cannot distinguish "404 not found" from "timeout" from "extraction failed".

### P01-10 — ReviewResult.results field is typed as bare list with no element type, violating strict Pydantic typing.

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/use_cases.py:45`  
- **Partition:** P01

**Evidence**

Line 44 defines results: list with no element type hint. The comment on line 102 clarifies it holds plugin results, but the type annotation leaves this implicit. This inconsistency weakens type safety and code clarity.

**Fix**

Annotate as results: list[Any] or results: list[dict] (or a specific PluginResult model if that exists) to match project conventions.

**Verdict reason**

Line 44 of use_cases.py defines `results: list` with no element type, inconsistent with the project's typing discipline. The comment mentions it holds plugin results, but no type hint is provided. Should be annotated as `list[Any]`, `list[dict]`, or a specific model type to match project conventions.

### P01-9 — ReviewOptions.categories field is typed as list with no element type annotation, while scanners field is typed as list[str].

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/core/use_cases.py:33-34`  
- **Partition:** P01

**Evidence**

Line 33 defines scanners: list[str] | None with clear element type. Line 34 defines categories: list with no element type. This inconsistency violates the project's type annotation discipline and creates confusion about what categories should contain.

**Fix**

Change line 34 to categories: list[str] | None = None to match the pattern and clarify expected content.

**Verdict reason**

Line 34 of use_cases.py defines `categories: list | None = None` with no element type annotation, while line 33 defines `scanners: list[str] | None = None` with explicit element type. This inconsistency violates the project's strict typing discipline (per CLAUDE.md: "Typed Pydantic models at every boundary"). The categories field should be typed as `list[str] | None`.

### P14-6 — _is_config_key() uses substring matching ("port" in "exported") which is overly broad and will match unintended keys

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/detectors/config/config_merge.py:159-171`  
- **Partition:** P14

**Evidence**

Lines 159-171:
```python
def _is_config_key(self, key: str) -> bool:
    """Check if key looks like a config key."""
    config_keys = (
        "debug",
        "env",
        "environment",
        "host",
        "port",
        "url",
        "endpoint",
        "timeout",
    )
    return any(k in key.lower() for k in config_keys)
```

Example false positives:
- "report" contains "port" → flagged as config key
- "environment_setup" contains "environment" → flagged
- "timeout_handler" contains "timeout" → flagged

The substring check is too loose. Better to use word-boundary matching or an exact match against common patterns.

**Fix**

Use stricter logic: `key.lower() in config_keys` for exact match, or word-boundary regex if allowing partial names.

**Verdict reason**

config_merge.py _is_config_key() (lines 159-171) uses substring matching `any(k in key.lower() for k in config_keys)`. This will incorrectly flag "exported" (contains "port"), "environment_setup" (contains "environment"), and "timeout_handler" (contains "timeout") as config keys, generating false positives. Should use exact match or word-boundary regex.

### P13-10 — False negative: The detector checks for @lru_cache() without maxsize, but will miss @lru_cache(maxsize=None) which is semantically unbounded in older Python versions.

- **Severity:** low  
- **Category:** correctness  
- **Location:** `src/eedom/detectors/reliability/cache_eviction.py:95-96`  
- **Partition:** P13

**Evidence**

Lines 94-96. The check `has_maxsize = any(kw.arg == "maxsize" for kw in decorator.keywords)` only checks for the presence of the keyword, not its value. In Python <3.9, @lru_cache(maxsize=None) means unbounded cache. The detector returns False (no maxsize) if no "maxsize" keyword exists, but doesn't check if maxsize=None, which is also problematic.

Line 95: `has_maxsize = any(kw.arg == "maxsize" for kw in decorator.keywords)`. If decorator is @lru_cache(maxsize=None), then kw.arg == "maxsize" is True, so has_maxsize=True, and the detector returns not has_maxsize = False, so NO finding is raised. But maxsize=None is unbounded! This is a false negative.

**Fix**

Check not only for the presence of maxsize but also ensure its value is not None. Line 95-96: `has_maxsize = any(kw.arg == "maxsize" and self._is_safe_maxsize(kw.value) for kw in decorator.keywords)`, where _is_safe_maxsize checks that the value is a positive constant.

**Verdict reason**

cache_eviction.py _has_unbounded_cache() (line 95) checks `has_maxsize = any(kw.arg == "maxsize" for kw in decorator.keywords)`. If decorator is @lru_cache(maxsize=None), kw.arg == "maxsize" is True so has_maxsize=True, and the detector returns `not has_maxsize = False`, yielding no finding. But maxsize=None is semantically unbounded and should be flagged; the detector should check the value is not None.

### P12-5 — Pattern matching uses inconsistent glob implementation instead of shared utility

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/detectors/security/rate_limiting.py:135-143`  
- **Partition:** P12

**Evidence**

The detector defines RATE_LIMIT_PATTERNS as glob patterns (line 31: `"*limit*", "*throttle*", "*rate*"`) but reimplements glob matching locally in _matches_pattern() (lines 135-143) instead of using the shared `matches_pattern()` utility from ast_utils.py (line 152). The local implementation works for these simple patterns, but this creates a maintenance burden and inconsistency. The codebase has a centralized glob matching function in ast_utils that uses standard fnmatch semantics; duplicate implementations risk divergence.

**Fix**

Use the shared `matches_pattern()` from ast_utils for consistency across all detectors. Replace line 114 `if self._matches_pattern(dec_name, pattern)` with `if matches_pattern(dec_name, pattern)` after importing matches_pattern from ast_utils.

**Verdict reason**

Duplicate glob implementation. ast_utils.py has matches_pattern() (line 142-152) using fnmatch. rate_limiting.py reimplements _matches_pattern() (lines 135-143) with manual string handling. No functional bug, but maintenance burden and inconsistency risk across detectors.

### P15-5 — Hardcoded timeout value in error message ignores the timeout parameter.

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/plugins/_runners/kube_linter_runner.py:66`  
- **Partition:** P15

**Evidence**

Line 66: error_msg(ErrorCode.TIMEOUT, "kube-linter", timeout=60) hardcodes 60, 
but the function parameter is `timeout: int = 60` (line 17). When a caller passes a different 
timeout, the error message will report the wrong value, confusing debugging.

**Fix**

Use the timeout parameter: `error_msg(ErrorCode.TIMEOUT, "kube-linter", timeout=timeout)`

**Verdict reason**

Line 66 in kube_linter_runner.py hardcodes timeout=60 in error message instead of using the timeout parameter, causing incorrect error diagnostics.

### P17-10 — BlastRadiusPlugin.run() assumes CodeGraph.stats() always returns a dict with 'symbols' key (line 70), but if CodeGraph is uninitialized or crashes, stats() may return empty dict or raise, causing unhandled exception.

- **Severity:** low  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/blast_radius.py:68-73`  
- **Partition:** P17

**Evidence**

Line 70: 'if graph.stats()[\"symbols\"] == 0' will KeyError if stats() returns {}. No try/except wraps CodeGraph operations (lines 68-78). CodeGraph is pure Python with SQLite backend; if DB creation fails (line 54-64 writes a test file), fallback to tempdir succeeds, but subsequent graph operations are unchecked.

**Fix**

Wrap CodeGraph operations (index_directory, rebuild_incremental, run_checks) in try/except; validate stats() dict has 'symbols' key before accessing; return PluginResult with error if CodeGraph fails.

**Verdict reason**

blast_radius.py line 70 directly accesses graph.stats()["symbols"] without validating dict structure. If CodeGraph initialization fails and stats() returns {}, KeyError will raise unhandled.

### P16-5 — stderr concatenated twice in redundant output parsing.

- **Severity:** low  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/clamav.py:84-87`  
- **Partition:** P16

**Evidence**

Line 84: `findings = self._parse_output(output + stderr)`
Line 87: `summary_match = _SUMMARY_RE.search(full_output + stderr)`
where `full_output = r.stdout or ""` (line 86).
stderr is already in `output` via line 84 but added again at line 87.

**Fix**

Line 87 should use `full_output` only: `summary_match = _SUMMARY_RE.search(full_output)`

**Verdict reason**

Line 87 in clamav.py adds stderr to full_output again, when stderr was already included in output at line 84, causing redundant stderr parsing.

### P17-6 — _run_mypy() and _run_pyright() are duplicated code paths with nearly identical structure (subprocess.run, timeout handling, JSON parsing logic). Violation of DRY; makes future bug fixes require changes in two places.

- **Severity:** low  
- **Category:** design  
- **Location:** `src/eedom/plugins/mypy.py:76-94`  
- **Partition:** P17

**Evidence**

Lines 76-119 show parallel implementations: both call subprocess.run() with similar timeout/exception handling (lines 82-94 vs 127-139), both parse JSON output, both map severity. Only differences are tool names and command flags. Line 102-103 vs 151-153 both filter by severity=='info'.

**Fix**

Extract common subprocess orchestration into a _run_tool() helper method that accepts (tool_name, cmd, timeout) and returns (stdout, exit_code, error). Both _run_mypy and _run_pyright call it, then handle tool-specific output parsing.

**Verdict reason**

mypy.py lines 76-139 duplicate subprocess orchestration (_run_mypy and _run_pyright) with identical timeout/exception/JSON-parsing patterns. DRY violation increases maintenance burden.

### P16-8 — Timeout error message hardcoded to 60 even though no timeout parameter exists.

- **Severity:** low  
- **Category:** correctness  
- **Location:** `src/eedom/plugins/scancode.py:56-64`  
- **Partition:** P16

**Evidence**

Lines 56-64: subprocess.run called with timeout=60 (hardcoded).
Line 63: error_msg(ErrorCode.TIMEOUT, "scancode", timeout=60)
Unlike other plugins, scancode.run() takes no timeout parameter, making error_msg
hardcoded value misleading if defaults change.

**Fix**

Either parameterize timeout in scancode.run() signature or accept timeout inconsistency is OK for minor plugins.

**Verdict reason**

Line 63 in scancode.py hardcodes timeout=60 in error message. Unlike other plugins, scancode.run() has no timeout parameter, so this is acceptable but inconsistent.

## Uncertain — needs human review

| ID | File:line | Claim | Why uncertain |
|----|-----------|-------|---------------|
| P19-6 | `src/eedom/cli/main.py:400-408` | Diff file path parsing via string split on "b/" is fragile and does not validate against path traversal or symlink escapes before constructing full paths. | Diff parsing via line.split(" b/") is fragile with filenames containing " b/" sequences. However, line 402 validates is_relative_to() which rejects paths escaping repo boundary, mitigating but not eliminating the issue. Proper diff parser would be safer. |
| P03-4 | `src/eedom/core/opa_adapter.py:98-114` | _build_opa_input selects only first package from input.packages list with silent fallback to empty dict, but doesn't validate non-empty. | Line 112 uses input.packages[0] with no validation that the list is non-empty. While the fallback to {} is safe, the silent selection of only the first package when multiple exist is design-questionable and undocumented. Would benefit from explicit validation or logging. |
| P03-5 | `src/eedom/core/policy.py:237-239` | _map_decision logic gates warn->approve_with_constraints on both "raw==approve_with_constraints" AND "(len(deny)==0 and len(warn)>0)", creating redundancy and confusing intent. | Decision logic at lines 257-258 uses OR for two conditions, creating potential ambiguity if OPA returns malformed output (e.g., raw="reject" but deny list is empty). However, actual OPA policy.rego likely prevents this case, making it defense-in-depth uncertainty rather than confirmed bug. |
| P07-1 | `src/eedom/core/review_summary.py:101` | Skipped plugins' findings are incorrectly counted in verdict statistics | Lines 101-102 of review_summary.py increment skipped counter but lack continue, allowing skipped plugins' findings to flow through to counts (lines 104-116). Semantic bug IF skipped plugins carry findings (which shouldn't happen by design). Tests only cover empty findings. Defensive fix warranted but depends on whether skipped-with-findings is possible in practice. |
| P04-2 | `src/eedom/core/telemetry.py:37` | Regex for path detection does not match paths with colons (e.g., Windows `C:\foo`) when preceded by certain characters, and does not handle many valid path formats. | Line 37 regex _FILE_PATH_RE has limited boundary detection. The lookahead class [\s\(\"'] omits commas, backticks, and other delimiters. However, the validator at line 150 is called on truncated stack traces post-processing where paths are already partially sanitized. Real-world impact depends on actual error message formats in telemetry — requires integration testing to confirm. |
| P16-7 | `src/eedom/plugins/trivy.py:48-56` | Timeout handling inconsistent: trivy uses ToolRunnerPort abstraction but osv_scanner/syft use raw subprocess.run directly. | Design inconsistency noted: trivy uses SubprocessToolRunner abstraction, but osv_scanner/syft/clamav use raw subprocess.run. This is architectural, not a fail-open violation or functional bug. |
| P06-2 | `src/eedom/core/llm_client.py:45` | LlmClient creates httpx.Client without context manager or __enter__/__exit__, causing resource leak on exception. | LlmClient lacks __enter__/__exit__ and callers never call close(), but this is acceptable for transient clients without persistent resources (httpx.Client sockets cleaned by GC). Not production-critical since LLM is optional/disabled by default. Defensive practice suggested, not a correctness bug. |
| P04-5 | `src/eedom/core/telemetry.py:112-113` | _strip_paths_from_text() modifies stack_summary but does not validate that stripped result is still privacy-safe. | Validator at line 150 calls _strip_paths_from_text() but doesn't validate the output contains no paths. If regex fails due to P04-2 limitations, unstripped paths leak through. However, this is a validation issue on telemetry (privacy-sensitive) data; real impact depends on regex efficacy and whether telemetry is enabled in practice. |
| P12-4 | `src/eedom/detectors/security/jwt_audience.py:76-103` | Overly conservative false-negative suppression masks potential issues with dynamic payloads | By design, returns True (no finding) when payload is not a dict literal (line 103). Per CLAUDE.md, deterministic analysis is static-only, and comment (line 102) confirms "we only flag known issues." This is intentional conservative strategy, not a bug—whether to flag dynamic payloads is a spec/design question. |
| P15-6 | `src/eedom/plugins/_runners/complexity_runner.py:185` | Duplicate cleanup of radon failures silently suppresses errors that should be logged at warning level. | Radon timeout/missing errors logged at debug level (line 206) rather than warning. This is a logging policy choice, not a fail-open violation; fail-open is preserved. |

## Methodology

- **Partitioning:** `src/eedom` was sharded into 20 partitions (P01–P20), each reviewed independently by a Haiku reviewer agent. The partition map is recorded in the JSON `partitions` array.
- **Challenge pass:** the candidate findings were grouped into 9 challenger batches (batch-01–batch-09). Each Haiku challenger attempted to refute every finding it received and recorded a final verdict and severity.
- **Models:** both the reviewer and the challenger passes ran on Haiku. No dedicated verifier model was used; the challenger pass serves as the verification step.
- **Severity:** when the challenger recorded a final severity it takes precedence over the reviewer's; confirmed findings are ranked high > medium > low, then by file path.
- **Fixtures excluded:** `tests/e2e/fixtures/` holds intentionally pinned old dependencies used as scan-target inputs and is not eedom's own code; it was excluded from the review scope.

### Blind spot

This review is **partitioned**: each reviewer agent saw only one shard of the codebase. That design is strong at finding local, file-scoped defects but **under-covers cross-file and emergent bugs** — defects that only appear when two or more modules interact, contract mismatches that span partition boundaries, and whole-system invariants. Findings that require reasoning across partitions are systematically under-represented here and should be pursued with a complementary whole-system or integration-level review.

