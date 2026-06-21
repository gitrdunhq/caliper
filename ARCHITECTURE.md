# Eagle Eyed Dom — Architecture Reference

## 1. System Overview

Eagle Eyed Dom is a deterministic code and dependency review platform for CI. It
exposes two evaluation paths — a legacy dependency review pipeline and a 19-plugin
review system — both fully fail-open with zero LLM in the decision path.

**Dependency review** (`evaluate` command): when a PR modifies a dependency manifest,
the pipeline detects changed packages, runs vulnerability and license scanners in
parallel, normalizes findings, evaluates them against an OPA policy, assembles a
structured decision, writes a Markdown memo for PR commenting, persists evidence
atomically, seals the evidence bundle with a SHA-256 chain, and appends the decision to
an append-only Parquet audit log.

**Plugin review** (`review` command): runs 19 scanner plugins organized into five
categories (dependency, code, infra, quality, supply_chain) plus the OPA policy
plugin (which always runs last) against a repository or diff. In addition to the
plugins, a `DeterministicScanner` (Section 21) runs 21 AST-based detectors
(EED-001..EED-021) in the same parallel pass. The flow is: file enumeration →
parallel scan (plugins + deterministic detectors) → normalize/dedup (highest
severity wins) → detect-then-enrich (Section 22) → OPA policy/decision → render
(Markdown comment or SARIF v2.1.0) plus evidence/Parquet persistence. Plugins are
discovered automatically, can be filtered by name or category, and each renders its
results via a Jinja2 template. Watch mode (`--watch`) re-runs the review on every
file change.

All failure paths are fail-open: a scanner timeout produces a `ScanResult.skipped`, a
plugin exception returns `PluginResult(error=...)`, an OPA failure produces
`needs_review`, a DB failure falls back to `NullRepository`. Nothing blocks the build.

### Dependency Review Pipeline

```
PR diff / SBOM pair
        |
        v
  DependencyDiffDetector            sbom_diff.diff_sboms()
  (diff.py / sbom_diff.py)
        |
        v
  ReviewRequest list
        |
        +-----> ScanOrchestrator.run()   <-- ThreadPoolExecutor (scanners in parallel)
        |            |  Syft  |  OSV  |  Trivy  |  ScanCode  |
        |            v
        |       list[ScanResult]
        |            |
        +-----> normalize_findings()  (dedup by advisory_id, highest severity wins)
        |            |
        +-----> PyPIClient.fetch_metadata()   (package age, summary)
        |            |
        +-----> OpaEvaluator.evaluate()       (OPA subprocess, input.pkg)
        |            |
        +-----> assemble_decision()
        |            |
        +-----> generate_memo()               (Markdown for PR comment)
        |            |
        +-----> EvidenceStore.store()         (atomic writes)
        |            |
        +-----> append_decisions()            (Parquet audit log)
        |            |
        +-----> create_seal()                 (SHA-256 chain)
        |
        v
  list[ReviewDecision]
  (returned to CLI / Jenkins step)
```

### Plugin Review Pipeline

```
repo path / diff
        |
        v
  get_default_registry()            discover_plugins(plugin_dir)
  (plugins/__init__.py)             (core/registry.py)
        |
        v
  PluginRegistry
        |
        v
  load_repo_config(repo_path)       .eagle-eyed-dom.yaml
  (core/repo_config.py)
        |
        v
  registry.run_all(files, repo,
    disabled_names, enabled_names)
        |
        +-- for each ScannerPlugin:
        |     plugin.can_run(files, repo_path) ?
        |     plugin.run(files, repo_path) -> PluginResult
        |
        +-- opa plugin runs last, receives all findings
        |
        v
  list[PluginResult]
        |
        +-----> render_comment()  OR  to_sarif()
        |       (core/renderer.py)     (core/sarif.py)
        |
        v
  Markdown comment  OR  SARIF v2.1.0 JSON
```


## 2. Three-Tier Architecture

### Presentation — `src/eedom/cli/`

| Module | Responsibility |
|--------|---------------|
| `cli/main.py` | Click CLI entry point. Six commands: `evaluate` (dependency review pipeline), `review` (19-plugin repo review), `query` (DuckDB queries over the Parquet audit log), `check-health` (binary + DB probe), `plugins` (list registered plugins), and `schema` (emit JSON Schema for domain models). Reads diff from file or stdin, constructs the appropriate pipeline or registry, delegates all logic, formats output. Never contains business logic. SARIF output (`--format sarif`) and watch mode (`--watch`) are coordinated here but implemented in `core/sarif.py` and the watchdog observer respectively. |

Imports: `click`, `structlog`, `core.models.OperatingMode`, `core.pipeline.ReviewPipeline`,
`core.config.EedomSettings`, `core.plugin.PluginCategory`, `core.renderer.render_comment`,
`core.sarif.to_sarif`, `core.repo_config.load_repo_config`, `plugins.get_default_registry`.

The CLI catches `Exception` only at the outermost boundary to exit with code 1. Watch mode
exits cleanly on `KeyboardInterrupt` with no stack trace.

#### GATEKEEPER Copilot Agent (`src/eedom/agent/`)

Second presentation-tier entry point (see ADR-001 through ADR-004 in `docs/adr/`).

| Module | Responsibility |
|--------|---------------|
| `config.py` | `AgentSettings` with `GATEKEEPER_` prefix. `EnforcementMode`, GitHub token, Semgrep timeout. |
| `prompt.py` | System prompt: 8-dimension rubric, comment format, Semgrep guidance. |
| `tools.py` | `@tool` functions: `evaluate_change`, `check_package`, `scan_code`. All fail-open. |
| `main.py` | `GatekeeperAgent` orchestrator. Copilot SDK session, PR comments, enforcement. |

The agent catches all exceptions and exits 0 (fail-open). Pipeline failures never block a PR.

### Logic — `src/eedom/core/`

| Module | Responsibility |
|--------|---------------|
| `config.py` | `EedomSettings` — Pydantic `BaseSettings` with `EEDOM_` prefix. Custom `_CommaSeparatedEnvSource` handles comma-separated scanner lists. `SecretStr` for `llm_api_key`. Validates at startup; missing `db_dsn` raises immediately. |
| `models.py` | All domain objects as Pydantic models. Six `StrEnum` types. `ReviewDecision.model_post_init` computes `should_comment` and `should_mark_unstable` from operating mode x verdict. |
| `pipeline.py` | `ReviewPipeline` — stateless per call. Two entry points: `evaluate()` for diff-based (PyPI) and `evaluate_sbom()` for SBOM-based (ecosystem-agnostic). Wires all subsystems together. Enforces per-package pipeline timeout. |
| `pipeline_helpers.py` | Extracted helpers keeping `pipeline.py` under 500 lines: `resolve_git_sha`, `count_transitive_deps_from_scan`, `parse_changes`, `sbom_changes_to_requests`. |
| `orchestrator.py` | `ScanOrchestrator` — parallel execution via `ThreadPoolExecutor`. Combined wall-clock timeout. Returns results in original scanner order. Never raises. |
| `diff.py` | `DependencyDiffDetector` — parses unified diff output; extracts before/after content for `requirements.txt` and `pyproject.toml`; computes added/removed/upgraded/downgraded changes; creates `ReviewRequest` objects. |
| `sbom_diff.py` | `diff_sboms()` — ecosystem-agnostic diffing via CycloneDX SBOMs. purl-based ecosystem detection for 17 ecosystems. `packaging.version.Version` for upgrade vs downgrade classification. |
| `normalizer.py` | `normalize_findings()` — deduplicates vulnerability findings across scanners by `(advisory_id, category, package_name, version)`, highest severity wins. License findings pass through undeduped. Returns merged list + severity summary dict. |
| `policy.py` | `OpaEvaluator` — builds OPA input (`input.pkg`, not `input.package`), invokes `opa eval` subprocess, parses `deny`/`warn`/`decision` from result, maps to `DecisionVerdict`. All failures degrade to `needs_review`. |
| `decision.py` | `assemble_decision()` — pure function that constructs `ReviewDecision` from parts. Zero I/O. |
| `memo.py` | `generate_memo()` — pure function producing Markdown for PR comments. Truncates at 3900 chars. |
| `plugin.py` | `ScannerPlugin` ABC and `PluginCategory` enum. `PluginResult` dataclass. `render()` method with Jinja2 template dispatch and `_render_inline()` fallback. |
| `registry.py` | `PluginRegistry` — register, filter, and run plugins. `discover_plugins()` auto-loads `ScannerPlugin` subclasses from a directory. `run_all()` runs scan plugins first, then the `opa` policy plugin with all aggregated findings. |
| `renderer.py` | `render_comment()` — pure function assembling plugin results into Markdown via `comment.md.j2`. Computes verdict (blocked/incomplete/warnings/clear) and `calculate_severity_score()`. Truncates at 65536 chars. |
| `sarif.py` | `to_sarif()` — pure function converting `list[PluginResult]` to a SARIF v2.1.0 document. One SARIF run per plugin. Severity mapped to SARIF levels. |
| `repo_config.py` | `load_repo_config()` — loads `.eagle-eyed-dom.yaml` from the repo root. Returns `RepoConfig` with `plugins.enabled`, `plugins.disabled`, and `thresholds`. Missing file returns defaults. |
| `taskfit.py` | `TaskFitAdvisor` — optional LLM advisory against 8 dimensions. Structured system/user message separation. Retry loop (up to 2 retries) with rejection guidance on validation failure. |
| `taskfit_validator.py` | `validate_taskfit_response()` — strict regex-based gate. All 8 dimensions required. No partial credit. Returns `ValidationResult` with specific errors for retry guidance. |
| `seal.py` | `create_seal()` / `verify_seal()` / `find_previous_seal_hash()` — SHA-256 integrity chain across evidence runs. |

Imports: `core` modules import only from `core` and `data.scanners.base`. The logic tier has zero knowledge of HTTP frameworks or Click.

### Data — `src/eedom/data/`

| Module | Responsibility |
|--------|---------------|
| `scanners/base.py` | Abstract `Scanner` contract + `run_subprocess_with_timeout()`. Never raises on subprocess errors. |
| `scanners/osv.py` | `OsvScanner` — osv-scanner JSON format. Exit code 1 = findings found (not an error). CVSS vector heuristic for severity when no numeric score. |
| `scanners/trivy.py` | `TrivyScanner` — `trivy fs --format json --scanners vuln`. Maps Trivy severity strings to `FindingSeverity`. |
| `scanners/syft.py` | `SyftScanner` — `syft dir:<path> -o cyclonedx-json`. Produces no findings; writes SBOM to evidence dir. Component count extracted from message. |
| `scanners/scancode.py` | `ScanCodeScanner` — `scancode --license --json-pp`. Maps to `FindingCategory.license` findings with SPDX IDs and confidence scores. |
| `db.py` | `DecisionRepository` (psycopg3 pool, `SET LOCAL statement_timeout`) + `NullRepository` (silent no-op). `RepositoryProtocol` structural protocol. DSN password masking via regex. |
| `evidence.py` | `EvidenceStore` — atomic writes (temp + `os.rename`), path traversal guard (`resolved.is_relative_to`), fail-open on any error. |
| `catalog.py` | `PackageCatalog` — org-wide scan cache. Lookup, upsert, semantic search via pgvector cosine distance, consumer query, lockfile ingestion, scan queue. |
| `parquet_writer.py` | `append_decisions()` — PyArrow append-only Parquet. Flat + list-column schema for DuckDB analytics. |
| `pypi.py` | `PyPIClient` — httpx GET to `pypi.org/pypi/<pkg>/<ver>/json`. Computes `first_published_date` and `package_age_days`. Never raises. |
| `alternatives.py` | Loads `alternatives.json` for `TaskFitAdvisor` approved-alternatives list. |


## 3. Pipeline Flow

Function call chain for `ReviewPipeline.evaluate()` (`pipeline.py:56`):

```
ReviewPipeline.evaluate(diff_text, pr_url, team, mode, repo_path)
  resolve_git_sha(repo_path)                              # pipeline_helpers.py:24
  DependencyDiffDetector.detect_changed_files(diff_text) # diff.py:212
  parse_changes(detector, diff_text, changed_files)      # pipeline_helpers.py:53
    -> detector.extract_file_content_from_diff(...)      # diff.py:169
    -> detector.parse_requirements_diff(before, after)   # diff.py:231
    -> detector.parse_pyproject_diff(before, after)      # diff.py:241
  detector.create_requests(changes, ecosystem, ...)      # diff.py:251

  ScanOrchestrator(scanners, combined_timeout=180).run(repo_path)
                                                         # orchestrator.py:30
    -> ThreadPoolExecutor: scanner.scan(repo_path) x N  # parallel
      OsvScanner.scan() / TrivyScanner.scan()
      SyftScanner.scan() / ScanCodeScanner.scan()        # data/scanners/*.py
    -> ScanResult.skipped() on combined timeout          # orchestrator.py:84

  for req in requests:                                   # per-package loop
    db.save_request(req)                                 # db.py:109
    db.save_scan_results(req.request_id, scan_results)  # db.py:162
    normalize_findings(scan_results)                     # normalizer.py:23
    PyPIClient.fetch_metadata(pkg, version)              # pypi.py:36
    count_transitive_deps_from_scan(scan_results)        # pipeline_helpers.py:40
    OpaEvaluator.evaluate(findings, package_metadata)   # policy.py:105
    db.save_policy_evaluation(...)                       # db.py:206
    assemble_decision(...)                               # decision.py:16
    generate_memo(decision)                              # memo.py:31
    db.save_decision(...)                                # db.py:243
    EvidenceStore.store(run_id, 'pkg/decision.json', .) # evidence.py:43
    EvidenceStore.store(run_id, 'pkg/memo.md', memo)    # evidence.py:43

  append_decisions(evidence_path, decisions, run_id)    # parquet_writer.py:102
  find_previous_seal_hash(evidence_path, run_id)        # seal.py:168
  create_seal(evidence_run_dir, run_id, commit_sha, .)  # seal.py:57
```

For SBOM-based evaluation (`evaluate_sbom()`), `diff_sboms(before, after)` and
`sbom_changes_to_requests()` replace the diff detection step; the rest of the chain
is identical.

`run_id` is `<short_sha>/<YYYYMMDDHHmm>`, e.g. `abc123def012/202604231430`.


## 4. Plugin System

### ScannerPlugin ABC

```python
# core/plugin.py
class ScannerPlugin(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str: ...

    @property
    @abc.abstractmethod
    def description(self) -> str: ...

    @property
    @abc.abstractmethod
    def category(self) -> PluginCategory: ...

    @abc.abstractmethod
    def can_run(self, files: list[str], repo_path: Path) -> bool: ...

    @abc.abstractmethod
    def run(self, files: list[str], repo_path: Path) -> PluginResult: ...

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str: ...
    # Dispatches to Jinja2 template if {name}.md.j2 exists, else _render_inline()
```

`PluginResult` is a dataclass with `plugin_name: str`, `findings: list[dict]`,
`summary: dict`, and `error: str`. All plugin exceptions are caught by the registry;
a failed plugin returns `PluginResult(plugin_name=name, error=str(exc))` and does not
propagate.

`PluginCategory` is a `StrEnum` with five values: `dependency`, `code`, `infra`,
`quality`, `supply_chain`.

The legacy `Scanner` ABC in `data/scanners/base.py` remains in use for the dependency
review pipeline. `ScannerPlugin` is the newer interface for the review system —
both coexist.

### PluginRegistry

`PluginRegistry` (`core/registry.py`) is a thin dict wrapper:

- `register(plugin)` — adds a plugin by name
- `get(name)` — returns a plugin or `None`
- `list(category, names)` — filtered list
- `run_all(files, repo_path, names, categories, disabled_names, enabled_names)` — runs
  all matching plugins

Filtering priority in `run_all()`:
1. `names` and `categories` — positional filter applied first
2. `disabled_names` — matching plugins are skipped
3. `enabled_names` — overrides `disabled_names`; a plugin in both sets will run

The `opa` policy plugin is always deferred to run last. It receives the aggregated
findings from all scan plugins as a `findings` keyword argument via `_run_policy()`.

### Auto-Discovery

`discover_plugins(plugin_dir)` (`core/registry.py:139`) walks `*.py` files in the
plugins directory (skipping `_`-prefixed files), imports each module dynamically, and
instantiates every `ScannerPlugin` subclass found.

`get_default_registry()` (`plugins/__init__.py`) creates a fresh registry and registers
all auto-discovered plugins from `src/eedom/plugins/`.

### All 19 Plugins (+ OPA Policy Plugin)

19 scanner plugins are auto-discovered via `@ANALYZERS.register`, plus the OPA policy
plugin (`OpaPlugin`, `plugins/_opa.py`), which declares `depends_on=["*"]` so it always
runs last with the aggregated findings. (20 `ScannerPlugin` subclasses in total.) The
`opa` row below is listed in its policy role; `OpaPlugin` itself reports the `dependency`
category since `PluginCategory` has no policy value.

| Plugin | Category | Description |
|--------|----------|-------------|
| `osv-scanner` | dependency | Known vulnerability database lookup (OSV/GHSA/CVE) |
| `trivy` | dependency | Vulnerability scanning (Trivy database) |
| `scancode` | dependency | License detection (SPDX expression extraction) |
| `syft` | dependency | SBOM generation — CycloneDX JSON (18 ecosystems) |
| `supply-chain` | supply_chain | Unpinned dependency + lockfile integrity + Docker latest-tag detection |
| `gitleaks` | supply_chain | Secret and credential detection (800+ patterns) |
| `clamav` | supply_chain | Malware/virus scanning (ClamAV) |
| `semgrep` | code | Code pattern analysis — AST matching with dynamic rulesets |
| `cpd` | code | Copy-paste detection — token-based duplication (12 languages) |
| `mypy` | code | Static type checking for Python (type-error findings) |
| `swiftlint` | code | Swift style and convention linting |
| `swiftformat` | code | Swift formatting drift detection |
| `blast-radius` | quality | Code graph impact analysis — AST to SQLite, SQL checks |
| `complexity` | quality | Cyclomatic complexity (Lizard) + maintainability index (Radon) |
| `cspell` | quality | Code-aware spell checking (en-CA, 11 tech dictionaries) |
| `ls-lint` | quality | File naming convention linter |
| `cfn-nag` | infra | CloudFormation security linting (insecure resource patterns) |
| `cdk-nag` | infra | AWS CDK / synthesized-template policy checks |
| `kube-linter` | infra | K8s/Helm security — schema validation, resource limits, privileged containers |
| `opa` | policy | Policy enforcement — 6 Rego rules (deny/warn/approve); runs last via `depends_on=["*"]` |

### Plugin Failure Modes

All plugin failures are caught by the registry. No plugin exception propagates.

| Condition | Result |
|-----------|--------|
| `can_run()` returns False | `PluginResult(summary={"status": "skipped"})` |
| Binary missing (subprocess) | `PluginResult(error=error_msg(NOT_INSTALLED, ...))` |
| Subprocess timeout | `PluginResult(error=error_msg(TIMEOUT, ...))` |
| JSON parse failure | `PluginResult(error=error_msg(PARSE_ERROR, ...))` |
| Unhandled exception in `run()` | `PluginResult(error=str(exc))` via registry |

Error messages are produced by `errors.py:error_msg(ErrorCode, plugin_name, ...)`.
`ErrorCode` is a `StrEnum`: `NOT_INSTALLED`, `TIMEOUT`, `PARSE_ERROR`, `BINARY_CRASHED`.


## 5. Policy Engine

OPA evaluates `policies/policy.rego` via subprocess. Input is serialized to a temp
file and passed with `-i`. The query target is `data.policy`.

### Input Schema

The `build_opa_input()` function (`policy.py:48`) builds:

```json
{
  "findings": [
    { "severity": "high", "category": "vulnerability",
      "advisory_id": "GHSA-...", "package_name": "...", "version": "..." }
  ],
  "pkg": {
    "name": "requests", "version": "2.28.0",
    "ecosystem": "pypi", "scope": "runtime",
    "first_published_date": "2011-07-01T00:00:00+00:00",
    "transitive_dep_count": 5
  },
  "config": {
    "forbidden_licenses": [],
    "max_transitive_deps": 200,
    "min_package_age_days": 90,
    "rules_enabled": { "critical_vuln": true }
  }
}
```

The field is `pkg`, not `package`. `package` is a reserved keyword in Rego (`rego.v1`);
using it as an input field causes a parse error. All OPA rules reference `input.pkg`.

### Rego Rules (`policies/policy.rego`)

| Rule | Type | Trigger |
|------|------|---------|
| `critical_vuln` (deny) | deny | finding.category == "vulnerability" AND severity in {critical, high} |
| `forbidden_license` (deny) | deny | finding.category == "license" AND license_id in config.forbidden_licenses |
| `package_age` (deny) | deny | RFC3339 parse of `input.pkg.first_published_date`; age_days < min_package_age_days |
| `malicious_package` (deny) | deny | advisory_id starts with "MAL-" |
| `medium_vuln` (warn) | warn | finding.severity == "medium" |
| `transitive_count` (warn) | warn | input.pkg.transitive_dep_count > max_transitive_deps |

`decision` defaults to `"approve"`. If `count(deny) > 0` then `"reject"`. If
`count(deny) == 0` and `count(warn) > 0` then `"approve_with_constraints"`.

### Output Parsing (`policy.py:184`)

OPA `--format json` returns:
```json
{"result": [{"expressions": [{"value": {"deny": [], "warn": [], "decision": "..."}}]}]}
```

`_map_decision()` at `policy.py:226`: any `deny` message maps to `reject`; deny=0 and warn>0
maps to `approve_with_constraints`; otherwise `approve`.

On `subprocess.TimeoutExpired`, `FileNotFoundError`, or any other exception, the
evaluator returns `PolicyEvaluation(decision=needs_review, ...)` with a descriptive note.


## 6. LLM Task-Fit Advisory

`TaskFitAdvisor` (`core/taskfit.py`) is optional (`llm_enabled=False` by default).
It queries any OpenAI-compatible `/chat/completions` endpoint.

### 8-Dimension System Prompt

The `_SYSTEM_PROMPT` constant (`taskfit.py:26`) instructs the model to score the package
against:

1. **NECESSITY** — can stdlib or <50 lines replace it?
2. **MINIMALITY** — is this the narrowest dependency for the task?
3. **MAINTENANCE** — last release date, archived status, maintainer count
4. **SECURITY** — signed releases, SECURITY.md, CVE response history
5. **EXPOSURE** — processes untrusted input? handles secrets? internet-facing?
6. **BLAST_RADIUS** — transitive dep count, native extensions
7. **ALTERNATIVES** — approved org alternatives that serve the same purpose
8. **BEHAVIORAL** — install-time code execution, network requests on import

Each dimension is scored `PASS`, `CONCERN`, or `FAIL` followed by one sentence.
A `RECOMMENDATION: [APPROVE|REVIEW|REJECT]` line follows.

### Structured Message Format

Untrusted PyPI summary is passed in the `user` message as JSON, not injected into the
system prompt:

```python
# taskfit.py:166
messages = [
    {"role": "system", "content": _SYSTEM_PROMPT},
    {"role": "user", "content": json.dumps({
        "package": f"{package_name}@{version}",
        "use_case": use_case_text,
        "summary": summary,          # sanitized, max 200 chars
        "approved_alternatives": alternatives,
    })},
]
```

`_sanitize_summary()` at `taskfit.py:105` strips HTML tags, collapses markdown links,
removes special markdown characters, and truncates to 200 characters.

### Validation Gate with Retry

`_call_and_validate()` (`taskfit.py:189`) calls `validate_taskfit_response()` after
each LLM response. If validation fails, a follow-up `user` message appends the exact
errors plus the expected format template. Up to 2 retries. If all retries fail, returns
empty string — the pipeline continues without advisory text.

`validate_taskfit_response()` (`taskfit_validator.py:135`) uses two regexes:
- `_DIM_RE` — matches `DIMENSION: SCORE — rationale` lines
- `_REC_RE` — matches `RECOMMENDATION: VALUE — rationale`

All 8 `REQUIRED_DIMENSIONS` must be present with no duplicates. Missing or duplicate
dimensions produce specific `ValidationError` objects included in retry guidance.


## 7. Decision Framework

### Verdict Mapping

| OPA output | `DecisionVerdict` | `should_comment` (advise) | `should_mark_unstable` (advise) |
|------------|-------------------|--------------------------|----------------------------------|
| deny > 0 | `reject` | true | true |
| deny=0, warn>0 | `approve_with_constraints` | true | false |
| deny=0, warn=0 | `approve` | false | false |
| any OPA failure | `needs_review` | true | true |

`should_comment` and `should_mark_unstable` are computed in `ReviewDecision.model_post_init`
(`models.py:247`) via `_compute_should_comment()` and `_compute_should_mark_unstable()`.
In `monitor` mode both are always `False` — the pipeline logs but never comments or fails the build.

### Operating Modes

- **monitor** — log all decisions, never comment on PRs, never mark unstable.
  Safe for rollout phase; observe traffic without developer impact.
- **advise** — post Markdown memo as PR comment on non-approve verdicts; mark build
  unstable on `reject` or `needs_review`. No `enforce` mode in PoC.

### Package Evaluation Failure

If an unhandled exception occurs during per-package evaluation (`pipeline.py:215`), the
pipeline appends an `ReviewDecision` with `verdict=needs_review`, empty findings, and
`triggered_rules=["package evaluation failed unexpectedly"]`. The pipeline continues to
the next package.


## 8. Evidence System

### Directory Layout

```
<evidence_path>/
  decisions.parquet              <- append-only audit log (all runs)
  <short_sha>/<YYYYMMDDHHmm>/   <- run_id directory
    <package_name>/
      decision.json              <- full ReviewDecision (orjson)
      memo.md                    <- Markdown memo
    seal.json                    <- integrity seal for this run
```

### Atomic Writes

`EvidenceStore.store()` (`evidence.py:43`):
1. `tempfile.mkstemp(dir=dest_dir)` — temp file in same directory (same filesystem)
2. `f.flush()` + `os.fsync(f.fileno())` — force to disk
3. `os.rename(tmp_path, final_path)` — atomic rename (POSIX guarantee)

On any exception the temp file is unlinked and the error is logged; the method returns
empty string. Storage failures never propagate to the pipeline.

### Path Traversal Guard

```python
# evidence.py:53
resolved = (dest_dir / artifact_name).resolve()
if not resolved.is_relative_to(dest_dir.resolve()):
    logger.error("path_traversal_attempt", ...)
    return ""
```

Prevents `artifact_name` values like `../../etc/passwd` from escaping the evidence root.

### Seal Chain

`create_seal()` (`seal.py:57`) processes an evidence run directory:

1. Walk all files under `evidence_dir` (sorted, excluding `seal.json`)
2. SHA-256 hash each file
3. Build manifest string: `"<hash>  <rel_path>\n"` per artifact (sorted)
4. `manifest_hash = sha256(manifest_content)`
5. `seal_hash = sha256(f"{manifest_hash}:{previous_seal_hash}")`
6. Write `seal.json`

`find_previous_seal_hash()` (`seal.py:168`) scans all `seal.json` files in the evidence
root, sorts by `timestamp` descending, returns the `seal_hash` of the most recent prior
run (empty string for the first run).

`verify_seal()` (`seal.py:115`) recomputes all hashes and detects: missing files,
tampered files, manifest_hash mismatch, seal_hash mismatch.


## 9. Org-Wide Catalog

The `package_catalog` table (`migrations/002_package_catalog.sql`) decouples scanning
from PR evaluation. A package scanned once is available to all repos. The `PackageCatalog`
class (`data/catalog.py`) provides the access layer.

### Staleness TTLs

| Scan type | TTL | Constant |
|-----------|-----|----------|
| vuln | 24 hours | `VULN_STALE_HOURS` |
| license | 168 hours (7 days) | `LICENSE_STALE_HOURS` |
| sbom | 168 hours | `SBOM_STALE_HOURS` |

`CatalogEntry.needs_scan()` returns which scan types are stale for a given entry.

### Semantic Search

`package_catalog.description_embedding` is a `vector(1536)` column (OpenAI embedding
dimension). An HNSW index enables fast approximate nearest-neighbor search:

```python
# catalog.py:167
cur.execute("""
    SELECT package_name, ...,
           1 - (description_embedding <=> %s::vector) AS similarity
    FROM package_catalog
    WHERE description_embedding IS NOT NULL
    ORDER BY description_embedding <=> %s::vector
    LIMIT %s
""", (query_embedding, query_embedding, limit))
```

The `<=>` operator is pgvector cosine distance; `1 - distance` = cosine similarity.

### Scan Queue

`scan_queue` tracks packages pending background scanning. Workers pull by
`priority DESC, created_at ASC WHERE status = 'pending'`. `PackageCatalog.queue_scan()`
inserts items; `mark_vuln_stale()` triggers a weekly forced rescan.


## 10. SBOM Diffing

`diff_sboms(before, after)` (`sbom_diff.py:54`) operates on CycloneDX JSON SBOMs
produced by Syft. It works for any ecosystem Syft supports.

### Ecosystem Detection

```python
# sbom_diff.py:135 — _PURL_ECOSYSTEM_MAP
# 17 ecosystems: pypi, npm, maven, golang, cargo, gem, nuget, hex,
#                composer, cocoapods, swift, pub, deb, rpm, apk, oci, docker
```

`_ecosystem_from_purl(purl)` prefix-matches the PURL string against this map.
`component.get("type", "library")` is used as fallback when the PURL is absent.

### Package Key

Each component is keyed as `"{ecosystem}:{name}"`. Components without a `name` field
are skipped.

### Version Classification

`_classify_version_change(old_ver, new_ver)` (`sbom_diff.py:123`) uses
`packaging.version.Version` for comparison. On `InvalidVersion`, falls back to
`"upgraded"` with a structured log warning.

### Output Shape

```python
{"action": "added"|"removed"|"upgraded"|"downgraded",
 "package": str, "ecosystem": str,
 "old_version": str|None, "new_version": str|None, "purl": str|None}
```

`sbom_changes_to_requests()` (`pipeline_helpers.py:77`) converts these to
`ReviewRequest` objects; `removed` changes are skipped.


## 11. Data Model

```mermaid
classDiagram
    class ReviewDecision {
        +UUID decision_id
        +ReviewRequest request
        +DecisionVerdict decision
        +list~Finding~ findings
        +list~ScanResult~ scan_results
        +PolicyEvaluation policy_evaluation
        +str evidence_bundle_path
        +str memo_text
        +bool should_comment
        +bool should_mark_unstable
        +float pipeline_duration_seconds
    }
    class ReviewRequest {
        +UUID request_id
        +RequestType request_type
        +str ecosystem
        +str package_name
        +str target_version
        +str current_version
        +str team
        +str scope
        +str pr_url
        +OperatingMode operating_mode
    }
    class Finding {
        +FindingSeverity severity
        +FindingCategory category
        +str description
        +str source_tool
        +str package_name
        +str version
        +str advisory_id
        +str license_id
        +float confidence
    }
    class ScanResult {
        +str tool_name
        +ScanResultStatus status
        +list~Finding~ findings
        +str raw_output_path
        +float duration_seconds
    }
    class PolicyEvaluation {
        +DecisionVerdict decision
        +list~str~ triggered_rules
        +list~str~ constraints
        +str policy_bundle_version
        +str note
    }
    ReviewDecision --> ReviewRequest
    ReviewDecision --> PolicyEvaluation
    ReviewDecision "1" --> "*" Finding
    ReviewDecision "1" --> "*" ScanResult
    ScanResult "1" --> "*" Finding
```

**Enums:** `OperatingMode` (monitor/advise), `DecisionVerdict` (approve/reject/needs_review/approve_with_constraints), `ScanResultStatus` (success/failed/timeout/skipped), `FindingSeverity` (critical/high/medium/low/info), `FindingCategory` (vulnerability/license/malicious/age/transitive_count/behavioral), `RequestType` (new_package/upgrade).


## 12. Database Schema

### Migration 001 — Core Pipeline Tables

```
review_requests
  PK: request_id (UUID)
  ecosystem, package_name, target_version, current_version
  team, scope, pr_url, pr_number, repo_name, commit_sha, use_case
  operating_mode CHECK IN ('monitor','advise')
  Indexes: (ecosystem, package_name), team, created_at

scan_results
  PK: scan_result_id
  FK: request_id -> review_requests
  tool_name, status, finding_count, duration_seconds, raw_output_path

policy_evaluations
  PK: evaluation_id
  FK: request_id -> review_requests
  policy_version, decision, triggered_rules (JSONB), constraints (JSONB)

review_decisions
  PK: decision_id
  FK: request_id -> review_requests
  decision, findings_summary (JSONB), evidence_bundle_path, memo_text
  pipeline_duration_seconds, operating_mode

bypass_records
  PK: bypass_id
  FK: request_id -> review_requests
  bypass_type CHECK IN ('timeout','manual','kill_switch')
  invoked_by, reason
```

### Migration 002 — Org Catalog + pgvector

```
package_catalog
  PK: catalog_id
  UNIQUE: (ecosystem, package_name, version)
  summary, author, license, source_url
  first_published_at, package_age_days, transitive_dep_count
  description_embedding vector(1536)          <- pgvector semantic search
  sbom_scanned_at, vuln_scanned_at, license_scanned_at
  vuln_finding_count, vuln_max_severity (CHECK)
  license_findings (JSONB)
  latest_decision, latest_decision_at, policy_version
  status CHECK IN ('active','deprecated','restricted','quarantine')
  Indexes: (ecosystem,name,version), vuln_max_severity, status,
           vuln_scanned_at, latest_decision, HNSW embedding

repo_inventory
  UNIQUE: (repo_name, lockfile_path)
  lockfile_hash, updated_at

repo_packages
  PK: (repo_name, ecosystem, package_name, version)
  scope, added_at

scan_queue
  PK: queue_id
  scan_type CHECK IN ('full','vuln_only','rescan')
  priority, status CHECK IN ('pending','processing','completed','failed')
  requested_by, started_at, completed_at
  Index: (priority DESC, created_at ASC) WHERE status='pending'
```

All DDL is idempotent (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`).
Both migrations are wrapped in `BEGIN`/`COMMIT`.


## 13. Fail-Open Contract

Every subsystem failure has an explicit recovery path. Nothing in the pipeline raises
to the caller.

| Component | Failure | Recovery | User-visible effect |
|-----------|---------|----------|---------------------|
| Config load | Missing `EEDOM_DB_DSN` | CLI exits 0 with message | "Pipeline skipped — configuration unavailable" |
| DB connect | `ConnectionPool` fails | Falls back to `NullRepository` | `db_unavailable` log warning; pipeline continues |
| DB query | Any psycopg exception | Exception logged; method returns silently | Decision not persisted in DB |
| Scanner binary missing | `OSError` in subprocess | `ScanResult.not_installed(name)` | Scanner listed as failed in memo |
| Scanner timeout (60s) | `subprocess.TimeoutExpired` | `ScanResult.timeout(name, 60)` | Scanner listed as timeout in memo |
| Combined scanner timeout (180s) | `as_completed` `TimeoutError` | Late scanners -> `ScanResult.skipped` | Skipped scanners listed in memo |
| Plugin binary missing | `OSError` in subprocess | `PluginResult(error=NOT_INSTALLED)` | Plugin listed as error in comment |
| Plugin timeout | `subprocess.TimeoutExpired` | `PluginResult(error=TIMEOUT)` | Plugin listed as error in comment |
| Plugin unhandled exception | Any `Exception` in `run()` | `PluginResult(error=str(exc))` via registry | Plugin listed as error in comment |
| OPA binary missing | `FileNotFoundError` | `PolicyEvaluation(needs_review, note="OPA binary not found")` | PR comment requests manual review |
| OPA timeout (10s) | `subprocess.TimeoutExpired` | `PolicyEvaluation(needs_review, note="OPA evaluation timed out")` | PR comment requests manual review |
| OPA parse error | `KeyError`/`IndexError` | `PolicyEvaluation(needs_review, note=...)` | PR comment requests manual review |
| PyPI request timeout | `httpx.TimeoutException` | `{"available": False, "error": ...}` | `first_published_date=None`; package age rule skipped |
| Evidence write | Any `OSError` | Exception logged; `store()` returns `""` | Evidence not written; pipeline continues |
| Seal creation | Any exception | `logger.exception("seal_creation_failed")` | Run not sealed; pipeline still returns decisions |
| Parquet write | Any exception | `logger.error("parquet_write_failed")` | Audit log not updated for this run |
| Package eval error | Any unhandled exception | `ReviewDecision(needs_review)` appended | One package verdict = needs_review |
| LLM advisory | Any failure | Returns `""` | Advisory omitted from memo |
| Pipeline timeout (300s) | Elapsed >= 300s | Remaining packages skipped, decisions returned | `pipeline_timeout_reached` log warning |


## 14. Security Model

### DSN Credential Masking

`_safe_dsn()` (`db.py:57`) applies a regex substitution before any DSN value is logged:

```python
re.sub(r"://([^:]+):[^@]+@", r"://\1:***@", dsn)
```

`postgresql://user:secret@host/db` becomes `postgresql://user:***@host/db`. All `logger.*`
calls in `db.py` use `_safe_dsn(self._dsn)` instead of the raw DSN.

### SecretStr for LLM API Key

`EedomSettings.llm_api_key` is typed as `SecretStr | None` (`config.py:82`).
Pydantic's `SecretStr` redacts the value in `repr()` and `str()`, preventing accidental
logging. `taskfit.py:243` calls `get_secret_value()` explicitly when building the
Authorization header.

### Path Traversal Guard

`EvidenceStore.store()` and `store_file()` both resolve the candidate path and verify
it remains under `dest_dir` before writing. Any traversal attempt logs
`path_traversal_attempt` and returns `""` without writing.

### LLM Prompt Injection Mitigation

Two layers in `TaskFitAdvisor.assess()` (`taskfit.py:135`):

1. **Structural separation** — PyPI `summary` (untrusted) is placed in the `user` message
   as JSON-encoded data, never interpolated into the `system` message.
2. **Sanitization** — `_sanitize_summary()` strips HTML tags, collapses markdown links,
   removes special markdown characters, and hard-truncates to 200 characters before inclusion.

### SQL Injection

All DB queries in `db.py` and `catalog.py` use parameterized queries with psycopg3
`%s` placeholders. No string concatenation is used for SQL construction except for the
dynamic `SET` clause in `catalog.py:152`, which is built from field names (Python
identifiers, not user input).

### Jenkins Shell Injection

The `evaluate` CLI command takes a `--diff` file path and a `--repo-path` directory.
Neither is passed to a shell — all subprocess calls use list-form `cmd` arguments
(never `shell=True`). The subprocess base utility (`base.py:33`) always uses
`subprocess.run(cmd, ...)` with `shell` defaulting to `False`.


## 15. Plugin Templates (Jinja2)

Each plugin can ship a Jinja2 template at `src/eedom/templates/{plugin_name}.md.j2`.
`ScannerPlugin.render()` (`core/plugin.py:52`) checks for the template file and renders
it with Jinja2 if found, falling back to `_render_inline()` otherwise.

### Template Directory

```
src/eedom/templates/
  comment.md.j2          <- main comment wrapper, composes per-plugin sections
  blast-radius.md.j2
  complexity.md.j2
  kube-linter.md.j2
  semgrep.md.j2
  supply-chain.md.j2
```

### comment.md.j2

`render_comment()` (`core/renderer.py:43`) loads `comment.md.j2` and passes it:

| Variable | Type | Description |
|----------|------|-------------|
| `verdict` | str | `blocked`, `warnings`, `incomplete`, or `clear` |
| `severity_score` | float | 0-100 health score (see Section 16) |
| `summary_rows` | list[tuple] | Per-plugin `(label, count_or_status)` for the summary table |
| `sections` | list[str] | Per-plugin rendered Markdown blocks |
| `file_count` | int | Number of files scanned |
| `repo`, `pr_num`, `title` | str/int | PR metadata |
| `mi_grade`, `mi_score`, `mi_icon` | str/int | Maintainability index from `complexity` plugin |
| `avg_ccn`, `hi_ccn`, `mi_c_count` | float/int | Complexity metrics |
| `footer_stats` | str | Finding counts per plugin, e.g. `"3 semgrep - 1 gitleaks"` |
| `version` | str | Renderer version (`0.1.0`) |

### Verdict Logic

`_build_sections()` (`renderer.py:104`) computes the verdict as it iterates plugins:

- Any finding with severity `critical` or `high` sets verdict to `blocked`
- Any findings without critical/high (and not already `blocked`) sets verdict to `warnings`
- Any plugin with an error (and not already `blocked`) sets verdict to `incomplete`
- No findings, no errors leaves verdict as `clear`

### Per-Plugin Template Context

`ScannerPlugin._template_context()` returns a base dict with `result`, `findings`,
`summary`, `error`, and `plugin_name`. Subclasses override this to inject pre-processed
data (e.g., `BlastRadiusPlugin` adds `findings_by_sev: dict[str, list[dict]]`).

Jinja2 is configured with `autoescape=False`, `trim_blocks=True`, `lstrip_blocks=True`,
and `keep_trailing_newline=True`.


## 16. Severity Rollup

`calculate_severity_score(results)` (`core/renderer.py:28`) computes a 0-100 health
score across all plugin findings.

```
score = max(0, 100 - sum(weight(severity) for each finding))
```

Severity weights:

| Severity | Weight |
|----------|--------|
| critical | 10 |
| high | 5 |
| medium | 2 |
| low | 1 |
| info | 0 |
| unknown | 0 |

100 means no findings (clean). The score reaches 0 with 10 critical findings or 20
high findings. Unknown severity keys map to weight 0 rather than raising.


## 17. Code Knowledge Graph

The `blast-radius` plugin (`plugins/blast_radius.py`) builds an AST-derived call graph
stored in SQLite and runs SQL-based checks against it. No LLM, no external API.

### Graph Builder

`CodeGraph` (`plugins/_runners/graph_builder.py`) manages a SQLite database with four
tables:

| Table | Contents |
|-------|----------|
| `symbols` | Functions, classes, methods, modules with file, line, body_kind, stmt_count |
| `edges` | Directed relationships: `calls`, `imports`, `inherits` with confidence score |
| `checks` | Named SQL queries with severity and description |
| `file_metadata` | mtime + SHA-256 hash per file for incremental rebuild |

Supported languages: Python (full AST via `ast` module), JavaScript/TypeScript (regex-based).

`body_kind` classifies Python function bodies: `noop`, `pass_only`, `return_none`,
`return_input`, `log_only`, `stub`, or `real`.

### Persistence

`CodeGraph(db_path=":memory:")` defaults to in-memory; the `blast-radius` plugin passes
`repo/.eedom/code_graph.sqlite` for persistent storage across runs.

### Incremental Rebuild

`rebuild_incremental(files)` calls `needs_rebuild(file_path)` for each file, which
compares mtime first and falls back to SHA-256 content hash on mtime change. Only
changed files are re-parsed; deleted files are purged via `purge_deleted_files()`.

On the first run (empty `symbols` table), `index_directory(repo_path)` performs a full
walk, skipping `.git`, `__pycache__`, `node_modules`, `.venv`, `.claude`, `.eedom`, and
`.eedom/reports`.

### Built-in SQL Checks

Checks are loaded from `plugins/_runners/checks.yaml` at init. Each check is a named
SQL query with a `{changed_files}` placeholder replaced at runtime.

| Check | Severity | What it detects |
|-------|----------|-----------------|
| `blast_radius_critical` | critical | Symbol with >25 direct dependents |
| `blast_radius_high` | high | Symbol with >10 direct dependents |
| `mock_stub_in_source` | high | Stub/mock pattern in non-test source file |
| `layer_violation` | high | `core/` symbol imports from `data/` (tier violation) |
| `circular_dependency` | medium | Mutual import between two files |
| `high_fan_out` | medium | Function calls >8 other functions (god function) |
| `deep_inheritance` | medium | Class inheritance chain deeper than 3 levels |
| `noop_function` | medium | Function that accomplishes nothing (pass/stub/log-only) |
| `missing_tested_by` | medium | Source file has no `# tested-by:` annotation |
| `srp_high_fan_out_imports` | medium | Module imports from 4+ distinct packages |
| `srp_large_class` | medium | Class has >15 methods |
| `orphan_symbol` | info | Function with zero callers (potential dead code) |

Custom checks can be registered at runtime via `graph.register_check(name, query,
severity, description)`.

### Blast Radius Walk

`graph.blast_radius(symbol_name, max_depth=3)` performs an upstream walk from a symbol,
assigning risk levels: `WILL_BREAK` (depth 1), `LIKELY_AFFECTED` (depth 2),
`MAY_NEED_TESTING` (depth 3), `TRANSITIVE` (beyond).


## 18. SARIF Output

`to_sarif(results, repo_path, max_findings_per_run)` (`core/sarif.py:126`) converts a
`list[PluginResult]` to a SARIF v2.1.0 document.

### Document Structure

One SARIF `run` per `PluginResult`. Each finding maps to one SARIF result.

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "<plugin_name>" } },
      "results": []
    }
  ]
}
```

### Severity Mapping

| Finding severity | SARIF level |
|-----------------|-------------|
| critical, high, error | `error` |
| medium, moderate, warning | `warning` |
| low, info, note | `note` |
| unknown | `note` (safe default) |

### Location Resolution

`_make_locations()` extracts `file`/`path` and `start_line`/`line` from the finding
dict. When `repo_path` is provided, absolute URIs are made relative to it. Findings
without a file field produce no `locations` entry.

### Rule ID Resolution

`_rule_id()` checks finding keys in order: `rule_id`, `advisory_id`, `id`, `check_id`.
Falls back to `plugin_name` if none are present.

### Truncation

When `max_findings_per_run > 0`, findings beyond the cap are replaced with a single
`eedom-truncated` note result indicating how many were omitted.

### CLI Usage

```bash
# Write SARIF to file
uv run eedom review --repo-path . --all --format sarif --output results.sarif

# Pipe to stdout
uv run eedom review --repo-path . --format sarif

# Cap findings per plugin (default: 1000)
uv run eedom review --repo-path . --all --format sarif --sarif-max-findings 500
```

SARIF output is compatible with GitHub's Security tab (`upload-sarif` action) and any
tool that consumes the OASIS SARIF 2.1.0 spec.


## 19. Repo Configuration

`.eagle-eyed-dom.yaml` in the repository root provides per-repo plugin configuration.
The file is optional; absence returns defaults.

### Schema

```yaml
plugins:
  enabled:
    - semgrep
    - gitleaks
  disabled:
    - cspell
    - ls-lint

thresholds:
  complexity:
    max_cyclomatic: 15
```

`RepoConfig` (`core/repo_config.py`) is a Pydantic model:

| Field | Type | Description |
|-------|------|-------------|
| `plugins.enabled` | `list[str] or None` | Plugin names to force-enable |
| `plugins.disabled` | `list[str] or None` | Plugin names to disable |
| `thresholds` | `dict[str, dict]` | Per-plugin threshold overrides (plugin-specific) |

`load_repo_config(repo_path)` reads the file with `yaml.safe_load`, validates it
through `RepoConfig.model_validate()`, and raises `ValueError` on invalid YAML or
schema violations.

### CLI Override

`--disable` and `--enable` flags on the `review` command override the repo config at
runtime:

```bash
# Disable cspell and ls-lint for this run
uv run eedom review --repo-path . --disable cspell,ls-lint

# Force-enable a plugin even if config disables it
uv run eedom review --repo-path . --enable gitleaks
```

`enabled_names` always wins over `disabled_names` within `PluginRegistry.run_all()`.


## 20. Watch Mode

The `review` command supports `--watch` for interactive development workflows.

### Behaviour

```bash
uv run eedom review --repo-path . --watch
```

On startup the review runs once. The command then watches the repository for filesystem
changes and re-runs the review after a 500 ms quiet period.

### Implementation

`_watch_and_rerun()` (`cli/main.py`) uses the `watchdog` library:

- `Observer` monitors the repo path recursively
- `_Handler.on_any_event()` filters by file extension (`_WATCH_EXTENSIONS`:
  `.py`, `.ts`, `.js`, `.tf`, `.yaml`, `.yml`) and ignores `_IGNORE_DIRS`
  (`__pycache__`, `.git`, `.eedom`, `.eedom/reports`)
- `DebounceTimer(delay=0.5)` cancels any pending callback and restarts the timer on
  each matching event; the review fires only after 500 ms of inactivity

`DebounceTimer` uses `threading.Timer` with a `threading.Lock` for thread safety.
The daemon thread is cancelled on `KeyboardInterrupt`.

### Dependency

`watchdog` is required for watch mode. If not installed, the command prints:

```
watchdog is required for --watch mode. Install with: uv add watchdog
```

Watch mode is purely additive — the review command runs identically with or without
`--watch`; the flag only adds the filesystem monitoring loop after the first run.


## 21. Deterministic Detectors

The `src/eedom/detectors/` module provides 21 AST-based bug detectors
(`EED-001`..`EED-021`) that run alongside the scanner plugins. They are
deterministic — the same source always produces the same findings — and require no
subprocess, network, or external binary.

By category: **8 security**, **10 reliability**, **2 configuration**, **1 process**.
The full per-detector reference lives in `docs/detectors.md`; `DetectorCategory`
(`detectors/categories.py`) is a `StrEnum` mapped to `FindingCategory` for scanner
integration.

### Framework and Registry

Every detector subclasses `BugDetector` (`detectors/framework.py`) and declares
`detector_id`, `name`, `category`, `severity`, and `target_files` (default `("*.py",)`).
Detectors register via the `@register_detector` decorator into the `DETECTORS` registry
(`detectors/_registry.py`) and are auto-discovered by `discover_detectors()`.

| Concern | Mechanism |
|---------|-----------|
| Determinism | Pure AST traversal; no I/O in `detect()`; same input → same findings |
| Fail-safe | `detect_safe()` wraps `detect()` and catches all exceptions → `[]` |
| Suppression | `# noqa: EED-XXX` (or bare `# noqa`) on the finding's line skips it |
| Caching | `ASTCache` parses each file once and shares the tree across detectors |

### Pipeline Integration

Detectors are exposed to the pipeline as `DeterministicScanner` (`detectors/scanner.py`,
`tool_name="deterministic"`), which satisfies the core `ScannerPort` structurally
(`name` + `scan`). It enumerates files through the resolved `FileSourcePort`
(Section on file enumeration), runs all applicable detectors per file via the AST cache,
filters suppressed findings, and converts each `DetectorFinding` to the core `Finding`
model. Per ADR-DET-002 a detected bug is a *finding*, not a *failure*: the scanner's
status is always `success`. Per ADR-DET-006 detectors run inside the `review` command's
parallel scan pass rather than a separate `detect` command; `--scanners deterministic`
runs only the detectors.


## 22. Detect-Then-Enrich (ADR-006)

After detection and dedup, but before policy evaluation, findings pass through a
sequential **enrichment** pass that attaches deterministic context to each finding
without changing the verdict. The seam is defined by `EnricherPort` (`applies_to` +
`enrich`), driven by `enrich_findings()` (`core/enrich.py`) with an `EnrichmentContext`,
and backed by the core `ENRICHERS` registry (`core/registries.py`).

Enrichers write only to `metadata['enrichment']`; they never add, drop, or re-rank
findings. The pass runs sequentially (not in the plugin ThreadPool) so shared tool state
— e.g. the CodeGraph — is built once and read without locks.

### Enrichers

| Enricher | Key file | What it adds | Default |
|----------|----------|--------------|---------|
| `enclosing_symbol` | `detectors/enrichers/enclosing_symbol.py` | Enclosing function/class for a finding's line | on |
| `code_graph` | `plugins/enrichers/code_graph.py` | Enclosing symbol + upstream blast-radius callers (capped at 25) | on |
| `semgrep` | `plugins/enrichers/semgrep.py` | Related semgrep matches | opt-in |

`DEFAULT_ENRICHERS = ("enclosing_symbol", "code_graph")` (`core/config.py`); `semgrep`
stays opt-in. Composition happens in `composition/bootstrap.py`: `build_enrichers(settings)`
resolves `settings.enabled_enrichers` against the registry (unknown keys skipped), and
`load_adapters()` fires the registration decorators.

| Concern | Mechanism |
|---------|-----------|
| Fail-open | A raising enricher is logged and skipped; the finding survives unchanged |
| Verdict-independence | Writes only `metadata['enrichment']`; never affects deny/warn/decision |
| Time-bounded | `enrichment_timeout` (30s) budget; on exhaustion remaining enrichers are skipped |
| Determinism | Deterministic context (symbols, callers); no scoring or LLM |


## 23. Webhook Server

`src/eedom/webhook/server.py` is a Starlette ASGI application exposing a single
`POST /webhook` route for GitHub pull-request webhooks. It is a third presentation-tier
entry point (alongside `cli/` and `agent/`) and reuses the same `review_repository`
use-case via the wired `ApplicationContext`.

### Request Handling

| Stage | Behaviour |
|-------|-----------|
| Payload size | Reject > 1 MB with HTTP 413 before any HMAC work (DoS guard) |
| Authentication | HMAC-SHA256 over the raw body; missing/invalid signature → HTTP 401 |
| Content-Type | Must be `application/json`, else HTTP 400 |
| Event routing | Only `pull_request` events with action `opened`, `synchronize`, or `reopened` trigger a review |
| Review | `review_repository` runs in a worker thread under a 300 s `asyncio.wait_for` timeout |
| Comment | Result posted to the PR via the GitHub API; token scrubbed from any error log |

### Config and Fail-Open

Configuration is via `EEDOM_WEBHOOK_*` env vars (`webhook/config.py`, `WebhookSettings`):
the HMAC secret, GitHub token (`SecretStr`), and host/port (default **12800**). The
fail-open contract is explicit: every processing error after authentication is logged and
returns HTTP 200, so a review or comment failure never wedges GitHub's webhook delivery.
The only non-200 responses are authentication (401) and input-validation (400/413)
failures. The production app is built lazily and thread-safely via the module-level `app`
attribute for `uvicorn eedom.webhook.server:app`.


## 24. Composition Root

`src/eedom/composition/bootstrap.py` is the presentation-side composition tier. It is
the one place permitted to import `data` / `adapters` / `plugins` to construct the
core-owned `ApplicationContext`; core depends only on the port *types*, never on this
wiring.

| Function | Responsibility |
|----------|---------------|
| `bootstrap(settings)` | Production wiring — builds the full `ApplicationContext` from `EedomSettings` |
| `load_adapters()` | Imports every adapter module so its `@REGISTRY.register` factories run (idempotent) |
| `build_enrichers(settings)` | Resolves enabled enrichers from the `ENRICHERS` registry (Section 22) |
| `build_scanners` / `build_decision_store` / `build_publisher` / … | Per-adapter factories threading timeouts/paths through registry factories |
| `bootstrap_test()` / `bootstrap_review()` | All-fake / minimal contexts for unit tests and the review command |

Because core may not import across tier boundaries, `load_adapters()` explicitly imports
adapter modules (persistence, GitHub publisher, OPA, PyPI, file source, the enrichers,
graph/semgrep runners, etc.) to populate the registries in `core/registries.py`. Wiring
is fail-open by construction: `build_decision_store()`/`build_decision_repository()` fall
back to `NullRepository`/`NullDecisionStore` when `db_dsn` is unset or the connection
fails, `build_audit_sink()` falls back to `NullAuditSink` without `evidence_path`, and
`build_publisher()` falls back to `NullPublisher` without a GitHub token — so the pipeline
always proceeds regardless of which infrastructure is available.
