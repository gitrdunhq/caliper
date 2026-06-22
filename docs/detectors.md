# Deterministic Detectors

Caliper ships **21 deterministic bug detectors** (`CAL-001` … `CAL-021`) in
`src/caliper/detectors/`. They complement the 19 scanner plugins: where a plugin shells out
to an external tool or queries an external database (CVEs, licenses, SBOMs), a *detector* is
a small, self-contained, AST-driven rule that flags a specific bug pattern in source you
own. No external binary, no network, no LLM — same input always yields the same finding.

## Detector vs. plugin

| | Detector | Plugin |
|---|----------|--------|
| Input | Source AST / text in this repo | External data (PyPI, CVE/OSV, license corpora) |
| Output | `DetectorFinding` → `Finding` (code-pattern bug) | `Finding` (vuln / license / SBOM metadata) |
| Scope | File-level code rule | Project / dependency level |
| Example | "JWT encoded without an `aud` claim" | "this version of Django has CVE-2024-…" |
| Dependency | Python stdlib `ast` only | a wrapped CLI (osv-scanner, syft, trivy, …) |

Detectors and plugin findings flow into the **same** pipeline: the detector set is exposed
as a single `DeterministicScanner` (`src/caliper/detectors/scanner.py`) implementing
`ScannerPort` with `tool_name="deterministic"`, so the orchestrator runs it in parallel
alongside the plugins, and its findings go through the same normalize → scribe → policy
stages.

## How a detector works

Every detector subclasses `BugDetector` (`src/caliper/detectors/framework.py`) and exposes
five members:

- `detector_id` — the stable `CAL-NNN` id
- `name` — human label
- `category` — a `DetectorCategory` (security, reliability, configuration, process, …)
- `severity` — a `FindingSeverity` (critical / high / medium / low)
- `target_files` — `fnmatch` globs the detector applies to (e.g. `("*.py",)`, `Dockerfile*`)
- `detect(file_path) -> list[DetectorFinding]` — the actual analysis

Guarantees baked into the base class:

- **Fail-safe** — the scanner calls `detect_safe()`, which wraps `detect()` and returns `[]`
  on *any* exception. A buggy detector can never crash a scan or block a build.
- **Suppressible** — a `# noqa: CAL-NNN` comment on the offending line silences exactly that
  detector; `# noqa` with no id silences all of them on that line.
- **Deterministic** — analysis is pure AST/text inspection. Same file, same findings.

Registration and discovery are decorator-driven: `@register_detector`
(`src/caliper/detectors/_registry.py`) adds the class to the `DETECTORS` registry, and
`discover_detectors()` imports every `caliper.detectors.*` subpackage so those decorators fire.
Instances are cached and reused across files.

### AST machinery

Shared helpers live in `src/caliper/detectors/ast_utils.py`: a content-addressed `ASTCache`
(parse each file once, reuse across detectors), plus matchers like `find_function_calls`,
`get_call_name`, `has_decorator`, `find_exception_handlers`, `is_secret_field_name`, and a
`BatchVisitor` for single-pass multi-detector traversal. Python is analyzed via the stdlib
`ast`; YAML / Dockerfile / shell detectors use targeted text + structural parsing.

## The 21 detectors

### Security (8)

| ID | Name | Severity | Catches |
|----|------|----------|---------|
| CAL-001 | JWT Missing Audience Claim | high | `jwt.encode()` payloads with no `aud` claim (token replay across services) |
| CAL-002 | Error Information Exposure | high | exception variables interpolated into response/output strings |
| CAL-003 | API Endpoint Missing Rate Limiting | medium | Flask/FastAPI routes lacking a `@rate_limit`/`@throttle` decorator |
| CAL-004 | Secret Should Use SecretStr | high | Pydantic secret-named fields typed as plain `str` instead of `SecretStr` |
| CAL-005 | SQL Injection via String Formatting | critical | `cursor.execute()` built with f-strings, `%`, or `.format()` |
| CAL-016 | CI Verification Gate Bypass | high | shell scripts that exit `0` when a required GitHub Actions status is absent/null |
| CAL-017 | Presentation Tier Imports Data Tier Directly | medium | files in `agent/`/`cli/` importing `caliper.data.*` (three-tier breach) |
| CAL-020 | Fixed Heredoc Delimiter with GITHUB_OUTPUT/GITHUB_ENV | low | fixed heredoc delimiters writing to GitHub Actions output sinks |

### Reliability (10)

| ID | Name | Severity | Catches |
|----|------|----------|---------|
| CAL-006 | Unbounded Cache Without Eviction | medium | `@cache` / `@lru_cache()` with no `maxsize` |
| CAL-007 | Circuit Breaker Missing Half-Open State | medium | breaker classes with no half-open recovery path |
| CAL-008 | Path String Concatenation | medium | paths built with `+`/f-strings/`%` instead of `pathlib.Path` |
| CAL-009 | Cache Lookup Without Freshness Check | low | cache `.get()` lookups with no TTL/timestamp validation |
| CAL-010 | Batch Insert Without Rollback Handling | medium | `executemany()`/execute loops with no try/except + rollback |
| CAL-011 | Health Check Without Database Verification | medium | `/health`,`/ready`,`/status` endpoints that never touch the DB |
| CAL-012 | Subprocess Call Without Timeout | medium | `subprocess.run/Popen/...` with no `timeout=` |
| CAL-015 | High Cardinality Metric Labels | medium | Prometheus metrics labeled with `user_id`/`request_id`/`email`/uuid |
| CAL-019 | Nullable advisory_id in Dedup Key | low | dedup-key tuples with an unguarded `advisory_id` (None collapses findings) |
| CAL-021 | Non-Atomic File Write | medium | `.write_bytes()/.write_text()` with no `os.rename()`/`.replace()` swap |

### Configuration (2)

| ID | Name | Severity | Catches |
|----|------|----------|---------|
| CAL-013 | Config Merge Dropping Telemetry | low | `{**base, **override}` / `.update()` merges that drop telemetry keys |
| CAL-018 | Dockerfile Pin Drift | medium | hardcoded `pip install pkg==x` or `:latest` image tags (reproducibility drift) |

### Process (1)

| ID | Name | Severity | Catches |
|----|------|----------|---------|
| CAL-014 | Missing Tested-By Annotation | low | source files lacking the `# tested-by: tests/...` annotation |

## Configuration

The detector scanner runs as part of the standard pipeline. Findings carry their
`CAL-NNN` id as `source_tool`, map to the appropriate `Finding` category, and are eligible
for detect-then-scribe (ADR-006) like any other finding — e.g. the `enclosing_symbol`
scribe annotates each with its enclosing function/class.

Suppress a single occurrence inline:

```python
cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")  # noqa: CAL-005
```

## See also

- [`docs/CAPABILITIES.md`](CAPABILITIES.md) — full capability matrix
- [`ARCHITECTURE.md`](../ARCHITECTURE.md) — how the detector scanner plugs into the pipeline
- [`docs/adr/006-detect-then-scribe.md`](adr/006-detect-then-scribe.md) — the scribe seam
- `src/caliper/detectors/` — implementation
