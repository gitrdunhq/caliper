# Adversarial-review don't-flag ledger

Patterns that LOOK like bugs but usually aren't. Reviewers check this before emitting a
finding; challengers treat a match as a likely FALSE_POSITIVE unless evidence rules it out.
Auto-grown from challenger FALSE_POSITIVE reasons each run.

## Universal (language/framework-agnostic)
- A value sourced from config/settings/DI or injected as a parameter is NOT "missing" — trace its origin before reporting absence.
- Framework type coercion (enums/StrEnum, schema validators, ORM field types) is NOT a raw-string / wrong-type bug.
- Parametrized / bound queries are NOT SQL injection.
- Intentional fail-open error handling (broad except returning a typed degraded result + warning log) is by design.
- A field whose declared type constrains its values (e.g. a non-optional list) cannot be the null/falsy case a finding assumes.
- Deliberate asymmetry or documented defaults are design choices, not defects.

## caliper project-specific (mined from this run)
- A model default on a Pydantic field (e.g. `scope: str = "runtime"`) satisfies "missing field" claims when the upstream dict never carries that key by design — verify the upstream schema before reporting absence.
- Adapter boundary truncation (e.g. `PluginFinding` copying only the fields the policy port contract requires) is a clean port separation, not data loss — check the downstream interface contract before flagging missing fields.
- `or []` / `getattr(..., [])` on a field typed as `list` is not fragile: the falsy case for a proper list is only `[]`, which is valid and intended — only flag when the field can hold non-list falsy values.
- `executor.shutdown(wait=False, cancel_futures=True)` on timeout vs `shutdown(wait=True)` on success is intentional fast-fail asymmetry, not a resource-management inconsistency.
- A `try/except AttributeError` around a `getattr` call is defensive programming at an injection boundary, not dead code — the finding must show the AttributeError is structurally impossible before marking it dead.
- Symlink-escape checks using `resolved.is_relative_to(resolved_root)` (both paths fully resolved) are correct — do not re-flag after `resolve()` has been called on both sides.
- `_ALWAYS_SKIP_DIRS` (walk pruning) and `DEFAULT_PATTERNS` (ignore-layer filtering) are two independent exclusion mechanisms serving different code paths; a pattern absent from one is not necessarily absent from the other.
- Separate concerns in a two-mechanism exclusion stack (e.g. dir-prune + pattern-filter) look redundant but are not — confirm both mechanisms share a code path before reporting fragility.
- `json.dumps()` without `sort_keys` is NOT a determinism bug in Python 3.7+; insertion-order preservation is guaranteed and tests rely on it.
- A broad-except at a presentation-tier renderer that falls back to a default render is fail-open by design (BLE001 pragma is correct) — do not flag as exception swallowing.
- Multiple exit paths returning `None` with different semantic meanings (e.g., "quota OK — no wait needed" vs "header missing") are intentional control flow, not confusing code — read every return site before reporting.
- StrEnum values ARE strings; constructing a dataclass with a string literal that matches a StrEnum member is not a type violation in Python (no runtime coercion occurs at dataclass construction) — only flag if Pydantic validation is bypassed at the actual boundary.
- An `is_available()` guard called redundantly by a direct constructor is a defensive check for callers that bypass the factory; it is a performance micro-concern, not a correctness bug.
- An `except ValueError` block that wraps only `_parse_output()` cannot reference `result` from the preceding `subprocess.run()` call — the variable IS in scope because `subprocess.run()` is outside the try block; verify scoping before reporting.
- A fallback JSON re-parse triggered only when the primary parse returns empty findings is a deliberate dual-reporter pattern, not a spurious re-parse.
- `contextlib.suppress(Exception)` in a plugin runner is NOT automatically a fail-open violation — check whether the suppressed exception is resource cleanup (acceptable) vs a decision-path error (not acceptable).
- Pydantic v2 automatically coerces string values from DB rows to StrEnum fields; passing `row[n]` (a string) to a model field typed as an Enum is NOT a missing-coercion bug.
- Named-parameter dicts passed to psycopg may contain more keys than the query uses; extra keys are ignored and do not cause errors — verify the query placeholders before reporting a parameter mismatch.
- A pure function that builds a local dict and reads it sequentially has no concurrency or mutation risk — confirm shared mutable state exists before reporting a race condition.
- An early `return {}` from a seal/evidence loader when the directory is absent is fail-open "first run" behavior; callers that use `.get()` with a default are safe — confirm callers do not assume a non-empty dict before flagging.
- Exit-code interpretation documented in a comment (e.g. `# 0=clean, 1=violations found, 2=crash`) is self-documenting design, not a missing guard.
- A subprocess plugin distinguishing exit code 1 (tool-reported violations) from crash codes by parsing stderr is correct fail-open handling — do not flag the absence of a generic error return for code 1.
