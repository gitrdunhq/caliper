# Universal don't-flag prior (ships with the skill — any model, any repo)

These are the false-positive classes EVERY LLM reviewer regresses to — confirmed across
both Haiku and Sonnet arms of the calibration run. Inject this verbatim into every
reviewer and challenger prompt, regardless of model or project. The *project-specific*
ledger (`.eedom/adversarial-ledger.md` or `<repo>/.adversarial-ledger.md`) is the
auto-grown complement; this file is the fixed floor.

A reviewer checks this before emitting a finding. A challenger treats a finding matching
one of these as a likely FALSE_POSITIVE unless the evidence specifically rules the
pattern out.

- A value sourced from config/settings/DI or injected as a parameter is NOT "missing" — trace its origin before reporting absence (a `timeout` set elsewhere, a model/field default, a value passed in by the caller).
- Framework type coercion is NOT a raw-string / wrong-type bug: validating models (Pydantic/StrEnum, schema validators, ORM field types) coerce string/DB values to the right type at the boundary; a field typed as an enum but built from a valid member-name string is fine.
- Parametrized / bound queries (named-param dicts, `?` / `%s` placeholders) are NOT SQL injection; a placeholder repeated and bound once is still correct, and extra keys in a param dict are ignored.
- Intentional fail-open error handling is by design, not a swallowed error: a broad `except`/`catch` that returns a typed degraded result and logs (often lint-suppressed) at a presentation/port tier is a deliberate resilience boundary.
- A field whose declared type constrains its values (e.g. a non-optional list) cannot be the `None`/falsy case a finding assumes — `getattr(x, "f", []) or []` on a list-typed field is not fragile.
- Deliberate asymmetry or documented defaults are design choices: e.g. cancel-without-waiting on timeout vs wait-on-success; a config that passes a subset of fields and lets the rest use defaults.
- A boundary/adapter projecting only the fields the downstream contract needs is NOT "losing metadata" — it's separation of concerns at a port.
- A defensive guard/`except` for an input whose schema is injected or unknown is acceptable, not "dead code"; an "unreachable"/"can't happen" claim must trace the real call sites, not assume.
- `json.dumps()` without `sort_keys` is NOT a determinism bug when the dict is built in fixed order (modern dicts preserve insertion order); `+00:00` vs `Z` for a UTC timestamp is a format choice, not non-determinism, as long as it's consistent.
- A redundant-but-cheap defensive re-check (re-probing availability a caller may not have checked) is a micro-optimization note, not a correctness bug.
- A fetched-but-unused value/column, or a slightly inefficient double pass that is logically gated by a shared decision, is a code smell — not a correctness bug.
- A documented exit-code interpretation (`0=clean, 1=findings, 2=crash`) handled per its comment is correct, not a mis-parse.
- AST/heuristic analyzers with fixed line-windows, supplementary substring allowlists, or "flag the thing that lacks evidence of X" logic are documented trade-offs of the analyzer — judge the analyzer's stated design, not an idealized one.

## Recall backstop — these priors must NOT suppress a real bug

The fail-open / by-design priors above protect against false positives, but in the
calibration run they were *over-applied* and suppressed genuine bugs (the measured recall
cost of grounding). Do NOT let a prior auto-refute these — judge them on their merits:

- **"Fail-open by design" excuses a *broad* except, not a *missing* one.** A finding that a
  specific `read()`/`decode()`/`json.loads()`/subprocess call has **no** surrounding handler
  for a real failure mode (`UnicodeDecodeError`, `OSError`, `JSONDecodeError`, `TimeoutExpired`)
  is a real correctness bug — the absence of a handler is not "intentional fail-open."
- **"Configured/typed value" does not cover an *unbounded* resource.** `lru_cache(maxsize=None)`,
  an unbounded queue/dict, or a missing eviction is a real reliability bug even if the value is typed.
- **A detector false-negative is still a bug.** "The analyzer is a documented trade-off" excuses
  *its heuristics*, not a concrete input it provably fails to flag — if you can exhibit the missed case, confirm it.
- When a prior and the evidence conflict on a *missing handler / absent guard / unbounded resource*,
  prefer UNCERTAIN over FALSE_POSITIVE so a human (or the Opus adjudicator) sees it.
