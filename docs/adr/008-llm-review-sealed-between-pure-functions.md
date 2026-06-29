# ADR-008: Per-part LLM review sealed between two pure functions (`inspect` + `gauge`)

## Status

Accepted

## Context

`caliper review` is fully deterministic by design — no LLM in the decision path. But a
deterministic gate cannot reason about intent: "this refactor silently changes the
error contract," "this lock is taken in the wrong order." Reviewing a whole PR with an
LLM is the obvious move and the wrong one — whole-PR review is noisy and unanchored
(independent benchmarks put single-shot whole-PR precision in the low single digits),
and, more importantly, it would put a model's free-form judgment in front of a human as
if it were a finding.

Two upstream pieces made a disciplined version possible. `caliper part` (the `PARTING`
registry) already cuts a diff into an ordered **cut list** of small, single-purpose
**parts** — each part is a clean, self-contained context window. And the scribe seam
(ADR-006) established the house rule for LLMs in caliper: a model may only ever write
**advisory metadata**, never a verdict.

The requirement: bring an LLM into code review, per part, **without** weakening the
defensible claim. The claim we must preserve is precise — not "no LLM touches review,"
but **"no LLM output reaches a human or a gate except through a deterministic function
you can test."**

A secondary requirement followed: if the LLM keeps surfacing the same advisory issue
across many parts, that recurring pattern should *graduate* into a permanent
deterministic check, so deterministic coverage grows and the LLM is needed for less
over time — an LLM as a **discovery mechanism for deterministic rules**, never as the
rule itself.

## Decision

Add two manual, developer-invoked, advisory commands — `caliper inspect` (per-part
review) and `caliper gauge` (the flywheel) — built so the LLM is **sealed between two
pure functions** and is structurally incapable of entering the decision path.

### `caliper inspect` — three tiers per part

The tiers are named by role, not number (the two deterministic tiers bracket the LLM):

1. **Screen — deterministic gauges (no LLM).** Caliper's existing analyzers / detectors
   / secret scanners, scoped to the part's file set and routed by `ChangeType` bucket;
   produces pass/fail verdicts and `GaugeFinding`s. Fail-closed. A part that fails a hard
   gauge is reported with its review skipped. (`core/inspect_gauges.py`)
2. **Review — advisory LLM (behind a port).** Runs only on parts that clear Screen and
   need judgment (mostly `logic`), behind `LLMPort` (`core/llm_port.py`, the analog of
   `ToolRunnerPort`). It emits structured **claims** — never a verdict, never a gate.
   Sealed, swappable (null / `openai` / `omlx`), and cached on the rendered prompt
   (`core/inspect_runner.py`, `core/inspect_cache.py`, `plugins/_inspect_llm.py`).
3. **Adjudicate — a pure function (no LLM).** `adjudicate()` is a sibling of `part()` —
   no IO, clock, or randomness — that filters claims by rules in firing order: parse,
   scope, anchor (a claim's verbatim `anchor_quote` must be a literal substring of the
   part's changed text before its line numbers are trusted), substantiation (a `blocking`
   claim with no Screen witness is downgraded to advisory, never deleted), category
   allow-list per bucket, severity floor, collapse-into-Screen (drop a non-blocking claim
   that merely corroborates a Screen finding), and dedup. Only survivors reach the report.
   (`core/inspect.py`)

A final **integration pass** runs the same Screen→Review→Adjudicate over the assembled
stock (union of all parts) to catch cross-part defects per-part isolation cannot see.

`part()` upstream and `adjudicate()` downstream are both pure and property-tested; the
LLM is the impure filling, reachable only through `LLMPort`. **Evidence binding is
post-hoc and deterministic** — the model is never asked for caliper rule ids (it would
fabricate them); Adjudicate joins a claim to a Screen finding by (file, line-overlap,
compatible category) and sets `evidence_ref` itself.

### `caliper gauge` — the flywheel (LLM drafts, never decides)

The terminal stage turns recurring advisory claims into permanent Screen gauges:
`propose` clusters the claims ledger deterministically and the LLM drafts a candidate
gauge per high-recurrence cluster (the **only** LLM step, behind `GAUGE_DRAFTERS`);
`backtest` validates each candidate deterministically (recall / precision / determinism /
runtime); `promote` is **human-gated** and refuses without a passing backtest and an
explicit `--by`. A gauge is active iff a `Promotion` exists in the tool crib; promoted
semgrep gauges then execute in Screen (`core/gauge_engine.py`), closing the loop.

### Structural isolation (the enforcement, not just the convention)

- The LLM lives **only** behind `INSPECT_BACKENDS` / `GAUGE_DRAFTERS` registries, the
  same way the `PARTING` registry is isolated from the auto pipeline. The backend module
  is underscore-prefixed so `autodiscover` never pulls it into `ANALYZERS`.
- The deterministic side (`inspect.py`, `inspect_gauges.py`) must not import the LLM path
  (`llm_port`, `inspect_runner`, `_inspect_llm`). This is enforced by a **transitive**
  import-graph test (`tests/unit/test_inspect_isolation.py`), not just a convention.
- Output is comments + an advisory claims ledger; it **never gates a build and never
  enters the decision audit lake**, and it is not in the auto pipeline.

### Trust gate

`caliper eval` (`core/inspect_eval.py`) scores the reviewer against a seeded-bug corpus
**pre- and post-Adjudicate** (precision / recall / F1 / nit-rate / SNR + per-rule drop
rate), so the value Adjudicate adds is measurable and the model default is chosen by
data, not assertion. The feature is not trusted until this runs.

## Consequences

- **The defensible claim is preserved and now testable.** No LLM output reaches a human
  or a gate except through `adjudicate()` — a pure function with property tests
  (Determinism, Integrity, Isolation, Monotonicity, Boundedness) — and the isolation is
  enforced structurally (transitive import test), not by reviewer vigilance.
- **`anchor_quote` is the load-bearing anti-hallucination primitive.** Requiring a
  verbatim source quote turns the anchor rule into a string-membership test the model
  cannot satisfy by fabricating line numbers.
- **Fail-soft review, fail-closed gates.** An unavailable model skips Review (no invented
  claims); Screen and Adjudicate keep their fail-closed / pure guarantees. Promoted-gauge
  execution in Screen is fail-open augmentation (a missing opengrep never breaks inspect).
- **The flywheel is safe by construction.** The LLM only drafts; a candidate becomes a
  deterministic gauge only after a passing backtest **and** an explicit human promotion —
  there is no code path from model output to an active gauge that skips both.
- **Manual, not in the gate.** Like `caliper part`, these are developer-invoked. They
  need the cut list (which `ANALYZERS`' `run(files, repo_path)` contract does not carry),
  so they are their own CLI commands and cannot regress the main review gate.
- **Cost / latency are opt-in.** The default backend is `null` (review is inert until a
  model is wired via `CALIPER_LLM_*`), so nothing changes for existing users.
- **Known limits (deferred, not hidden).** Routing is by bucket only until the Blast
  Radius graph lands (R3/R5); only `semgrep` gauges auto-execute (ast/manual need a
  human-written detector); and the backtest's recall gate needs a historical-snapshot
  corpus keyed by content hash, which is a documented follow-on.

## Alternatives considered

- **Route Review through the existing `agent/` (Copilot) path.** Rejected: that is a
  presentation-tier entry point, not a swappable model port — it could not be sealed or
  faked the way `LLMPort` is.
- **Whole-PR LLM review.** Rejected: noisy, unanchored, and it would put model judgment
  in front of humans without a deterministic filter. Per-part + Adjudicate is the
  disciplined alternative.
- **Evidence binding by asking the model for rule ids.** Rejected: a documented
  hallucination failure mode; binding is post-hoc and deterministic instead.
- **Auto-promoting recurring claims into gauges.** Rejected: that would put LLM output
  into the decision path. Promotion is deterministic-backtest-gated **and** human-gated.
