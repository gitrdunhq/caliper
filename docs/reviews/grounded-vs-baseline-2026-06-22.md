# Grounded vs. ungrounded Haiku review — first data point

**Question:** does feeding a cheap (Haiku) reviewer cross-file *type contracts + symbol
facts* (the `eedom ground` bundle) plus a *don't-flag ledger*, and requiring it to
self-refute before emitting, actually recover the precision gap vs an expensive model?
The thesis was **unproven** until this run.

## Design
Same three partitions, same Haiku reviewer model, same plain Haiku challenger (no ledger
— identical ruler to the original baseline) so the comparison isolates the **reviewer**
change. Partitions were chosen because they were **false-positive-heavy** in the baseline
(selection bias — see caveats). Grounding bundles generated with
`eedom ground` (codegraph provider, 34–40 defs + 40 cross-file contracts each).

## Result

| Partition | Ungrounded raw→conf/fp/unc | Grounded raw→conf/fp/unc |
|-----------|---------------------------|--------------------------|
| P03 policy/OPA | 6 → 4 / 0 / 2  (67%) | 3 → **3 / 0 / 0**  (100%) |
| P16 scanners   | 9 → 6 / 2 / 1  (67%) | 6 → **6 / 0 / 0**  (100%) |
| P19 data/cli   | 7 → **0 / 6** / 1  (0%) | 0 → **0 / 0 / 0**  (—) |
| **Total**      | **22 → 10 / 8 / 4** — conf **45%**, FP **36%** | **9 → 9 / 0 / 0** — conf **100%**, FP **0%** |

**What grounding did:**
- **Eliminated every false positive** (8 → 0) and every uncertain (4 → 0).
- **Raised confirm-rate 45% → 100%** on these partitions — past even ungrounded *Sonnet's*
  79% (full-run), at Haiku's price.
- **Preserved real-bug yield**: 9 confirmed grounded vs 10 confirmed ungrounded.
- **Surfaced a new class of real bug** it otherwise missed: grounded P03 found three
  `OpaRegoAdapter`-vs-`OpaEvaluator` *contract divergences* (ignored `decision` field,
  unpopulated `triggered_rules`, dropped `warn_reasons`) — bugs that require seeing *both*
  implementations' contracts at once, which is exactly what the type-context bundle supplies.
- **P19 is the cleanest win**: ungrounded Haiku invented 6 false positives and confirmed 0
  real bugs; grounded Haiku emitted nothing — correctly (the baseline confirmed no real
  bugs there either).

The false positives that vanished were the context-starvation classes the ledger/bundle
target: Pydantic/StrEnum coercion read as a raw-string bug, parametrized SQL read as
injection, a config-injected timeout read as missing, type-constrained fields read as
nullable.

## Caveats (this is one data point, not a proof)
- **n = 1, 3 partitions, single run.** No repeats, no variance estimate. The result could
  shift several points on a rerun.
- **Selection bias.** These three partitions were picked *because* they were FP-heavy —
  i.e. exactly where grounding should help most. The unbiased number needs the **full
  20-partition grounded rerun**.
- **Verifier is Haiku.** "100% confirmed / 0 FP" partly reflects the challenger agreeing,
  not ground truth. No Opus adjudication or human label on the grounded set yet.
- **Recall is unmeasured.** Grounding + self-refutation could also suppress *real* bugs
  (false negatives). The comparable confirmed-bug count (9 vs 10) is reassuring but not
  proof; only a labeled set would settle it.

## Verdict
A strong directional confirmation of the thesis: on the partitions where a cheap model
drowns in context-starvation false positives, grounding it with cross-file contracts +
a don't-flag ledger **removed the noise wholesale and preserved (even extended) the real
findings.** The next step to harden this is the full 20-partition grounded rerun with an
Opus adjudicator on the deltas — which would turn this from "promising" into "measured."
