# Grounding experiment — conclusions & next steps

Closing synthesis of the grounded-review investigation. Detailed data:
`grounded-vs-baseline-2026-06-22.{md,json}` (cherry-picked 3-partition) and
`grounded-full-20-2026-06-22.{md,json}` (unbiased 20-partition + Opus adjudication).

## The arc (why each step mattered)
1. **Cherry-picked 3 FP-heavy partitions** → grounding looked like a miracle (Haiku 45%→100% confirm). *Selection bias.*
2. **Unbiased full 20** → naive Haiku-verifier view *reversed* it: grounded 48% vs ungrounded 64% confirm. Looked like grounding hurt.
3. **Opus de-biasing of every delta** → the real story: **the cheap Haiku verifier was the confound.** It over-confirmed **39 of 69** ungrounded "bugs" (57%) — rubber-stamping style nits and *documented fail-open paths*.

## De-biased result (the one to trust)
| | Ungrounded | Grounded |
|---|---|---|
| Raw findings | 117 | 68 |
| Haiku-"confirmed" | 69 | 31 |
| **Opus TRUE bugs** | **30** | **26** |
| True precision (true/raw) | 26% | **38%** |
| Real bugs unique to this arm | 16 | 12 |

- **Grounding ~doubles true precision and halves volume.** The 69→31 collapse was ~90% illusory (39 of 55 dropped uniques were never bugs).
- **Real recall cost: −4 net bugs** (16 suppressed − 12 newly found). Small but non-zero — do not sell grounding as free.
- **Diagnostic suppression pattern:** the don't-flag ledger's *"fail-open by design"* prior rationalized away **genuine uncaught-exception bugs** (missing `UnicodeDecodeError`/`OSError`/`JSONDecodeError` catches in `subprocess_runner`/`concern_prompt`) and detector false-negatives (bare-assign secrets, `lru_cache(maxsize=None)`). "Fail-open by design" justifies a *broad* except — not a *missing* one.
- **The 12 newly-caught bugs are exactly the cross-file-contract class grounding was built for** (`OpaRegoAdapter` `triggered_rules`/`constraints` divergence, `graph_builder._walk_upstream` crash) — invisible without the bundle.

## Follow-on arms: capacity vs decomposition (P07/P08/P10, raw volume)
| Arm | total raw |
|---|---|
| Haiku monolithic-grounded | 21 |
| **Sonnet** monolithic-grounded | **10** |
| Haiku **decomposed** per-file | ~56 |

- **Capacity (Sonnet) halves over-production.** Overload is real: same prompt, bigger model, ~⅓ the volume on P08 (3 vs 10).
- **Decompose-per-file *tripled* it — a negative result.** Stripping the ledger/self-refute discipline to "shrink the task" backfired: Haiku free-associates per file (`ports.py`, pure protocol stubs → 10 findings). The over-production isn't pure context-overload; it's **Haiku lacking refutation discipline**, and removing that discipline makes it worse.

## Practical conclusions
1. **The highest-leverage fix is the verifier, not the reviewer.** A cheap Haiku challenger over-confirms ~57%. Upgrade the challenge pass (Opus/Sonnet adjudication, or apply the grounded self-refute discipline *to the challenger*). Every prior number in this repo's review experiments was verifier-inflated.
2. **Ship grounding** for the precision/effort win — but add a **recall backstop**: when a "fail-open by design" ledger rule would suppress a finding about a *missing* except/timeout/guard, do **not** suppress — escalate to review. That single carve-out recovers most of the −4 recall.
3. **Drop decompose-per-file.** If volume/cost control is needed, use a higher-capacity model for the generation pass; precision gating belongs in the verifier.
4. **Keep grounding monolithic but trim the load:** lean bundle (signatures over snippets), one ledger, keep the self-refute. The discipline is load-bearing; the bulk is not.

## Caveats
Single run (no variance). Haiku was the base verifier; Opus adjudicated only the 72 delta findings and inherited the challenger's calls on the 14 matched-both. Opus shares defect-taxonomy priors with the reviewers. Cross-arm matching is fuzzy (file + line±12 + judged-same defect). Ungrounded per-partition raw/FP weren't persisted in the original baseline artifact.
