# Agent A — External Research: Technique & Prior Art for LLM Code Review

Scope: external/web research only. No caliper code was read. Recommendations for
the Tier 0/1/2 part-review design. Primary, recent sources (2024–2026) preferred.

Cross-cutting finding: the independent benchmark literature converges that
**per-part scoping (small, clean context) is the single biggest lever for review
quality**, and the failure mode of every commercial tool is the noise/recall
tradeoff. CR-Bench measured GPT-5.2 single-shot at **3.56% precision** on whole-PR
review (https://arxiv.org/html/2603.11078v1); the design's premise — cut the diff
into clean parts, seal the LLM between two pure functions — is the correct response.

---

## Q1. Claim schema

**Recommendation.** Flat per-claim record, verbatim evidence pulled from source, a
model-emitted confidence, and a required free-form `reasoning` field captured but
never trusted by Tier 2. The LLM never emits a verdict, a rule id, or a severity it
cannot justify from the part text.

```jsonc
{
  "file": "string",                 // must be one of the part's files (rule 1)
  "line_start": "int",              // 1-based inclusive
  "line_end": "int",                // inclusive
  "anchor_quote": "string",         // VERBATIM copy of flagged source line(s)
  "category": "enum",               // closed set; drives rule-4 allow-list
  "severity": "enum",               // info|low|medium|high (NOT a verdict)
  "confidence": "enum",             // low|medium|high (model self-report)
  "assertion": "string",            // one-sentence: what is wrong
  "reasoning": "string",            // why; captured for flywheel+audit, never gates
  "suggested_fix": "string|null",
  "evidence_ref": "string|null"     // null by default; filled by Tier 2, not model
}
```

`category` enum (closed, <15 — keep enums under ~50 for constrained decoding,
https://collinwilkins.com/articles/structured-output): correctness_bug, null_deref,
resource_leak, concurrency, injection, auth, crypto_misuse, error_handling,
api_contract, perf, style, maintainability, test_gap, other.

**Reasoning.**
- **`anchor_quote` is the load-bearing anti-hallucination field.** The strongest
  semantic-reliability technique is forcing the model to pull text verbatim:
  "Asking for evidence spans or direct quotes is hard to hallucinate when you
  require pulling them verbatim"
  (https://rotascale.com/blog/structured-output-isnt-reliable-output/). Tier 2
  rule 2 (anchor) becomes a string-membership test against the part's changed lines.
- **Integer line ranges, not a string.** Greptile counted a bug as caught only with
  an explicit line-level comment (https://www.greptile.com/benchmarks). Structured
  lines are required for scope/anchor filtering and Tier 0 matching.
- **severity/confidence are self-reports, NOT verdicts.** A hallucinated confidence
  score is syntactically valid but semantically wrong
  (https://rotascale.com/blog/structured-output-isnt-reliable-output/). Use
  confidence only for display/ranking; monitor its distribution as a drift signal
  (https://collinwilkins.com/articles/structured-output).
- **`reasoning` mandatory but advisory** — chain-of-thought capture powers the
  flywheel and audit; never gates.
- **`evidence_ref` nullable on purpose** — makes rule-3 substantiation work without
  the model knowing rule ids (see Q4).
- **Constrained decoding** guarantees well-formed JSON (99.9%+ schema compliance,
  https://mbrenndoerfer.com/writing/constrained-decoding-structured-llm-output) but
  "structured output isn't reliable output" — validity is necessary, not sufficient.

**Confidence: high** on shape and verbatim-anchor; **medium** on the exact category
enum (tune against caliper bucket allow-lists — Agent B).

---

## Q2. Context presentation

**Recommendation.** Part under review = **full unified diff + Tree-sitter
smallest-enclosing-scope per hunk**. Lower parts = **signatures/symbol summaries,
not full text**. Spend tokens in order: (1) PR/issue prose, (2) part diff + enclosing
scope, (3) signatures of lower parts the part calls, (4) full lower-part text only
when a symbol is directly referenced.

**Reasoning.**
- **Textual context beats code context per token.** Enriched-context benchmark
  (Nov 2025): PR description lifted quality-estimation F1 36.08→62.12 (+72%);
  issue+PR 64.37 (+78%); surrounding-code alone 51.76. Textual context gave
  1.2–1.3× more gain per token (https://arxiv.org/html/2511.07017).
- **Enclosing scope via AST, not raw line windows**
  (https://arxiv.org/html/2511.07017, https://www.codeant.ai/blogs/llm-code-reviews-beyond-rag).
- **More context is not better.** "Retrieving more context does not guarantee
  better reviews"; open-source/local code models **degraded with longer context**
  (−1.05% Pass@1; "more susceptible to noise from longer contexts")
  (https://arxiv.org/html/2511.07017). Direct warning for the local-model plan (Q7).
- **Token budget.** Cloudflare writes per-file patches and passes only relevant
  paths; duplicating full MR context across reviewers cost ~7× for no gain
  (https://blog.cloudflare.com/ai-code-review/). Per-part design gets this for free.
- **Avoid generated summaries for grounding** — a model summary is itself
  un-anchored; prefer deterministic Tree-sitter signatures.

**Confidence: high.**

---

## Q3. Output filtering mapped to the six Tier 2 rules

| Tier 2 rule | External technique | Source |
|---|---|---|
| 1. scope | path-membership; per-domain reviewers see only their files | https://blog.cloudflare.com/ai-code-review/ |
| 2. anchor | verbatim evidence-span; line-level grounding required to count | https://rotascale.com/blog/structured-output-isnt-reliable-output/ , https://www.greptile.com/benchmarks |
| 3. substantiation | LLM-as-FP-filter; ground claims to tool warnings | https://arxiv.org/html/2601.18844v1 , https://arxiv.org/html/2411.03079v2 |
| 4. category allow-list | category enum + policy on output meaning | https://collinwilkins.com/articles/structured-output |
| 5. severity floor | severity calibration; SNR-oriented suppression | https://arxiv.org/html/2603.11078v1 |
| 6. dedup/collapse | ensembling/consensus dedup; alert-fatigue reduction | https://www.greptile.com/greptile-vs-coderabbit |

- **Self-consistency / multi-sample voting** reduces FPs but trades recall vs noise:
  CR-Bench Reflexion raised recall (27.01→32.76%) but cut SNR (5.11→1.95)
  (https://arxiv.org/html/2603.11078v1). If added, place it before Tier 2; fold
  agreement-count into rule 6 ranking.
- **Agentic FP filtering** gives biggest FP reductions (94–98% elimination at
  ~0.93 accuracy, https://arxiv.org/html/2601.18844v1) but puts exploration inside
  the LLM loop — conflicts with "sealed between two pure functions." Keep out of the
  gate; only as optional Tier 1 enrichment whose output still passes Tier 2.

**Missing rule — "collapse-into-Tier-0".** None of the six drop a claim that merely
restates a Tier 0 finding the human already has. Add a rule (between 3 and 6): if a
claim's (file, line, category) collides with an existing Tier 0 finding, collapse it
as corroboration rather than a separate comment. Directly fights the alert-fatigue
failure mode all benchmarks cite. Secondary candidate: explicit low-severity +
low-confidence suppression floor (CR-Bench's SNR exists for this).

**Confidence: high** on mapping; **medium** on placement of the new rule.

---

## Q4. Evidence binding

**Recommendation: post-hoc deterministic matching on (file, line-overlap, category),
with verbatim `anchor_quote` as the join key — NOT model-supplied rule ids.** The
model never learns your rule ids; Tier 2 binds. In rule 3: for each blocking claim,
search the part's Tier 0 findings for one whose line range overlaps the claim and
whose category is compatible (small static category→category map). Match ⇒ set
evidence_ref, keep blocking. No match ⇒ downgrade to advisory, never delete. Run the
anchor_quote membership check first so line numbers are trustworthy before joining.

**Reasoning.**
- **Asking the model for your rule ids is the failure mode** — phantom references and
  fabricated package names are documented code-review hallucination classes
  (https://arxiv.org/pdf/2511.00776, https://diffray.ai/blog/llm-hallucinations-code-review/).
  A model asked to cite an id it never saw fabricates one. Binding must be post-hoc
  and deterministic, from data the model never touched.
- **Industry FP-mitigation is this pattern reversed** — systems feed the static
  finding to the LLM and ask "is this real?", binding by (file, line, category)
  correspondence (https://arxiv.org/html/2601.18844v1, https://arxiv.org/html/2411.03079v2).
  You do the dual: LLM proposes, Tier 2 binds to the deterministic baseline.
- **Optional opaque-handle variant** — put Tier 0 findings in read-only context with
  minted handles (F1, F2); evidence_ref then verifiable by table lookup. More
  reliable but adds prompt surface and spurious-anchoring risk. Default to post-hoc
  matching; keep handle variant as an A/B experiment.
- Retrieval/RAG binding is overkill at part scale and nondeterministic — reject for
  the gate path.

**Confidence: medium-high.** Open gap: the category→detector compatibility map is
caliper-specific; no published canonical mapping exists. Build against caliper's
catalog (Agent B).

---

## Q5. Prior art — what changes the design

| Tool | Approach | Large-PR / per-concern | Failure mode | Transferable |
|---|---|---|---|---|
| **CodeRabbit** | Ensembling; PR+CLI+IDE; very high comment volume | Thorough, noisy; needs tuning | **Noise / triage burden**; recall ~44–46% | Ensembling for dedup; the noise problem is the cautionary tale your Tier 2 answers |
| **Greptile** | Full-repo graph index (call sites, tests, history) | Best recall via indexing beyond diff | **Low-priority noise**; misses cross-file bugs if not indexed | Confirms cross-part blindness → **integration pass mandatory**; repo-graph is the recall lever |
| **Graphite Diamond** | Stacked-PR-native, codebase-aware | Built around small stacked diffs (closest analog to parts) | **Very low catch rate** (6–18%) — small context alone under-detects | Validates small-diff unit AND warns small context isn't enough |
| **Copilot** | Per-concern, diff-scoped suggestions | Per-hunk style | Misses repo-context bugs; ~54% | Per-concern line comments + suggested_fix pattern |

**Forced design changes:** (1) **integration pass over assembled bottom-first parts
is non-negotiable** (isolation reproduces Diamond's low cross-part catch rate);
(2) **let Tier 0 carry recall, keep Tier 1 brief** (inverse of CodeRabbit's noisy
tuning) — your differentiator; (3) benchmarks measuring only catch rate mislead —
Greptile's explicitly omits false positives (https://www.greptile.com/benchmarks).

**Confidence: high** on qualitative lessons; **medium** on absolute numbers — vendor
benchmarks conflict (Greptile 82% vs 24% across sources); trust relative tradeoffs.
Sources: https://www.greptile.com/benchmarks ,
https://www.greptile.com/greptile-vs-coderabbit ,
https://www.devtoolsacademy.com/blog/state-of-ai-code-review-tools-2025/

---

## Q6. Eval methodology

**Recommendation: CR-Bench-style harness with four metric families, driven through
BATTLEARENA** (https://arxiv.org/html/2603.11078v1).

**Ground truth:** (1) **seeded-bug corpus** — `git blame` to the introducing commit,
reintroduce on a clean fork, run the reviewer; validate each bug is "detectable via
review" (CR-Bench filter) (https://linearb.io/resources/2025-ai-code-review-buyers-guide).
(2) **real-PR usefulness corpus** — Martian behavioral signal (developer acted on
comment), approximated offline against the eventual fix.

**Metrics (CR-Bench):** precision = bug hits / total comments; recall = bug hits /
total bugs; F1; **usefulness rate** = (bug hits + valid suggestions) / total;
**SNR** = (bug hits + valid suggestions) / noise — the key metric (recall/SNR trade
off); **nit rate** = fraction at severity ≤ low; **per-rule Tier 2 drop rate** (your
diagnostic — instrument every rule so the "sealed by a testable function" claim is
defensible).

**Harness for BATTLEARENA:** fix corpus + part-cutter output; sweep
(model, context-strategy, sampling-N); run Tier 1 → the SAME Tier 2 → score. Report
all metrics **pre- and post-Tier-2** to quantify what Tier 2 buys. Cache on
part-content hash for cheap reproducible reruns.

**Confidence: high** — CR-Bench is a near-exact template.

---

## Q7. Model selection

**Recommendation: default local (Qwen3.6 ~27B-class or Qwen3-Coder-Next MoE), cloud
as confidence/length-triggered fallback — but confirm via the Q6 eval.** Per-part
scoping favors local because small clean context is where the quality gap closes.

**Reasoning.**
- **Small/clean context is where local wins** — "for structured extraction,
  summarization, standard code generation, the quality gap is negligible"
  (https://www.sitepoint.com/self-hosting-ai-code-review-local-models/). A part is
  closer to extraction-over-small-diff than reason-over-repo.
- **Hard size floor:** 7B catches ~45% of real bugs (too low); **32B+ catch 80–88%,
  cited as the practical minimum for pre-merge review**
  (https://www.promptquorum.com/local-llms/best-local-llms-code-review). Qwen3.6
  ~27B (77.2% SWE-bench, best dense in tier,
  https://www.promptquorum.com/local-llms/best-local-llms-for-coding) sits at the
  edge; 7B/8B and small gemma are below the floor — demote to a pre-pass.
- **Local models more noise-sensitive to long context** (−1.05% Pass@1,
  https://arxiv.org/html/2511.07017) — the Q2 "signatures not full text" discipline
  matters MORE for the local default.
- **Latency/cost/privacy favor local** for a manual, advisory, non-gating tool;
  10–15s/response is acceptable and diffs stay on-prem
  (https://www.kdnuggets.com/self-hosted-llms-in-the-real-world-limits-workarounds-and-hard-lessons).
- **Deciding eval:** run local-27B / local-MoE / cloud-frontier on the seeded-bug
  corpus, scored **after Tier 2**. Pick the cheapest model whose post-Tier-2 recall
  and SNR are within margin of cloud — Tier 2 may close the raw-quality gap.

**Default: local Qwen3.6 ~27B. Fallback: cloud frontier, triggered on low-confidence
claims or oversized parts. gemma/7B → pre-pass only.**

**Confidence: medium** — size-floor numbers are secondary-source blogs and Qwen3.6
sits at the threshold; must be confirmed by the eval.

---

## Decisions for synthesis

1. **Claim schema** — flat per-claim: file, line_start, line_end (ints),
   **anchor_quote (verbatim, anti-hallucination + anchor join key)**, category
   (closed enum <15), severity (not a verdict), confidence (display/ranking only),
   assertion, reasoning (captured, never gates), suggested_fix?, evidence_ref? (null
   by default, filled by Tier 2). Constrained decoding. [high]
2. **Context** — part = full diff + Tree-sitter enclosing scope; lower parts =
   signatures not full text; **PR/issue prose first** (+72–78% F1). Prune hard —
   more context hurts local models. [high]
3. **Evidence-binding** — **post-hoc deterministic join** (file, line-overlap,
   category-compat-map) with anchor_quote verified first. Model never supplies rule
   ids. No match ⇒ advisory, never delete. Opaque-handle = optional A/B. Open gap:
   category→detector map (Agent B). [medium-high]
4. **Eval** — CR-Bench-style: seeded-bug + real-PR usefulness corpora;
   precision/recall/F1, **usefulness, SNR**, nit rate, **per-rule Tier 2 drop
   rate**; score **pre- and post-Tier-2**; drive via BATTLEARENA; cache on
   part-content hash. [high]
5. **Model** — **local Qwen3.6 ~27B** default; cloud confidence/length fallback;
   gemma/7B → pre-pass. Confirm with post-Tier-2 eval. [medium]
6. **Prior-art-forced changes** — (a) **integration pass over assembled parts is
   mandatory**; (b) **Tier 0 carries recall, Tier 1 stays brief**; (c) add a Tier 2
   **collapse-into-existing-Tier-0** rule.

### Open questions (unresolved externally)
- Exact category→detector compatibility map — no canonical published mapping; build
  against caliper catalog (Agent B). Real gap.
- Whether Qwen3.6-27B clears the bar after Tier 2 — only your eval can answer;
  size-floor figures are secondary-source blogs.
- Vendor catch-rate numbers conflict (82% vs 24%); trust relative tradeoffs. No
  neutral, noise-inclusive, reproducible public benchmark exists yet.
- Self-consistency multi-sample net value — raises recall, cuts SNR; corpus-
  dependent; make it a swept axis, not a default.

### Sources
- Enriched-context code-review benchmark (2025): https://arxiv.org/html/2511.07017
- CR-Bench (2026): https://arxiv.org/html/2603.11078v1
- Reducing FPs in static bug detection w/ LLMs, industry (2026): https://arxiv.org/html/2601.18844v1
- Precise/complete code context for FP mitigation (2024): https://arxiv.org/html/2411.03079v2
- Code-hallucination systematic review (2025): https://arxiv.org/pdf/2511.00776
- LLM hallucinations in code review: https://diffray.ai/blog/llm-hallucinations-code-review/
- Structured output isn't reliable output: https://rotascale.com/blog/structured-output-isnt-reliable-output/
- LLM structured outputs / enum limits: https://collinwilkins.com/articles/structured-output
- Constrained decoding: https://mbrenndoerfer.com/writing/constrained-decoding-structured-llm-output
- Greptile benchmarks: https://www.greptile.com/benchmarks
- Greptile vs CodeRabbit: https://www.greptile.com/greptile-vs-coderabbit
- State of AI code review tools 2025: https://www.devtoolsacademy.com/blog/state-of-ai-code-review-tools-2025/
- Cloudflare, AI code review at scale: https://blog.cloudflare.com/ai-code-review/
- LLM code reviews beyond RAG (AST scope): https://www.codeant.ai/blogs/llm-code-reviews-beyond-rag
- LinearB buyers guide (seeded-bug method): https://linearb.io/resources/2025-ai-code-review-buyers-guide
- Best local LLMs for code review (size floor): https://www.promptquorum.com/local-llms/best-local-llms-code-review
- Best local coding LLMs (Qwen3.6 27B): https://www.promptquorum.com/local-llms/best-local-llms-for-coding
- Self-hosted AI code review local LLMs: https://www.sitepoint.com/self-hosting-ai-code-review-local-models/
- Self-hosted LLMs real-world limits (latency): https://www.kdnuggets.com/self-hosted-llms-in-the-real-world-limits-workarounds-and-hard-lessons
