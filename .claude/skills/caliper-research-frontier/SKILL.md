---
name: caliper-research-frontier
description: >-
  Use when scoping caliper's next research bet on deterministic (zero-LLM)
  code review precision vs LLM reviewers — e.g. "where should caliper's
  detectors get smarter", "does grounding actually help", "why did the LLM
  review find a bug our detectors missed", "what's the next caliper research
  milestone", "is caliper competitive with an LLM reviewer yet", or before
  proposing a new detector/scribe/grounding-provider whose stated goal is
  closing a precision or recall gap vs LLM review. Grounds every claim in
  docs/reviews/*-2026-06-22.* and docs/llm-review/*. Not for running a review
  (use adversarial-review) or for general architecture questions (use
  caliper-architecture-contract).
---

# Caliper Research Frontier

Runbook for extending caliper's **zero-LLM-in-the-decision-path** review
toward — or past — LLM-reviewer precision, using evidence already gathered in
this repo. This is not a vision doc: every number below was measured, is
dated, and comes with a command to reproduce or re-check it.

**Audience:** human engineers and autonomous agent sessions alike. Every
command below is copy-pasteable verbatim from the repo root.

## When NOT to use this skill

| You want to... | Use instead |
|---|---|
| Actually run a multi-agent adversarial review | `adversarial-review` |
| Understand the ports-and-adapters tier boundaries | `caliper-architecture-contract` |
| Write a new scanner plugin | `caliper-plugin-authoring-playbook` |
| Author/tune an OPA policy rule | `caliper-opa-policy-playbook` |
| Debug a failing test or flaky pipeline | `caliper-debugging-playbook` |
| Run the general test/build/format loop | `caliper-testing-and-tdd`, `caliper-build-and-env` |
| Reproduce a past incident, not push the frontier | `caliper-failure-archaeology` |
| Understand how reachability/scan-cache/code-graph checks work *today* (not the frontier gap) | `caliper-proof-and-analysis-toolkit` |
| Decide whether a result from one of this skill's open problems is proven enough to ship as a default | `caliper-research-methodology` |

If you're not sure whether your task is "push precision/recall forward" vs
"operate the existing system," it's this skill only if you're about to
propose or evaluate a *change* aimed at closing a measured gap.

## Vocabulary (defined once)

| Term | Meaning |
|---|---|
| **Grounding bundle** | Output of `caliper ground` (`src/caliper/adapters/grounding.py`) — a fact sheet (symbols defined in the files under review) + type context (contracts referenced but defined elsewhere), sourced from caliper's own code graph. Fed to an LLM reviewer as a "don't-flag ledger" precondition. |
| **Scribe seam (ADR-006)** | Post-detection, pre-policy pass (`SCRIBES` registry, `core/port_registries.py`) that decorates a finding's `metadata['scribe']` with deterministic context — enclosing symbol, blast-radius callers, reachability. Sequential, fail-open, verdict-independent. |
| **Adjudicate filter** | `adjudicate()` in `src/caliper/core/inspect.py` — the **pure, deterministic** 7-rule gate (scope → anchor → substantiation → category → floor → collapse → dedup) that every LLM claim from `caliper inspect` must pass before it reaches a human. Architecturally isolated from the LLM path (a structural test enforces it never imports `core.llm_port`/`plugins._inspect_llm`). |
| **De-biased confirm rate** | A finding count corrected for challenger-model bias by having a stronger model (Opus) independently re-open the source and rule REAL/NOT-REAL, rather than trusting the cheap challenger's self-report. |
| **Precision / recall / F1 / SNR / nit-rate** | Standard IR metrics as computed by `caliper eval` (`core/inspect_eval.py`) against a labeled corpus: precision = matched claims / total claims, recall = matched truths / total truths, SNR = confirmed / (confirmed + nit), nit-rate = share of surviving claims judged low-value. |
| **Reachability scribe (ADR-009)** | `ReachabilityScribe` (`src/caliper/plugins/scribes/reachability.py`) — resolves a vulnerable package's import name via the code graph and marks `reachable: true/false/null`. `false` lets OPA downgrade a critical/high vuln deny to warn (`policies/policy.rego` `_unreachable_downgraded`). The template this skill's Open Problem 3 generalizes. |

## The evidence base (all dated 2026-06-22 unless noted)

Four experiments, read in full before proposing anything here — do not take
this summary on faith, re-open the source files:

| File | What it measured |
|---|---|
| `docs/reviews/grounded-vs-baseline-2026-06-22.md` | **n=1, 3 cherry-picked FP-heavy partitions.** First look: grounding took Haiku confirm-rate 45%→100%, FP 36%→0%. Selection bias flagged by its own caveats. |
| `docs/reviews/grounded-full-20-2026-06-22.md` | **Unbiased 20-partition rerun + Opus adjudication of every delta.** The number to trust. |
| `docs/reviews/grounding-conclusions-2026-06-22.md` | Closing synthesis of the two runs above — the practical-conclusions section is this skill's primary source. |
| `docs/reviews/haiku-vs-sonnet-2026-06-22.md` | Same 20 partitions, same prompts, reviewer model swapped Haiku↔Sonnet, Opus adjudicates every model-unique finding. |

### Headline numbers (de-biased, i.e. Opus-adjudicated — not the raw Haiku-challenger view)

| Metric | Ungrounded | Grounded |
|---|---|---|
| Raw findings | 117 | 68 |
| Haiku-challenger "confirmed" | 69 | 31 |
| **Opus TRUE bugs** | **30** | **26** |
| **True precision (true/raw)** | 26% | **38%** |
| Real bugs unique to this arm | 16 (suppressed by grounding) | 12 (found only via grounding) |

**Net recall cost of grounding: −4 real bugs.** Grounding roughly *doubles*
true precision and halves reviewer volume — genuinely worth shipping — but it
is not free, and the failure mode is diagnostic (see Open Problem 2).

| Metric | Haiku reviewer | Sonnet reviewer |
|---|---|---|
| Confirm rate (own challenger) | 59.0% | 79.1% |
| FP rate | 32.5% | 19.4% |
| Opus-confirmed unique real bugs | 16 (Haiku-only) | 54 (Sonnet-only) |
| Reviewer tokens | 1,068,618 | 909,690 |

**The single most important number in all four documents:** the plain-Haiku
challenger over-confirmed **39 of 69** ungrounded "bugs" (57%) — rubber-stamping
style nits and documented fail-open paths. *"Every prior number in this
repo's review experiments was verifier-inflated"* — `grounding-conclusions-2026-06-22.md:37`.

## Open problems

Each entry: why the deterministic side currently loses (or wins) per the
evidence above, the caliper-specific asset that could close the gap, three
concrete next steps in this repo, and a falsifiable milestone — a number
that must move on a named eval, not a vibe.

### Open Problem 1 — The verifier, not the reviewer, is the leverage point

**Evidence.** Sonnet-as-reviewer beat Haiku-as-reviewer 3.4x on unique
Opus-confirmed bugs (54 vs 16) at a *lower* FP rate and *fewer* tokens — a
clean capacity win. But the bigger effect in the whole evidence base is the
**challenger**: the same cheap Haiku challenger over-confirmed 57% of
ungrounded raw findings. Caliper's `adversarial-review` skill already
upgrades the challenger to Sonnet/Opus for exactly this reason — that is the
orchestration-level fix. The *deterministic*-side fix does not exist yet:
caliper's own `adjudicate()` (`core/inspect.py`) is a pure, 7-rule,
zero-LLM claim filter built for `caliper inspect`'s Tier 1→2 pipeline, but
nothing currently routes `adversarial-review`'s raw Haiku-reviewer claims
through it as a second, free, deterministic gate.

**Asset.** `core/inspect.py:adjudicate()` (scope/anchor/substantiation/
category/floor/collapse/dedup) + `caliper eval` (`core/inspect_eval.py`),
which scores precision/recall/F1/nit-rate/SNR pre- and post-Adjudicate
against a labeled corpus.

**Next steps (in this repo).**
1. Grow `docs/llm-review/eval-corpus/` past its current 2 illustrative cases
   using the method its own README already documents: `git blame` a real fix
   to its introducing commit, reintroduce the bug on a clean fork, record a
   backend's claims for the affected part, mark the site in `truths`. Target
   >=10 real cases sourced from this repo's own commit history.
2. Write an adapter that maps a `docs/reviews/adversarial-*.json` run's raw
   Stage-1 claims into the `Claim`/`Part`/`changed_lines` shape `adjudicate()`
   expects, and run them through it — this reuses the existing pure function,
   it does not require a new one.
3. Re-run the exact grounded-vs-ungrounded 3-partition comparison (P03/P16/P19)
   via `adversarial-review`, this time diffing "Haiku-challenger-confirmed"
   against "Haiku-challenger-confirmed AND Adjudicate-survives" to see how much
   of the 57% over-confirm the deterministic filter alone removes for free.

**Milestone.** On a >=10-case labeled corpus, `caliper eval`'s
post-Adjudicate precision is **>= 0.80** while post-Adjudicate recall stays
within 0.05 of pre-Adjudicate recall on the same corpus. (Today's number,
`bash .claude/skills/caliper-research-frontier/scripts/reverify_evidence.sh`,
is precision 0.50→0.67 pre→post on 2 cases — explicitly not a benchmark per
`docs/llm-review/eval-corpus/README.md:32`.)

### Open Problem 2 — Grounding's "fail-open by design" prior eats real bugs

**Evidence.** Of the 16 real bugs grounding suppressed on the unbiased
20-partition run, the pattern is diagnostic, not random: the grounding
ledger's "this is intentional fail-open" prior rationalized away **genuine
uncaught-exception bugs** — `subprocess_runner` missing `UnicodeDecodeError`/
`OSError` catches, `concern_prompt` missing `JSONDecodeError` — and detector
false negatives. `grounding-conclusions-2026-06-22.md:23`: *"'Fail-open by
design' justifies a broad except — not a missing one."* This is caliper's own
stated design principle (`CLAUDE.md` "Fail-open") being weaponized by an LLM
reviewer against itself.

**Asset.** `adapters/grounding.py`'s `GroundingProviderPort` (4 registered
providers: null/codegraph/ctags/gitnexus) is the exact seam to add a new
deterministic fact kind to the bundle; the scribe-seam pattern (ADR-006) is
the template for computing it once and attaching it everywhere.

**Next steps (in this repo).**
1. Add a fact to the grounding bundle that lists, per `try` block near a
   `subprocess.run`/`.json()`/file-IO call in the files under review, which
   exception types are actually caught (`ast.ExceptHandler.type`) — so the
   ledger has ground truth instead of a "trust the fail-open doc" prior. Land
   it as a new method on `GroundingProviderPort` (mirrors `fact_sheet`/
   `type_context`/`neighbors`) so all four providers stay swappable.
2. Add the literal carve-out `grounding-conclusions-2026-06-22.md:38`
   recommends to `_render_grounding_markdown` (`src/caliper/cli/main.py`):
   the rendered bundle must say outright that "fail-open by design" never
   excuses a *missing* except/timeout/guard, only a *broad* one.
3. Re-run the full 20-partition grounded arm (`adversarial-review`, same
   prompts/partitions as `grounded-full-20-2026-06-22.md`) with both changes
   in place and diff the new run's suppressed-uniques list against the 16
   named ones in that file's "UNGROUNDED_ONLY real-suppressed-bugs" section.

**Milestone.** A rerun of the grounded 20-partition arm recovers **>= 12 of
the 16** previously-suppressed real bugs (the named list in
`grounded-full-20-2026-06-22.md:54-70`) while grounded raw volume stays
within 20% of the original 68 (i.e. the fix targets recall, not "just ask for
more findings").

### Open Problem 3 — Cross-file contract divergence is currently LLM-only territory

**Evidence.** The 12 real bugs grounding uniquely caught are, in the source's
own words, *"exactly the cross-file-contract class grounding was built
for"* — `OpaRegoAdapter` never populating `triggered_rules`/`constraints`
that its sibling `OpaEvaluator` does, `pipeline.py`'s `evaluate_sbom()` never
stamping `commit_sha` unlike `evaluate()` at line 151
(`haiku-vs-sonnet-2026-06-22.md:51`), `graph_builder._walk_upstream`'s
unguarded `.fetchone()["id"]`. No deterministic detector caught these: the 22
`CAL-*` detectors are file-scoped (`BugDetector.detect(file_path)`,
`detectors/framework.py:150`), and the 12 shipped code-graph checks
(`checks.yaml`) test structural properties (fan-out, layer violation, circular
deps) — none diff two implementations of the same contract against each other.

**Asset.** `ReachabilityScribe` (ADR-009) already proves the recipe works for
one narrow case: a pure code-graph query (declared-vs-imported) replacing an
LLM judgment entirely, wired into OPA as `_unreachable_downgraded`
(`policies/policy.rego:83`). The same shape — diff what a contract declares
against what an implementation actually does — generalizes.

**Next steps (in this repo).**
1. RED first (per this repo's split-TDD convention): write a failing test in
   `tests/unit/detectors/` for a new `CAL-023` detector or a 13th
   `checks.yaml` entry that, given a class implementing a `Protocol`/ABC,
   flags a method that returns a dataclass/model instance without setting a
   field the protocol's declared return type carries — using the
   already-adjudicated `OpaRegoAdapter.triggered_rules` gap as the seed
   fixture.
2. Implement the minimum AST/graph query to turn that test green; register it
   in `src/caliper/detectors/_registry.py` (`DETECTORS`) or `checks.yaml`,
   whichever shape fits — a code-graph SQL check is likely the better fit
   since the comparison is inherently cross-symbol.
3. Add a dataclass-field-omission case type to `caliper eval`'s corpus schema
   so this detector's own precision is tracked the same deterministic way LLM
   claims are — it should never regress silently.

**Milestone.** The new check/detector ships as `CAL-023` (or `checks.yaml`
entry 13) with a green `tests/unit/test_X.py`, passes `make test`
(container-only per `CLAUDE.md`), and fires with **zero false positives**
against the existing 22-detector + 12-check regression corpus while
correctly flagging a reconstructed `opa_adapter.py`-style fixture with a
deliberately omitted field.

### Open Problem 4 — Every headline number here is n=1

**Evidence.** `grounded-vs-baseline-2026-06-22.md:43`, `grounded-full-20-2026-06-22.md:144`,
and `haiku-vs-sonnet-2026-06-22.md:201` each say, in their own caveats
section, some form of "single run, no variance estimate, a rerun would shift
the exact counts." No number in this skill's evidence base has an error bar.
That is the gap standing between "grounding doubles precision" as a
finding and as a *defensible* finding.

**Asset.** `caliper eval` (`core/inspect_eval.py`) is deterministic and
reproducible by construction (recorded claims, no live model call needed to
rerun the *scoring*), so it is the natural harness to attach variance
tracking to, even before more (expensive) model reruns are affordable.

**Next steps (in this repo).**
1. Rerun the existing 3-partition grounded-vs-baseline comparison (P03
   policy/OPA, P16 scanners, P19 data/cli) at least 2 more times with
   identical prompts/models via `adversarial-review`, recording each run's
   raw/confirmed/FP counts in the same shape as
   `grounded-vs-baseline-2026-06-22.json`.
2. Compute range and stdev per partition across the runs; publish as
   `docs/reviews/grounded-vs-baseline-variance-<RUN_ID>.md` (RUN_ID pattern:
   `date +%Y%m%d-%H%M%S`), sitting alongside — never overwriting — the
   original point-estimate file.
3. Extend the `caliper eval` corpus case schema
   (`docs/llm-review/eval-corpus/README.md`) to optionally carry N recorded
   claim sets per case (one per rerun) so `caliper eval` itself can report a
   precision/recall *range*, not a single point, without any new tooling
   outside this repo.

**Milestone.** A documented 3-run range exists for at least one partition
(e.g. P16 scanners) where the spread in Haiku-challenger confirm-rate is
**< 15 percentage points** — turning "45%→100% confirm, n=1" into a number
with a stated confidence band.

Every milestone above marks a number to hit, not a decision to ship. Before
promoting any resulting change (a new detector default-on, a grounding
carve-out, a challenger swap) out of "experiment," run it through
`caliper-research-methodology`'s evidence bar — one causal mechanism
explaining all observations including negatives, an assigned adversarial
refutation pass, numbers predicted before the experiment runs. This skill
tells you *what* to try next; that one tells you *when you're allowed to
believe it worked*.

## Reproduce the headline evidence yourself

```bash
# Full evidence-base reverification: capability counts, caliper eval numbers,
# and a check of the detector's bare-@lru_cache vs @lru_cache() handling.
bash .claude/skills/caliper-research-frontier/scripts/reverify_evidence.sh
```

Observed output as of 2026-07-02 (commit `c78154b`):

```
scanner plugins (ScannerPlugin subclasses, excl. OpaPlugin/PartingPlugin): 19
OPA policy plugin present (_opa.py OpaPlugin): yes
deterministic detectors (unique CAL-NNN ids in docs/detectors.md): 22
custom semgrep rules (- id: entries under policies/semgrep): 67
code graph checks (checks.yaml '- name:' entries): 12
OPA deny/warn rules (policy.rego 'X contains msg if' blocks): 16

review eval over 2 case(s) [caliper eval --format json → precision/recall/f1/snr]:
  pre_adjudicate:  precision=0.50 recall=1.00 f1=0.6667 snr=1.0
  post_adjudicate: precision=0.6667 recall=1.00 f1=0.8 snr=2.0

findings on bare @lru_cache fixture: []   # CORRECT — see below, this is not a gap
```

That last line is **not a bug**. Python's `functools.lru_cache` used bare (no
call, no parens) defaults to `maxsize=128` — confirmed empirically
(`@lru_cache` on a function yields `cache_parameters() == {'maxsize': 128,
'typed': False}`) — so it is genuinely bounded, and
`src/caliper/detectors/reliability/cache_eviction.py`'s `_has_unbounded_cache`
correctly does not flag it. Only bare `@cache` (`functools.cache`, always
unbounded) and `@lru_cache(maxsize=None)` are truly unbounded; both of those
*are* flagged (`tests/unit/detectors/reliability/test_cache_eviction.py`
covers all four cases).

There is a smaller, real **inconsistency** worth knowing about instead: the
detector's own policy (per that same test file, "Detects `@lru_cache()`
without maxsize argument") is to flag *any* `lru_cache` use that doesn't
state its bound explicitly — even though `@lru_cache()` with empty parens
also defaults to the identical bounded `maxsize=128`. Under that
"state-your-bound-explicitly" policy, the bare `@lru_cache` (no parens) form
is the odd one out: it's exempted only because `_has_unbounded_cache`'s
`ast.Name` branch checks for the name `"cache"` but not `"lru_cache"`, while
its `ast.Call` branch handles `@lru_cache()`. This is a minor style/parity
gap in the detector's own stated policy, not a memory-safety or OOM-risk
false negative — treat it as low-priority polish, not a "ready-to-fix" item.

Individual commands, run standalone:

```bash
# Grounding bundle (gated — off by default)
CALIPER_GROUNDING_ENABLED=1 uv run caliper ground --files src/caliper/core/scribe.py --out .temp/ground.json

# Eval harness against the seeded corpus
uv run caliper eval --corpus docs/llm-review/eval-corpus --format json

# The deterministic LLM-review pipeline itself (needs a cutlist from `caliper part`)
uv run caliper inspect --help

# opa test — nothing in this skill's proposals may bypass OPA's own test suite
opa test policies/ --ignore '*.yaml' --ignore '*.yml'
```

## Guardrails inherited from this project (do not route around)

- Any new detector/check follows **split RED/GREEN TDD** — see
  `caliper-testing-and-tdd`. A failing test comes from a *different* agent
  turn than the implementation, per `CLAUDE.md` "Split TDD Across Agents."
- Any new deterministic check must stay in `core`/`detectors`/`plugins` per
  the tier-boundary guard test
  (`tests/unit/test_deterministic_architecture_guards.py`) — see
  `caliper-architecture-contract`. `core/inspect.py`'s Adjudicate filter is
  structurally forbidden from importing the LLM path; do not weaken that.
- **Tests run in containers only** (`make test`). Never propose
  `CALIPER_ALLOW_HOST_TESTS=1`.
- Self-review any change to the detector/policy surface with `make dogfood`
  before calling an open problem "closed."
- LLM stays advisory everywhere in this pipeline: `caliper inspect` without
  `--no-llm` still requires every claim to survive `adjudicate()`; no open
  problem above proposes putting an LLM on the decision path (`WHY.md`'s
  "zero LLM in the decision path" is the one constraint none of this may
  break).

## Provenance & maintenance

Every count and number above drifts as the codebase grows. Re-verify before
citing this skill's evidence in a design doc:

| Fact | Re-verification command |
|---|---|
| All capability counts + eval numbers + the bare-`@lru_cache` behavior check | `bash .claude/skills/caliper-research-frontier/scripts/reverify_evidence.sh` |
| Detector count | `grep -oE "CAL-[0-9]{3}" docs/detectors.md \| sort -u \| wc -l` |
| Semgrep rule count | `grep -rhE "^\s*- id:" policies/semgrep \| wc -l` |
| Code graph check count | `grep -cE "^\s*- name:" src/caliper/plugins/_runners/checks.yaml` |
| OPA rule count | `grep -cE "^(deny\|warn) contains msg if" policies/policy.rego` |
| Current commit this skill was verified against | `git rev-parse --short HEAD` (was `c78154b` on 2026-07-02) |
| eval-corpus is still "2 illustrative cases, not a benchmark" | `ls docs/llm-review/eval-corpus/*.json \| wc -l` — if this grew, re-read Open Problem 1/4's milestones, they assume a small corpus |
| No new `docs/reviews/*.md` superseding the 2026-06-22 evidence base | `ls -la docs/reviews/` — a newer dated file may update or override headline numbers above |
