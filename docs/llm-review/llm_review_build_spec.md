# Build Spec — LLM-Driven Per-Part Review (Tier 0 / Tier 1 / Tier 2)

> Synthesized from `findings_external.md` (Agent A — technique & prior art) and
> `findings_internal.md` (Agent B — caliper integration). This is the build spec the
> next phase consumes. Reconciliation rule applied throughout: **B's constraints win
> on placement, A's win on technique.** Hard A/B conflicts are flagged in
> [§0 Conflicts for human decision](#0-conflicts-for-human-decision) — not papered over.

Style mirrors the `caliper part` build prompt: a phase-scope line, guardrail
invariants carried verbatim, a module/seam map, concrete signatures, the
adjudicator as a pure property-tested function, and a consumer-first test-first
build sequence.

---

## Phase scope line

**Build Tier 0 routing + Tier 1 reviewer-behind-a-port + Tier 2 adjudicator + cache
+ integration pass + eval.** Route by **bucket only**. Defer R3/R5-driven (layer/risk)
routing until the Blast Radius graph lands; until then `layer`/`risk` part metadata is
recorded but not consulted by the routing table.

---

## 0. Conflicts for human decision

These need a human call before the build starts.

1. **`caliper part` v0 exists on the sibling branch `906l7z` — conflict RESOLVED,
   merge needed.** Agent B's repo scan was of the current branch
   `claude/caliper-part-subcommand-kn8yv0`, where `part()` is genuinely absent. A
   follow-up check of the sibling branch `claude/caliper-part-subcommand-906l7z`
   confirms `caliper part` v0 **is built there** (3 commits, 23 files, ~2,779 lines;
   pre-PR). So Agent A's "built, v0" was correct — just on a branch not merged here.
   See [§0a Verified symbol map](#0a-verified-symbol-map-from-906l7z) for the real
   names. **Decision needed:** merge/rebase `906l7z` onto this branch (or build atop
   it) **before** starting this phase — that is Step 0. The §12 build sequence and the
   symbol names below assume the `906l7z` definitions, not the placeholder
   `PartMetadata`/`Bucket` names used in the original draft.

2. **Migrate legacy `caliper audit` (`core/concern_review.py`) onto the new port — or
   leave it?** `concern_review.py` already does cluster→scan→attach-findings→fan-out-
   to-LLM→advisory-markdown, but it calls `httpx.Client` directly in core with
   hardcoded Anthropic/OpenRouter endpoints + `FREE_FALLBACKS` (`concern_review.py:265-380`)
   — bypassing `LlmClient`, with no port and no registry. That is the **only in-core
   LLM-transport decision-path leak in the repo**. We reuse its *structure* (packet,
   `source_block`, `run_audit` fan-out) but must not inherit its transport.
   **Decision needed:** migrate `audit` onto `LlmReviewPort` (removes the leak), or
   keep it as legacy and build part-review cleanly on the port. Recommendation:
   migrate, since it closes the leak the isolation contract test (§8) will otherwise
   have to carve an exception for.

3. **Claim-schema richness vs. existing draft.** A's technique-driven schema (with
   `anchor_quote`, integer `line_start`/`line_end`, `reasoning`) wins over B's leaner
   `Claim` dataclass draft. Adopted in §3. No human call needed unless the local model
   cannot reliably emit `anchor_quote` (resolve via §9 eval, not by dropping the field).

---

## 0a. Verified symbol map (from `906l7z`)

The real `caliper part` v0 names, verified by reading the sibling branch. Use these,
not the placeholder names in the original draft. Everything below this section has been
reconciled to them.

| Draft placeholder | Real symbol on `906l7z` | Notes |
|---|---|---|
| `Bucket` enum | **`ChangeType`** (`core/models.py`) | values: `generated, move, delete, binary, config, test, logic` — exact match for the 7 buckets |
| `PartMetadata` | **`Part`** (`core/models.py`) | fields: `id`, `files: list[str]` (sorted), `bucket: ChangeType`, `size: int`, `opened_by: Kerf`, `oversized: bool` |
| ordered cut list | **`CutList`** (`core/models.py`) | `parts`, `ambiguities`, `size_cap`, `provenance`, `stats`; bottom-of-stack first; "a proposal, never a verdict" |
| `part()` (pure upstream) | **`core.parting.part(records, cfg, provenance=None) -> CutList`** | pure, deterministic, callable with no repo/git — exactly the upstream pure function the LLM is sealed against |
| stock producer (impure) | **`core.part_stock.build_stock`** | the impure git step; `Record` (`file, change_type, size, old_path`) is the per-file unit |
| PARTING registry | **`PARTING: Registry[AnalyzerPort]`** (`core/registries.py:60`) | **EXISTS** — see §8 correction |
| parting plugin (consumer) | **`plugins/_parting.py` `PartingPlugin`** | underscore-prefixed (autodiscover skips it), self-registers into `PARTING` not `ANALYZERS`, `can_run` always `False` — isolation already built |
| config | **`core/repo_config.py PartingConfig`** | `size_cap`, `rename_threshold`, etc.; `config_digest()` is pure |

**Two corrections that change the spec below:**

- **C1 — `Part` carries `files` + `size` only, NOT hunk ranges.** v0 is **whole-file**
  (one `Record` per file, no hunk-level split). The anchor rule (§6 rule 2) therefore
  **cannot** read hunk ranges off `Part`; the per-part diff/hunks must be passed into
  `adjudicate()` separately (carried on `ReviewRequest.part_diff`, parsed with
  `pr_review.parse_hunk_ranges`). Reflected in §6.
- **C2 — naming collision: `core/part_gate.py` already exists** and is the parting
  **safety** gate (jj reversibility preconditions, fail-closed, via `ToolRunnerPort`) —
  **unrelated** to the LLM-review Tier 0. Do **not** name the Tier 0 module `part_gate`.
  The spec keeps `core/llm_review/tier0.py` (class `PartScopedGate`), which avoids the
  clash. Note also `part_gate` is fail-**closed**; Tier 0 review gating stays advisory.

---

## Guardrails (invariants — carried verbatim, non-negotiable)

- The **decision path is deterministic, the review is not.** The defensible claim is
  "no LLM output reaches a human or a gate without passing a deterministic function
  you can test," not "no LLM touches review."
- **Tier 2 is a pure function, sibling of `part()`:** input is claims + part metadata
  + Tier 0 findings, output is filtered claims, no IO, property-tested.
- The LLM is **sealed between two pure functions** (`part()` upstream, adjudicator
  downstream) and isolated behind a port, the way the `PARTING` registry is
  structurally isolated from the auto pipeline.
- **Advisory and manual.** This never gates a build and is developer-invoked, like
  `caliper part`. Output is comments, plus optionally a deterministic Tier 0 verdict
  that already existed.
- **Reproducibility-in-practice:** cache LLM output keyed on part content hash so a
  part reviews identically until it changes.
- **Per-part isolation is blind to cross-part defects.** A final **integration pass**
  over assembled `backup+::@` is required.
- **The flywheel:** an advisory claim that recurs across many parts is a signal to
  write a new deterministic Tier 0 detector. The LLM is a discovery mechanism for
  Tier 0 rules.

---

## 1. Module / seam map

```
PROPOSED  src/caliper/core/llm_review/
  routing.py      BUCKET_GATES (bucket->registry keys) + CATEGORY_COMPAT map   [DET side]
  tier0.py        PartScopedGate, Tier0Result                                  [DET side]
  adjudicator.py  adjudicate()  PURE, NO IO  [Tier 2]                          [DET side]
  port.py         LlmReviewPort Protocol, Claim, ReviewRequest, ReviewResponse [ADV side]
  context.py      lower-part assembly (signatures), ReviewRequest builder      [ADV side]
  cache.py        ReviewCachePort + filesystem/null adapters                   [ADV side]
  pipeline.py     Tier 1 orchestrator: cache -> port -> adjudicator            [ADV side]

REUSED (already in repo):
  registry.py / core/registries.py     Registry[T] + new LLM_REVIEWERS key
  core/tool_runner.py                  TEMPLATE for LlmReviewPort (ToolRunnerPort/ToolResult)
  core/llm_client.py                   transport for the OpenAI-compat / oMLX adapter
  core/pr_review.py:23,34              anchor rule (parse_hunk_ranges / line_in_hunks)
  core/normalizer.py                   dedup/collapse (Tier 0 + Tier 2 rules 6/7)
  core/diff.py:235                     unified-diff per-file before/after (stock cut)
  core/seal.py                         SHA-256 for content-hash cache key
  detectors/_registry.py, framework.py per-file Tier 0 gates (CAL-001..021)
  RULE_RUNNERS / CODEGRAPH_CHECKS      semgrep + graph Tier 0 gates
  plugins/scribes/code_graph.py        symbol signatures for lower-part context
  core/concern_review.py               prior-art fan-out (packet / source_block / run_audit) — fix transport
  data/parquet_writer.py + cli/query_cmd.py  flywheel aggregation
  composition/bootstrap.py             wiring + Null/Fake adapter pattern

ISOLATION: the DET side may NOT import the ADV side or core/llm_client.py.
           Enforced by a contract test (sibling of tests/unit/test_port_registries.py).

UPSTREAM (exists on 906l7z, unmerged here — §0.1, §0a):
  core/parting.py        part(records, cfg, provenance) -> CutList   PURE upstream
  core/part_stock.py     build_stock(...)                            impure git producer
  core/models.py         ChangeType, Record, Part, Kerf, CutList, Provenance, CutStats
  core/registries.py:60  PARTING: Registry[AnalyzerPort]             isolation template (§8)
  plugins/_parting.py    PartingPlugin (can_run=False)               consumer, autodiscover-skipped
  core/part_gate.py      parting SAFETY gate (jj) — NOT Tier 0       naming-collision warning (§0a C2)
The whole pipeline consumes a CutList of Part(s). Merge 906l7z first.
```

Tier separation maps onto caliper's `cli -> core -> data` import-downward rule. The
**deterministic side** (`routing`, `tier0`, `adjudicator`) and the **advisory side**
(`port`, `context`, `cache`, `pipeline`) are two sub-packages of `core/llm_review/`;
the advisory side may import the deterministic side, never the reverse.

---

## 2. The claim schema (Tier 1 output contract)

The contract the whole of Tier 2 depends on. A's technique wins: `anchor_quote` is the
load-bearing anti-hallucination field (CR-Bench measured GPT-5.2 whole-PR review at
3.56% precision — verbatim quotes are hard to fabricate and turn the anchor rule into a
string-membership test). Emitted via **constrained decoding** (≈99.9% schema
compliance) — but valid JSON ≠ true claim; truth is verified downstream in Tier 2.

```python
# core/llm_review/port.py  (frozen dataclass; the JSON the model emits maps 1:1)
@dataclass(frozen=True)
class Claim:
    file: str                      # MUST be one of the part's files (Tier 2 rule 1)
    line_start: int                # 1-based inclusive
    line_end: int                  # inclusive
    anchor_quote: str              # VERBATIM copy of the flagged source line(s) — join key
    category: Category             # closed enum (<15); drives Tier 2 rule 4
    severity: Severity             # info|low|medium|high — NOT a verdict
    confidence: Confidence         # low|medium|high — model self-report; display/rank only
    assertion: str                 # one sentence: what is wrong
    reasoning: str                 # why; captured for flywheel + audit, NEVER gates
    suggested_fix: str | None = None
    evidence_ref: str | None = None  # null from model; Tier 2 fills it (post-hoc join)
```

```python
class Category(StrEnum):           # closed set, <15 (constrained-decoding friendly)
    CORRECTNESS_BUG, NULL_DEREF, RESOURCE_LEAK, CONCURRENCY, INJECTION, AUTH,
    CRYPTO_MISUSE, ERROR_HANDLING, API_CONTRACT, PERF, STYLE, MAINTAINABILITY,
    TEST_GAP, OTHER
class Severity(StrEnum):  INFO, LOW, MEDIUM, HIGH         # never a verdict
class Confidence(StrEnum): LOW, MEDIUM, HIGH
```

Rules of the contract:
- The model **never** emits a verdict, a caliper rule id, or `evidence_ref`. `ReviewResponse`
  has no allow/deny field — "claims, never a verdict" is made structural by the type.
- `severity`/`confidence` are self-reports used only for ranking/display and as a drift
  signal; they never drive the gate.
- `reasoning` is mandatory (chain-of-thought capture powers the flywheel) but advisory.

```python
@dataclass(frozen=True)
class ReviewRequest:
    part_id: str; bucket: ChangeType; part_diff: str
    lower_context: str; tier0_findings: list[Tier0Finding]; content_hash: str
@dataclass(frozen=True)
class ReviewResponse:
    part_id: str; claims: list[Claim]; raw_text: str   # no verdict field, by design
```

---

## 3. Tier 0 — deterministic gate (part-scoped), bucket routing

### Reuse inventory (Agent B)

| Gate | Symbol / path | Scoping today | Part-scopable |
|---|---|---|---|
| AST detectors CAL-001..021 | `DeterministicScanner` `detectors/scanner.py:26`; `BugDetector.detect(file_path)` `detectors/framework.py:150` | per-file | **native** — iterate part files |
| semgrep / opengrep | `SemgrepRunnerPort` `core/ports.py:59` `run(changed_files,...)` | changed-files | **native** — pass `part.files` |
| code-graph SQL checks | `CodeGraphCheckPort` `core/ports.py:73` `run_checks(changed_files)` | changed-files | **native** |
| secret scanning | scanner plugins / `agent/tools.py scan_code` | plugin-level | **adapter** (post-filter to `part.files`) |
| supply-chain / OSV | `plugins/supply_chain.py`, `data/scanners` | repo / manifests | **adapter**; OSV supports `--experimental-exclude`, not include |
| cdk/cfn/kube/cpd/complexity | `plugins/_runners/*.py` | file-list or repo | **adapter** |

### Adapter: `PartScopedGate` (`core/llm_review/tier0.py`)

1. Resolve part files via `core/file_source.py select_file_source` (keeps exclusions).
2. Per-file gates: loop `part.files`.
3. changed-files gates: pass `part.files`.
4. `ScannerPort.scan(target_path)` is single-path (`core/ports.py:43`) → pass each file,
   or post-filter findings with `finding.file in part.files` (reuse the
   `if fpath in cluster_rels` idiom at `concern_review.py:172`).
5. Return typed `Tier0Result`; dedup via `core/normalizer.py normalize_findings`
   (highest-severity-wins, `_SEVERITY_RANK`).

### Bucket → gate routing table (`core/llm_review/routing.py`)

`BUCKET_GATES: dict[ChangeType, tuple[str, ...]]` whose values are **keys into existing
registries** (`detectors/_registry.py DETECTORS`, `RULE_RUNNERS`, `CODEGRAPH_CHECKS`,
`AnalyzerRegistryPort`). Mirrors `bootstrap.build_scribes` (`composition/bootstrap.py:250`)
resolving named scribes from `SCRIBES`. Routing imports only registry keys + the
deterministic registries — never the LLM path (§8).

| Bucket | Tier 0 gate set | Reaches Tier 1? |
|---|---|---|
| generated | checksum + stamp assert only | No |
| binary | size + malware/secret scan | No |
| delete | structural-delete assert (no content to review) | No |
| move | structural-identity assert (reuse `diff.extract_file_content_from_diff` `diff.py:235`) | No |
| config | supply-chain/dependency gates + `docker_pin_drift` detector | Rarely |
| test | full detector set, severity-floored | Optional |
| logic | **full gate**: detectors + semgrep + code-graph + secrets | **Yes** |

Tier 1 runs **only** on parts that clear Tier 0 and whose bucket needs judgment
(mostly `logic`). Prior art forces a division of labor: **Tier 0 carries recall, Tier 1
stays brief** (the inverse of CodeRabbit's noisy tuning) — this is the differentiator.

---

## 4. Tier 1 — LLM review behind a port (advisory only)

**Recommendation: a new `LlmReviewPort`, modeled exactly on the real `ToolRunnerPort`**
(`core/tool_runner.py` + `SubprocessToolRunner`). Rejected alternatives: routing through
`agent/` (a presentation-tier entry point, not a swappable model port) and copying
`concern_review.py`'s direct-`httpx`-in-core call (the leak in §0.2).

```python
# core/llm_review/port.py  (core-owned, like ToolRunnerPort)
@runtime_checkable
class LlmReviewPort(Protocol):
    def review(self, request: ReviewRequest) -> ReviewResponse: ...
```

- New core registry `LLM_REVIEWERS: Registry[LlmReviewPort]` in `core/registries.py`.
- Adapters (data tier): `OmlxReviewer` (**default** — local oMLX, OpenAI-compatible
  endpoint, offline reproducibility-in-practice) and `OpenAICompatReviewer` (cloud
  fallback). **Both delegate transport to `core/llm_client.py LlmClient`** (fail-open,
  returns `""` on failure, `SecretStr` key, already documented as decision-path-isolated).
- `NullReviewer` ("LLM disabled") → empty claims, exactly like `NullRepository` /
  `_FakeToolRunner` (`bootstrap.py:91`). Tests use `NullReviewer`/`_FakeReviewer`, never
  a live model.
- Swappable exactly like `ToolRunnerPort -> SubprocessToolRunner` vs `_FakeToolRunner`.

### Model default & fallback (Agent A)

- **Default: local oMLX, Qwen3.6 ~27B-class** (sits at the cited 32B-class
  practical-minimum recall floor for pre-merge review; 7B/gemma fall below the floor →
  demote to a pre-pass only).
- **Fallback: cloud frontier**, triggered on low-confidence claims or oversized parts.
- Per-part scoping (small, clean context) is what closes the local-vs-cloud quality gap.
  **Confirm the default via the §9 post-Tier-2 eval before trusting it** — pick the
  cheapest model whose *post-Tier-2* recall and SNR are within margin of cloud.

---

## 5. Context presentation & assembly (Agent A technique, Agent B placement)

Token budget order: **(1) PR/issue prose first** (a 2025 benchmark: +72–78% F1 vs
diff-only, and more F1 per token than code context), **(2) the part diff + Tree-sitter
smallest-enclosing-scope per hunk**, **(3) signatures of the lower parts** the part
calls, **(4) full lower-part text only when a symbol is directly referenced.**

- **Lower parts = signatures, NOT full text.** Open/local models *degrade* with longer
  context (−1.05% Pass@1; "more susceptible to noise from longer contexts") — pruning
  matters *more* for the local default. Source signatures from
  `plugins/scribes/code_graph.py` rather than model-generated summaries (a summary is
  itself un-anchored).
- **Assembly module** `core/llm_review/context.py` reuses the diff producer
  (`diff.py:235` per-file before/after; `pr_review.py:23` hunks) and the
  `concern_review.build_packet` shape (`concern_review.py:235`), adding `part_diff` and
  `lower_context` as **separate labeled fields**.
- **Read-only boundary, enforced two ways:** (a) the Tier 1 adapter is only ever handed
  `part_diff` as the review target; `lower_context` renders inside a Jinja2 template
  (under `templates/`) in an explicit "READ-ONLY — do not review" block; (b) **Tier 2's
  scope rule deterministically drops any claim on a lower-part file** not in the current
  part's set. The prompt is advisory; the scope rule is the gate.

---

## 6. Tier 2 — the pure adjudicator (sibling of `part()`)

- **Module:** `core/llm_review/adjudicator.py` (deterministic side, pure).
- **Signature:**
  `def adjudicate(claims: list[Claim], part: Part, hunks: HunkRanges, tier0: Tier0Result) -> AdjudicationResult`
  (`Part` is the real `core/models.py` type. `hunks` is passed **separately** — see C1:
  `Part` carries `files` + `size` only, not hunk ranges, so the per-part changed lines
  come from `ReviewRequest.part_diff` parsed via `pr_review.parse_hunk_ranges`.)
- **Output:** `AdjudicationResult(survivors: list[Claim], drops: list[Drop])`; each
  `Drop` records the **firing rule** (for logging + the §10 flywheel).
- **No IO.** No file reads (the part's file set comes from `Part.files`, the changed
  lines from the pre-parsed `hunks` argument), no network, no DB. Same discipline as the
  already-pure `core/normalizer.py`.

### Rules, in firing order

The **six mandated rules** (verbatim from Shared context), plus **one A-recommended
addition** (rule 6, "collapse-into-Tier-0") that no mandated rule covers — it fights the
alert-fatigue failure mode every benchmark cites. It is additive and does not weaken any
invariant; flagged as a technique recommendation, not a mandated rule.

1. **scope** — drop `claim.file not in part.files`.
2. **anchor** — drop claims not on a real changed line. **Reuse `pr_review.parse_hunk_ranges`
   + `line_in_hunks` (`pr_review.py:23,34`)** — already pure and tested. Hunks come from
   the `hunks` argument (parsed from `part_diff`), **not** from `Part` (C1). Verify
   `anchor_quote` is a verbatim substring of the changed lines *first*, so line numbers
   are trustworthy before any join.
3. **substantiation (post-hoc evidence binding)** — for each `blocking` claim, search the
   part's Tier 0 findings for one whose line range overlaps and whose category is
   compatible per a static `CATEGORY_COMPAT` map (in `routing.py`). Match → set
   `evidence_ref`, keep blocking. **No match → downgrade to advisory, never delete.** The
   model is **never** asked for caliper rule ids (it would fabricate them); Tier 2 binds
   from data the model never saw. (Optional A/B: opaque handles `F1/F2` in context.)
4. **category allow-list per bucket** (same `BUCKET_GATES`/bucket source).
5. **severity floor per bucket.**
6. **collapse-into-Tier-0 (added, A)** — if a claim's `(file, line, category)` collides
   with an existing Tier 0 finding the human already has, collapse it as corroboration
   rather than emit a duplicate comment.
7. **dedup/collapse** — reuse severity-rank collapse (`normalizer.py:38-45`).

Survivors are the review output; drops are logged.

### Property tests (`tests/unit/test_adjudicator.py`, `TestProperties`, DPS-12)

| Domain | Type | Property |
|---|---|---|
| Integrity | SAFETY | an out-of-scope claim never survives |
| Determinism | INVARIANT | idempotent; survivor set independent of input order |
| Monotonicity | SAFETY | substantiation only downgrades, never deletes; `survivors ⊆ inputs` |
| Boundedness | PERFORMANCE | `len(survivors) <= len(claims)` |

"No IO" is asserted by running `adjudicate` with network + filesystem patched to raise.

---

## 7. Caching — part-content-hash-keyed (reproducibility-in-practice)

- **Key:** SHA-256 (via **`core/seal.py`**, the existing evidence hash chain) over a
  canonicalized `(part_diff, lower_context, bucket, model_id, prompt_version,
  tier0_findings_digest)`. No `lru_cache`/`diskcache` layer exists in core today — this
  is net-new but reuses `seal.py` for the key.
- **Store:** content-addressed JSON under `.temp/` (the writable mount per CLAUDE.md).
  Module `core/llm_review/cache.py` with `ReviewCachePort` + filesystem adapter + null
  adapter (mirrors `NullRepository`).
- **Invalidation:** purely by key — any content/model/prompt change yields a new key;
  stale entries simply never hit. No mutation logic.
- **Placement:** the lookup sits **in front of** the `LlmReviewPort` call, inside the
  Tier 1 orchestrator (`pipeline.py`); the port stays pure transport.
- **Claim:** same (part content, model, prompt) → same cached `ReviewResponse` on re-run
  — a deterministic *result* on cache hit, **without asserting the model is
  deterministic.** Document exactly as `llm_client.py` documents isolation.

---

## 8. Structural isolation — "no LLM in the decision path"

Enforced the way caliper already enforces tier boundaries: by **import direction** plus a
**contract test**. **Correction:** the `PARTING` registry is **not** non-existent — it is
real (`core/registries.py:60`, `PARTING: Registry[AnalyzerPort]`) and is the **exact
template to copy**, not something to substitute. `plugins/_parting.py` already
demonstrates the pattern: underscore-prefixed so `autodiscover` skips it, self-registers
into `PARTING` rather than `ANALYZERS`, and `can_run` is always `False` — so it is
structurally impossible for parting to enter `caliper review` / Foreman / the webhook.
The new `LLM_REVIEWERS` registry + the deterministic/advisory split below apply that same
isolation to the LLM path.

1. Two sibling sub-packages in `core/llm_review/`:
   - **deterministic side** (`tier0.py`, `adjudicator.py`, `routing.py`) imports only
     `detectors/`, `normalizer.py`, `pr_review.py`, and registries. It must **NOT**
     import `port.py`, `pipeline.py`, `cache.py`, `context.py`, or `core/llm_client.py`.
   - **advisory side** (`port.py`, `pipeline.py`, `context.py`, `cache.py`) may import the
     deterministic side; the deterministic side never imports back.
2. **Contract test** (sibling of `tests/unit/test_port_registries.py`) asserting
   `adjudicator.py`/`tier0.py` have **zero transitive imports** of the LLM adapters and
   `llm_client`.
3. **The port is the only door:** Tier 1 is reachable only via `LLM_REVIEWERS` resolution
   wired in `composition/bootstrap.py`. Tier 0/2 never resolve from it. A registered
   `NullReviewer` → empty claims → adjudicator on `[]` → `[]` survivors; the gate is
   unaffected and fail-open (like `build_default_scribes` / `NullRepository`).

Pre-existing violation to fix (see §0.2): `core/concern_review.py`'s direct `httpx` LLM
call. Either route it through `LlmReviewPort` or keep `audit` legacy and build part-review
cleanly on the port.

---

## 9. Eval harness (plugs into BATTLEARENA)

CR-Bench-style harness with four metric families (Agent A).

- **Ground truth:** (1) **seeded-bug corpus** — `git blame` to the introducing commit,
  reintroduce on a clean fork, run the reviewer; keep only bugs validated as
  "detectable via review." (2) **real-PR usefulness corpus** — developer-acted-on signal,
  approximated offline against the eventual fix.
- **Metrics:** precision = bug hits / total comments; recall = bug hits / total bugs; F1;
  **usefulness** = (bug hits + valid suggestions) / total; **SNR** = (bug hits + valid
  suggestions) / noise (the key metric — recall trades against SNR); **nit rate**
  (fraction at severity ≤ low); **per-rule Tier 2 drop rate** (the diagnostic that makes
  "sealed by a testable function" defensible — instrument every rule).
- **Harness:** fix corpus + part-cutter output; sweep `(model, context-strategy,
  sampling-N)`; run Tier 1 → the **same** Tier 2 → score. Report **all metrics pre- and
  post-Tier-2** to quantify what Tier 2 buys. Cache on part-content hash for cheap
  reproducible reruns. Drive through BATTLEARENA.
- This eval is the **definition-of-trust gate**: the feature is not trusted until it has
  run, and it is what decides the model default (§4) and whether self-consistency
  multi-sampling (raises recall, cuts SNR) is worth enabling.

---

## 10. Integration pass (cross-part defects)

Per-part isolation is blind to bugs that exist only because part 3 and part 7 interact —
mandatory per the invariants, and prior art confirms it (skipping it reproduces Graphite
Diamond's low cross-part catch rate).

- **How it runs:** a separate Tier 1 invocation with a single synthetic "whole-stock"
  part — file set = union of all parts, `part_diff` = the full assembled `backup+::@`
  diff. It still passes Tier 0 (full gate over the union) and the **same** Tier 2
  adjudicator (scope = union file set, so cross-file claims survive that per-part review
  would have dropped).
- **Reuses:** `PartScopedGate` over the union, the same `LlmReviewPort`, the same
  adjudicator, and `concern_review.run_audit`'s canary + ThreadPool fan-out
  (`concern_review.py:418`).
- **Distinguished output:** tag each integration `Claim` with `origin = CROSS_PART` (and
  `part_id = "@integration"`); render under a "Cross-part findings" heading, separate
  from per-part claims.

---

## 11. Flywheel — recurring advisory → new Tier 0 detector

- **Aggregation:** the adjudicator's structured `survivors`/`drops` (each with `category`
  + firing rule) are persisted via the existing analytics path — `data/parquet_writer.py`
  + `data/catalog.py` — one row per adjudicated claim `(content_hash, file, category,
  severity, rule_fired, part_bucket, timestamp)`, the same hash+time evidence persistence
  the pipeline already uses.
- **Recurrence query:** a `caliper` subcommand (sibling of `query`, `cli/query_cmd.py`)
  groups by `(category, normalized_message)` with a count threshold to surface recurring
  advisories.
- **Mechanism:** the report emits a **detector-stub proposal** (category + representative
  file/line + scaffold pointing at `detectors/framework.py BugDetector` +
  `register_detector` `_registry.py:46` + the `# tested-by:` convention). **Human-gated —
  never auto-writes a detector** (that would put LLM output in the decision path). A
  recurring advisory graduating to a CAL-0xx detector is the intended endpoint: the LLM
  is a discovery mechanism for Tier 0 rules.

---

## 12. Consumer-first, test-first build sequence

Split RED/GREEN across agents per CLAUDE.md (context-poisoning prevention). Tests run in
containers (`make test`); the LLM port uses `Null`/`Fake` reviewers in tests, never live.

0. **(Blocked on §0.1) Merge/rebase `906l7z` onto this branch.** `part()`, `CutList`,
   `Part`, `ChangeType`, `build_stock`, and the `PARTING` registry already exist there —
   do **not** rebuild them. Note v0 is whole-file (no hunk split); the per-part diff for
   the anchor rule is derived downstream from the stock, not carried on `Part` (C1).
1. **`adjudicator.py` (Tier 2) — pure, build first after part().** RED: the §6 property
   tests from acceptance criteria. GREEN: on top of `pr_review` anchor + `normalizer`
   dedup. No IO; fully testable without any LLM.
2. **`routing.py` + `tier0.py` (Tier 0).** RED: bucket→gate-set + part-scoping +
   `CATEGORY_COMPAT` tests. GREEN: wrap existing detectors/semgrep/graph via registries.
3. **`port.py` + `NullReviewer` + `_FakeReviewer`.** RED: claims-never-verdict contract;
   null yields `[]`. Wire `LLM_REVIEWERS`.
4. **`context.py` + `cache.py`.** RED: read-only-boundary test (lower-part claims dropped)
   + cache hit-reproducibility test. GREEN.
5. **`pipeline.py` (Tier 1).** Compose cache → port → adjudicator.
6. **Isolation contract test** (§8).
7. **Integration pass** (§10), then **flywheel persistence + query** (§11).
8. **CLI command** `caliper part-review` (sibling of `review`/`audit` in `cli/main.py`) —
   advisory + manual, never gating.
9. **Eval harness** (§9) wired into BATTLEARENA; run before trusting the feature; it
   decides the model default.

---

## 13. Risk list (from the internal study)

1. **`part()` exists on `906l7z` but is unmerged here** — Step 0 is a merge/rebase, not
   a build (see §0.1, §0a). Risk is integration/merge, not greenfield. v0 is whole-file
   with no hunk split, so the anchor rule needs the per-part diff passed separately (C1).
2. **`concern_review.py` is a decision-path leak waiting to be copied** — copy its
   structure, not its direct-`httpx` transport (§0.2, §8).
3. **`ScannerPort.scan(target_path)` is single-path** (`core/ports.py:43`); plugin gates
   (secrets, OSV) don't take a file set; OSV only supports exclude. `PartScopedGate` must
   post-filter by `finding.file in part.files`.
4. **The cutter exists on `906l7z`** — `core.part_stock.build_stock` (impure git stock)
   + `core.parting.part` (pure cut). Risk #4 from the internal study ("net-new cutter")
   is **retired** once `906l7z` is merged; until then it is just unmerged.
5. **No cache layer in core** — content-hash cache is net-new (reuse `seal.py` for the key).
6. **No `LlmReviewPort`/`LLM_REVIEWERS` yet** — `LlmClient` is concrete, not a Protocol
   behind a registry; add the port + registry for swap/isolation like `ToolRunnerPort`.
7. **`ChangeType` + `Part`/`CutList` are the shared contract** (already defined on
   `906l7z`, `core/models.py`) — consume them, do not redefine. The LLM-review tiers
   import these types; the routing table (§3) keys on `ChangeType`.
8. **Category→detector compat map is caliper-specific** — no canonical published mapping;
   build `CATEGORY_COMPAT` against caliper's detector/semgrep catalog (A's open gap).
9. **Local model at the recall floor** — Qwen3.6 ~27B sits at the threshold; only the §9
   post-Tier-2 eval can confirm it clears the bar.

---

## Definition of done for this spec

- ✅ Both findings docs exist (`findings_external.md` with citations,
  `findings_internal.md` with file paths), each with a "decisions for synthesis" list.
- ✅ This build spec exists; the one hard A/B conflict (`part()` absence) and the two
  judgment calls are surfaced in §0, not left silent.
- ✅ Every Shared-context invariant is carried verbatim as a guardrail.
- ✅ Tier 2 is a pure, property-tested function; the LLM is behind a port and structurally
  out of the decision path (§6, §8).
- ✅ An eval plan (§9) is defined that must run before the feature is trusted.
