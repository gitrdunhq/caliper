# LLM Review — Internal Findings (Agent B)

How the three-tier per-part LLM review design grafts onto the actual caliper
repo at `/home/user/caliper`. Every claim is grounded in real files/symbols.
Agent B did **not** build the feature; this is a mapping + seam study.

## Ground-truth status of prerequisites (verify-first)

| Brief claim | Reality in repo | Evidence |
|---|---|---|
| `caliper part` "built, v0" | **ABSENT.** No part/PARTING/kerf/cut-list/stock code exists anywhere in `src/`, `tests/`, or git history. | No file matches `*part*`; grep for PARTING/kerf/cut_list/cutlist/parting over `src/caliper` returns only unrelated "Dockerfile"/"partition" substrings; `git log --all` grep for part/kerf/parting is empty; `pyproject.toml [project.scripts]` has no `part` entry. |
| PARTING registry isolated from auto pipeline | **DOES NOT EXIST.** No PARTING registry. The *pattern* it should mimic exists: `Registry[T]` in `src/caliper/registry.py` + per-area registries in `src/caliper/core/registries.py`. | `src/caliper/registry.py:22` (`class Registry[T]`), `src/caliper/core/registries.py`. |
| ToolRunnerPort | **EXISTS** — exactly the model to copy for the LLM port. | `src/caliper/core/tool_runner.py` — `ToolInvocation`, `ToolResult`, `ToolRunnerPort` Protocol (`run(invocation) -> ToolResult`). Concrete: `src/caliper/core/subprocess_runner.py` `SubprocessToolRunner`. |
| scribe + taskfit LLM quarantine | **EXISTS.** | `core/scribe_pass.py` + `SCRIBES` registry; taskfit `core/taskfit.py`; shared transport `core/llm_client.py` (`LlmClient`). |
| agent/Copilot path | **EXISTS.** | `src/caliper/agent/` (`tools.py`, `main.py`, `prompt.py`). |
| analyzer/plugin registries | **EXISTS.** | `src/caliper/registry.py`, `core/registries.py`, `detectors/_registry.py` (`DETECTORS`). `AnalyzerRegistryPort` at `core/ports.py:120`. |
| Blast Radius CodeGraph | **EXISTS.** | `plugins/scribes/code_graph.py` (`graph.blast_radius(symbol)`, capped `_MAX_CALLERS=25`). |

**Headline:** the upstream half (`part()` / cut list / stock) is **not built**.
The brief's "built, v0" is incorrect for this repo. Everything below that consumes
a "part" consumes a *proposed* data structure; flagged where it must be produced first.

**Closest existing prior art for the whole pipeline:** `core/concern_review.py`
(the "Alley-Oop" / `caliper audit` command, CLI `main.py:527`). It already does:
cluster files -> run deterministic scanners -> attach findings -> build a per-cluster
packet -> fan out to an advisory LLM -> render markdown. The per-part review loop in
embryonic form. Most reusable module AND the biggest anti-pattern to fix (Q3, Q8).

---

## Q1 — Tier 0 reuse: which deterministic gates become part-scoped

| Gate | Symbol / path | Scoping unit today | Part-scopable? |
|---|---|---|---|
| AST bug detectors (CAL-001..021) | `DeterministicScanner` `detectors/scanner.py:26`; `BugDetector.detect(file_path)` `detectors/framework.py:150` | **per-file**, filtered by `target_files` glob + category + severity | **Yes, natively** — iterate the part's file set. |
| semgrep / opengrep | `SemgrepRunnerPort` `core/ports.py:59` (`run(changed_files, repo_path, ...)`); `plugins/_runners/semgrep_runner.py` | **changed-files list** | **Yes, natively** — pass `part.files`. |
| Code-graph SQL checks | `CodeGraphCheckPort` `core/ports.py:73` (`run_checks(changed_files)`) | **changed-files list** | **Yes, natively.** |
| Secret scanning | via scanner plugins / `agent/tools.py scan_code` | plugin-level | **Adapter needed** — constrain to `part.files`. |
| Dependency / supply-chain | `plugins/supply_chain.py`, OSV `data/scanners` | manifests, repo-wide | **Adapter needed**; OSV honors `--experimental-exclude`, not include. |
| cdk-nag/cfn-nag/kube-linter/cpd/complexity | `plugins/_runners/*.py` | file-list or repo | **Adapter** to filter to part. |

**Native path scoping:** detectors, semgrep, code-graph checks. **Needs adapter:**
plugin-level repo scanners and `ScannerPort.scan(target_path)` (single path,
`core/ports.py:43`).

**Adapter to specify: `PartScopedGate`** (proposed `core/llm_review/tier0.py`):
1. Resolve part files via existing `core/file_source.py select_file_source` (keep exclusions).
2. Per-file gates: loop `part.files`.
3. changed_files gates: pass `part.files`.
4. `ScannerPort.scan` gates: pass each file, or post-filter findings to
   `finding.file in part.files` (reuse the `if fpath in cluster_rels` idiom at
   `concern_review.py:172`).
5. Return typed `Tier0Result`; dedup via `core/normalizer.py normalize_findings`
   (highest-severity-wins, `_SEVERITY_RANK`).

---

## Q2 — Bucket routing: bucket -> gate set

| Bucket | Tier 0 gate set | Reaches Tier 1? |
|---|---|---|
| generated | checksum + stamp assert only | No |
| binary | size + malware/secret scan | No |
| move | structural-identity assert (reuse `diff.extract_file_content_from_diff` `diff.py:235`) | No |
| config | supply-chain/dependency gates + `docker_pin_drift` detector | Rarely |
| test | full detector set, severity-floored | Optional |
| logic | **full gate**: detectors + semgrep + code-graph + secrets | **Yes** |

**Lives in `core/llm_review/routing.py`** as `BUCKET_GATES: dict[Bucket, tuple[str,...]]`
whose values are **keys into existing registries**: detector ids ->
`detectors/_registry.py DETECTORS`; semgrep/graph/scanners -> `RULE_RUNNERS`,
`CODEGRAPH_CHECKS`, `AnalyzerRegistryPort`. Mirrors `bootstrap.build_scribes`
(`composition/bootstrap.py:250`) resolving named scribes from `SCRIBES`. `Bucket`
is an Enum (CLAUDE.md). Routing imports only registry keys + deterministic
registries — never the LLM path (Q8).

---

## Q3 — Tier 1 placement: where the LLM call lives

- **Option A — `agent/` Copilot path: rejected.** Presentation tier parallel to
  CLI (CLAUDE.md L82, `agent/tools.py evaluate_change/scan_code`); an entry point,
  not a swappable model port.
- **Option B — `taskfit` + `llm_client`: partial.** `LlmClient`
  (`core/llm_client.py`) is the right *transport* (OpenAI-compat, fail-open,
  returns "" on failure, SecretStr key, documented decision-path-isolated) but is
  a **concrete class, not a Protocol behind a registry**; taskfit is package
  advisory, not a code-review fan-out.
- **Option C — `concern_review.HolisticReviewer`: closest behavior** (clusters->
  scan->fan-out->advisory) **but** bypasses `LlmClient` and calls `httpx.Client`
  directly with hardcoded Anthropic/OpenRouter endpoints + `FREE_FALLBACKS`
  (`concern_review.py:265-380`). That direct-httpx-in-core is the leak to avoid.

**Recommendation: new `LlmReviewPort`, modeled on `ToolRunnerPort`.** Protocol in
`core/llm_review/port.py` (core-owned like `ToolRunnerPort`); concrete adapters in
data tier; new core registry `LLM_REVIEWERS: Registry[LlmReviewPort]` in
`core/registries.py`.

```python
# core/llm_review/port.py  (PROPOSED)
@dataclass(frozen=True)
class ReviewRequest:
    part_id: str; bucket: Bucket; part_diff: str
    lower_context: str; tier0_findings: list[dict]; content_hash: str
@dataclass(frozen=True)
class Claim:                      # structured, NEVER a verdict
    file: str; line: int; category: str; severity: str
    message: str; evidence_ref: str | None
@dataclass(frozen=True)
class ReviewResponse:
    part_id: str; claims: list[Claim]; raw_text: str
@runtime_checkable
class LlmReviewPort(Protocol):
    def review(self, request: ReviewRequest) -> ReviewResponse: ...
```

Adapters: `OmlxReviewer` (local oMLX, **recommended default** for offline
reproducibility-in-practice) posting to a local OpenAI-compatible endpoint via
`LlmClient`; `OpenAICompatReviewer` delegating transport to `core/llm_client.py`.
Swappable exactly like `ToolRunnerPort` -> `SubprocessToolRunner` (real) vs
`_FakeToolRunner` (`bootstrap.py:91`). The port returns **claims, never a
verdict** — enforced by the type (no allow/deny field on `ReviewResponse`).

---

## Q4 — Tier 2 module: the pure adjudicator (sibling of part())

- **Module:** `core/llm_review/adjudicator.py` (core tier, pure).
- **Signature:** `def adjudicate(claims: list[Claim], part: PartMetadata, tier0: Tier0Result) -> AdjudicationResult`
- **Inputs:** LLM claims, part metadata (file set, bucket, changed-line ranges),
  Tier 0 findings (for substantiation).
- **Output:** `AdjudicationResult(survivors, drops)`; each drop records the firing
  rule (logging + flywheel Q9).
- **No IO.** No file reads (part carries its file set + hunk ranges), no network,
  no DB; caller logs. Same discipline as the already-pure `core/normalizer.py`.

**Rules in firing order (each a pure helper, individually tested):**
1. **scope** — drop `claim.file not in part.files`.
2. **anchor** — drop claims not on a changed line. **Reuse**
   `pr_review.parse_hunk_ranges` + `line_in_hunks` (`pr_review.py:23,34`) — already
   pure + tested; the exact anchor primitive.
3. **substantiation** — blocking claim with no `evidence_ref` to a Tier 0 finding
   is **downgraded to advisory, not deleted** (brief invariant).
4. **category allow-list per bucket** (same `BUCKET_GATES` source).
5. **severity floor per bucket.**
6. **dedup/collapse** — reuse severity-rank collapse `normalizer.py:38-45`.

**Property tests** (`tests/unit/test_adjudicator.py`, `TestProperties`, DPS-12):
Integrity/SAFETY (out-of-scope claim never survives), Determinism/INVARIANT
(idempotent + order-independent survivor set), Monotonicity/SAFETY (substantiation
only downgrades, never deletes; survivors subset of inputs), Boundedness/PERFORMANCE
(`len(survivors)<=len(claims)`). "No IO" asserted by running with network+fs patched
to raise.

---

## Q5 — Context assembly: lower parts as read-only context

For part N, read-only context is parts 0..N-1 ("::part-").
- **Reuse the diff producer:** generic unified-diff -> per-file before/after at
  `diff.py:235` (`extract_file_content_from_diff`); hunks at `pr_review.py:23`. The
  "stock" is the whole diff; each part is a slice. Assemble lower context by joining
  lower parts' text exactly as `concern_review.review_concern` builds `source_block`
  (`--- {rel_path} ---\n{content}`, `concern_review.py:291`).
- **Packet shape exists:** `concern_review.build_packet` (`concern_review.py:235`)
  `{concern,tier,file_count,findings,source}` is the `ReviewRequest` template; add
  `lower_context` + `part_diff` as **separate labeled fields**.

**Boundary (structural, not prompt-based):** the assembler
(`core/llm_review/context.py`) emits `part_diff` (the one part under review) and
`lower_context` (read-only) as distinct fields; the Tier 1 adapter is only ever
handed `part_diff` as the target; a Jinja2 template (under `templates/`, like
existing PR-comment templates) renders `lower_context` in an explicit
"READ-ONLY — do not review" block. **Tier 2 enforces it again deterministically:**
the scope rule drops any claim on a lower-part file not in the current part's set.
The prompt is advisory; the scope rule is the gate.

---

## Q6 — Caching: part-content-hash-keyed LLM output

- **Key:** SHA-256 of canonicalized `(part_diff, lower_context, bucket, model_id,
  prompt_version, tier0_findings_digest)`. **Reuse `core/seal.py`** (existing
  SHA-256 chain for evidence) — no `diskcache`/`lru_cache` cache layer exists in
  core (only `seal.py`, `data/parquet_writer.py`, `data/catalog.py` hash/parquet).
- **Store:** content-addressed JSON under `.temp/` (already the writable mount per
  CLAUDE.md). Module `core/llm_review/cache.py` with `ReviewCachePort` + filesystem
  adapter + null adapter (mirrors `NullRepository`/`_FakeToolRunner`).
- **Invalidation:** purely by key; any content/model/prompt change -> new key; old
  entries never hit. No mutation/staleness logic.
- **Where:** lookup sits **in front of** the `LlmReviewPort` call, in the Tier 1
  orchestrator (`core/llm_review/pipeline.py`); the port stays pure transport.

**Reproducibility-in-practice:** same (part content, model, prompt) -> same cached
`ReviewResponse` on re-run. Deterministic *result* on cache hit without asserting
the *model* is deterministic. Document like `llm_client.py` documents isolation.

---

## Q7 — Integration pass over assembled backup+::@

- **How it runs:** a separate Tier 1 invocation with a single synthetic
  "whole-stock" part: file set = union of all parts, `part_diff` = full diff. Still
  passes Tier 0 (full gate) and Tier 2 (adjudicator with union scope).
- **Reuses:** `PartScopedGate` (Q1) over the union, same `LlmReviewPort`, same
  adjudicator; only new step is assembly (reuses cut-list ordering + diff producer).
  Structurally what `concern_review.run_audit` already does across clusters
  (`concern_review.py:418`) — canary + ThreadPool fan-out directly reusable.
- **Distinguished output:** tag each integration `Claim` with `part_id="@integration"`
  (or `origin: CROSS_PART` enum on `Claim`); render under a "Cross-part findings"
  heading. Its Tier 2 scope uses the union file set, so cross-file claims survive
  that per-part review would have dropped.

---

## Q8 — Structural isolation: "no LLM in the decision path"

**Pattern to copy:** caliper enforces tier isolation by import direction
(cli->core->data, CLAUDE.md L72) and registries decoupling consumers from adapters.
The decision path (detectors, normalizer, adjudicator, OPA) must be structurally
unable to import the LLM path.

**Concrete boundary:**
1. **Two sibling sub-packages in `core/llm_review/`:**
   - **deterministic side** (`tier0.py`, `adjudicator.py`, `routing.py`) imports
     only `detectors/`, `normalizer.py`, `pr_review.py`, registries. Must NOT import
     `port.py`, `pipeline.py`, `cache.py`, `context.py`, or `core/llm_client.py`.
   - **advisory side** (`port.py`, `pipeline.py`, `context.py`, `cache.py`) may
     import the deterministic side; the deterministic side never imports back.
2. **Contract test** (sibling of `tests/unit/test_port_registries.py`) asserting
   `adjudicator.py`/`tier0.py` have zero transitive imports of the LLM adapters +
   `llm_client`. Structural equivalent of the brief's PARTING isolation.
3. **The port is the only door:** Tier 1 reachable only via `LLM_REVIEWERS`
   resolution wired in `composition/bootstrap.py`. Tier 0/2 never resolve from it.
   A registered `NullReviewer` ("LLM disabled") -> empty claims -> adjudicator on
   `[]` -> `[]` survivors; gate unaffected, fail-open (like `build_default_scribes`
   / `NullRepository`).

**Current violation to fix:** `core/concern_review.py` puts an `httpx.Client` LLM
call directly in core, no port, no registry. Reusing it as-is inherits the leak.
Fix: route its LLM call through `LlmReviewPort` too, or keep `audit` as legacy and
build the part-review pipeline cleanly on the port.

---

## Q9 — Flywheel: recurring advisory claims -> new Tier 0 detector

- **Aggregation:** adjudicator emits structured `drops`/`survivors` with
  `category` + firing-rule per claim. Persist via existing analytics path —
  `data/parquet_writer.py` + `data/catalog.py` (and `cli/query_cmd.py` exposes
  `query`). Write each adjudicated claim as a row `(content_hash, file, category,
  severity, rule_fired, part_bucket, timestamp)` — same evidence-style hash+time
  persistence the pipeline already uses.
- **Recurrence query:** group by `(category, normalized_message)` with a count
  threshold to surface recurring advisories.
- **Mechanism:** a `caliper` subcommand (sibling of `query`) or report section
  listing high-recurrence categories and emitting a **detector-stub proposal**:
  category + representative file/line + scaffold pointing at
  `detectors/framework.py BugDetector` + `register_detector` (`_registry.py:46`) +
  `# tested-by:` convention. **Human-gated** — never auto-writes a detector (that
  would put LLM output in the decision path). Recurring advisory -> CAL-0xx is the
  intended graduation path.

---

## Module / seam map (three tiers)

```
PROPOSED  src/caliper/core/llm_review/
  routing.py      BUCKET_GATES enum->registry-keys     (det side)
  tier0.py        PartScopedGate, Tier0Result          (det side)
  adjudicator.py  adjudicate() PURE  [Tier 2]          (det side)
  port.py         LlmReviewPort Protocol, Claim, ...   (advisory side)
  context.py      lower-part assembly, ReviewRequest   (advisory side)
  cache.py        ReviewCachePort + fs/null adapters   (advisory side)
  pipeline.py     Tier1 orchestrator: cache->port->adj (advisory side)

REUSED (in repo):
  registry.py / core/registries.py    primitive + new LLM_REVIEWERS key
  core/tool_runner.py                 TEMPLATE for LlmReviewPort
  core/llm_client.py                  transport for OpenAI-compat/oMLX adapter
  core/pr_review.py:23,34             anchor rule (parse_hunk_ranges/line_in_hunks)
  core/normalizer.py                  dedup/collapse (Tier 0 + Tier 2 rule 6)
  core/diff.py:235                    unified-diff per-file before/after (stock cut)
  core/seal.py                        SHA-256 for content-hash cache key
  detectors/_registry.py, framework.py  per-file Tier 0 gates
  RULE_RUNNERS / CODEGRAPH_CHECKS     semgrep + graph Tier 0 gates
  core/concern_review.py              prior-art fan-out (packet/source_block/run_audit)
  data/parquet_writer.py + cli/query_cmd.py  flywheel aggregation
  composition/bootstrap.py           wiring + Null/Fake adapter pattern

ISOLATION: det side may NOT import advisory side or llm_client; enforced by a
contract test (sibling of tests/unit/test_port_registries.py).

UPSTREAM GAP: part()/cut-list/stock/PartMetadata DO NOT EXIST and must be built
first. The whole pipeline consumes PartMetadata + ordered cut list.
```

---

## Consumer-first, test-first build sequence

0. **Build part() + PartMetadata + Bucket enum first** (brief assumed it exists; it
   does not). Cut list ordered bottom-first; per-part file set + hunk ranges + bucket.
1. **adjudicator.py (Tier 2) — pure, build first after part().** RED: property
   tests (Q4) from acceptance criteria. GREEN: on top of `pr_review` anchor +
   `normalizer` dedup. No IO; testable with no LLM.
2. **routing.py + tier0.py (Tier 0).** RED: bucket->gate-set + scoping tests.
   GREEN: wrap existing detectors/semgrep/graph via registries.
3. **port.py + NullReviewer + _FakeReviewer.** RED: claims-never-verdict contract;
   null yields []. Wire `LLM_REVIEWERS`.
4. **context.py + cache.py.** RED: read-only-boundary test (lower-part claims
   dropped) + cache hit-reproducibility test. GREEN.
5. **pipeline.py (Tier 1).** Compose cache->port->adjudicator.
6. **Isolation contract test** (Q8).
7. **Integration pass (Q7)** then **flywheel persistence + query (Q9).**
8. **CLI command** `caliper part-review` (sibling of `review`/`audit` in
   `cli/main.py`), advisory + manual, never gating.

---

## Risk list (fragile / unknown)

1. **part() does not exist.** Biggest risk; the design's upstream input is unbuilt.
   "v0 built" is false here. Step 0 mandatory.
2. **concern_review.py is a decision-path leak waiting to be copied** — direct
   `httpx` in core, hardcoded endpoints + FREE_FALLBACKS, bypasses LlmClient and any
   port. Copy its structure, not its transport.
3. **ScannerPort.scan(target_path) is single-path** (`core/ports.py:43`); plugin
   gates (secrets, OSV) don't take a file set; OSV only supports exclude. PartScopedGate
   must post-filter by `finding.file in part.files`.
4. **diff.py only parses dependency manifests** into structured deps. Generic code-diff
   hunk extraction exists (`extract_file_content_from_diff`, `parse_hunk_ranges`) but
   there is NO "cut a diff into ordered parts" producer — the stock->parts cutter is net-new.
5. **No cache layer in core** (only seal.py + parquet). Content-hash cache is net-new
   (reuse seal for the key).
6. **No LlmReviewPort/LLM_REVIEWERS yet.** LlmClient is concrete, not a Protocol behind
   a registry — must add the port + registry for swap/isolation like ToolRunnerPort.
7. **Tests run in container** (CLAUDE.md). Adjudicator property tests are CPU-only and
   container-friendly; the LLM port uses Null/Fake reviewer in tests (never live).
8. **Bucket enum + part metadata are a shared contract** between unbuilt part() and
   every tier here; define once, as an Enum.

---

## Decisions for synthesis (internal side)

1. **Build part() first.** Absent; brief's "v0 built" is wrong for this repo. Cut
   list + PartMetadata + Bucket enum are prerequisites.
2. **Tier 1 = new LlmReviewPort modeled on ToolRunnerPort**, with LLM_REVIEWERS
   registry + Null/Fake adapters. Reuse LlmClient for transport; recommend local-oMLX
   OmlxReviewer default for offline reproducibility-in-practice. Do NOT route through
   agent/ or copy concern_review's direct-httpx call.
3. **Tier 2 adjudicator is pure** (`core/llm_review/adjudicator.py`), reusing pr_review
   anchor + normalizer dedup; property-tested as a sibling of part(). The port type
   makes "claims, never a verdict" structural.
4. **Isolation enforced by import direction + a contract test** (the way tier
   boundaries are enforced today) — det side cannot import the LLM path. Concrete
   substitute for the non-existent PARTING isolation.
5. **Reuse concern_review's packet/fan-out structure for context + integration pass**,
   but fix its transport leak.
6. **Cache key = SHA-256 (via seal.py) over part content + lower context + model +
   prompt version**; filesystem store in .temp/. Reproducible on cache hit without
   claiming model determinism.
7. **Flywheel reuses parquet (parquet_writer/catalog) + query command** to aggregate
   recurring advisories and emit human-gated detector-stub proposals.
8. **Open question:** migrate legacy `caliper audit` (concern_review) onto the new
   port, or keep separate? Migrating removes the only in-core LLM transport leak.
