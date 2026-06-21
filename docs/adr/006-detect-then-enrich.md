# ADR-006: Detect-then-Enrich — Deterministic Finding Enrichment

## Status

Accepted

## Context

eedom plugins **detect** findings (a vuln, a clone, a code smell) but emit them with thin context — a
file, a line, a message. A downstream consumer (the GATEKEEPER agent, a human reviewer, or datum-ax)
then has to *re-derive* the context it needs to act: what function is this in, who calls it, what's the
blast radius, is there a related rule match, where should a duplicated block be consolidated. That
re-derivation is expensive and, when an LLM does it, non-deterministic and token-hungry.

eedom already owns the deterministic tools to answer those questions — the `CodeGraph`
(`plugins/_runners/graph_builder.py`: symbols, edges, `blast_radius`), semgrep
(`_runners/semgrep_runner.py`), and AST helpers (`detectors/ast_utils.py`). They were just never
applied *to findings*.

## Decision

**Every finding is enriched after detection.** Detection and enrichment are two phases:

1. **Detect** (unchanged): a plugin produces findings.
2. **Enrich** (new): a deterministic pass attaches context to each finding — enclosing symbol, code-graph
   blast radius, related semgrep matches, and any other available deterministic signal — stored under
   `PluginFinding.metadata["enrichment"]` (additive; flows through `to_dict()` → JSON report and to the
   agent). The output is a **pre-computed packet** so a downstream LLM/human reasons with minimal effort.

**Enrichment is a shared service, not per-plugin code.** "Every plugin provides enrichment services"
means every finding *is enriched* by a shared layer — an `EnricherPort` + core-owned `ENRICHERS`
registry (mirroring the post-#404 ports pattern), with reusable adapters (`EnclosingSymbolEnricher`,
`CodeGraphEnricher`, `SemgrepEnricher`) that reuse eedom's own tools. Plugins do **not** each
re-implement CodeGraph/semgrep wiring — that would re-introduce the duplication the consolidation work
is removing. A plugin may declare `enrichment` scope tags so the right enrichers apply, and may ship a
bespoke enricher when it has special knowledge (the `cpd` plugin is the exemplar: clone groups enriched
with enclosing symbol + blast radius + a suggested consolidation home).

**Hard invariants (the gate stays a gate):**
- Enrichment is **deterministic** (pure functions of repo content; same input → same enrichment).
- Enrichment is **zero-LLM** and **never affects the verdict** — it only adds `metadata`. The decision
  path remains reproducible (ADR-006 does not touch policy/OPA).
- Enrichment is **fail-open and time-bounded**: an enricher error or timeout must never drop a finding,
  change a verdict, or block the build. On failure the finding passes through unchanged.

## Consequences

- Findings carry actionable context by construction; the agent/human/datum-ax consume a deterministic
  packet instead of re-deriving it (cheaper, reproducible — the "deterministic data → the LLM can tell
  the story" principle).
- New core seam: `EnricherPort` (`core/ports.py`), `ENRICHERS` registry (`core/registries.py`),
  `ApplicationContext.enrichers` + `get_enrichers` accessor, one enrichment pass in `core/pipeline.py`
  after `normalize_findings` and before policy. Adapters live in the tier of the tool they use
  (`CodeGraphEnricher` in `plugins`, `EnclosingSymbolEnricher` in `detectors`) and self-register into
  the core-owned registry, triggered by `composition.load_adapters` — same shape as every other port.
- New deterministic query `CodeGraph.symbol_at(file, line)` (enclosing symbol for a location) — the one
  missing graph primitive enrichment needs.
- Cost: one cached `CodeGraph` build per run (already the `blast_radius.py` pattern); per-finding
  enrichment is sub-10ms for graph/AST. Subprocess enrichers (semgrep) are opt-in / budgeted via the
  canonical `ToolRunnerPort` timeouts.
- Property-test targets (DPS-12): **Determinism** (same input → same enrichment), **Boundedness**
  (within the enrichment timeout), **Availability/fail-open** (an enricher failure never drops a finding
  or changes the verdict).
</content>
