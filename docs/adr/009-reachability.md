# ADR-009: Vulnerability reachability scribe (declared-vs-imported, tier 1)

## Status

Accepted

## Context

A vulnerability finding on a declared dependency says nothing about whether the
vulnerable code path is actually reachable from the scanned repo — a transitive dev
dependency that's never imported carries the same severity in the report as one wired
into the request path. Fits the detect-then-scribe seam exactly (ADR-006): this is
context attached to a finding, never a verdict, so it stays deterministic, zero-LLM,
fail-open, and time-bounded.

The one real unknown is mapping a PyPI/npm/etc. **distribution name** (what a vuln
finding's `package` field holds, e.g. `PyYAML`) to the **import name** the code graph
actually indexes (`yaml`). These frequently diverge (`beautifulsoup4` → `bs4`,
`pillow` → `PIL`, `python-dateutil` → `dateutil`) and there is no universal registry
of the mapping.

## Decision

**Tier 1 (this ADR): declared-vs-imported.** Resolve the finding's `package` to an
import name, then query the code graph's `imports` edges (already populated by
`graph_builder._add_import_edge` for every `import`/`from ... import ...` in indexed
Python — `CodeGraph.imports_module(name)`, new query added alongside `symbol_at`). No
import edge for the resolved name anywhere in the repo ⇒ `reachable=False`.

**Import-name resolution** (`core/import_resolution.py`, pure): three-step fallback,
each deterministic:
1. A small curated map for the well-known cases where the import name has no
   mechanical relationship to the distribution name (`pyyaml`→`yaml`,
   `beautifulsoup4`→`bs4`, `pillow`→`pil`, `python-dateutil`→`dateutil`, …).
2. `importlib.metadata` `top_level.txt` lookup — only useful when the *scanned repo's*
   dependency happens to also be installed in caliper's own venv (it usually isn't,
   since caliper scans arbitrary target repos without executing their environment).
   Kept as a best-effort win when it applies (e.g. caliper's own dogfooding), not
   relied on as the primary mechanism.
3. Heuristic fallback: lowercase, `-`/`.` → `_`. Covers the large majority of PyPI
   packages, where the import name is a mechanical transform of the distribution name
   (`django`→`django`, `requests`→`requests`).

**Failure mode is `reachable=None`, never a false `False`.** Resolution fails (step 3
doesn't produce a valid Python identifier) only for pathological names; in that case
the scribe attaches `reachable=None` with an evidence note, and policy (below) treats
`None` exactly like "don't know" — it must never downgrade a verdict.

**Tier 2 (deferred, noted not built):** when an advisory names specific affected
symbols, walk `CodeGraph.blast_radius(symbol)` to check whether project code actually
reaches the vulnerable symbol, not just the module. This needs advisory data caliper
doesn't currently parse (OSV `affected[].ecosystem_specific` symbol lists are
inconsistent across ecosystems) — left for a follow-up ADR once a concrete data source
is chosen.

**Policy (opt-in, off by default):** `rules_enabled.unreachable_vuln_exemption` in
`policies/policy.rego`, mirroring `dev_scope_exemption` — downgrades a critical/high
vuln `deny` to `warn` **only** when `input.metadata.scribe.reachability.reachable ==
false`. Never triggers on `null`.

## Consequences

- New scribe `ReachabilityScribe` (`plugins/scribes/reachability.py`), registered in
  `SCRIBES`. Not in `DEFAULT_SCRIBES` initially (opt-in via `enabled_scribes`) since it
  adds a per-finding graph query on top of the existing `code_graph` scribe's build
  cost — cheap, but no reason to force it on repos that don't use the exemption policy.
- `CodeGraph.imports_module` is a new deterministic query — same cost class as
  `symbol_at`/`blast_radius` (single indexed lookup, no full-graph walk).
- `core/import_resolution.py` is pure (no I/O beyond the best-effort, exception-guarded
  `importlib.metadata` call) — Determinism and Availability (fail-open) property tests
  apply directly.
- The curated map is small and will grow by accretion as gaps are found in practice —
  documented as a known, bounded limitation rather than a correctness bug.
- Property-test target (DPS-12): **SAFETY** — `reachable=None` never causes the OPA
  exemption to fire (only a fixture-level test at the OPA layer; the scribe itself just
  needs to never emit `False` for an unresolved import name).
