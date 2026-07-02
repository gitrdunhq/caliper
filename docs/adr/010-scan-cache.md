# ADR-010: Cross-run incremental scan cache (whole-target key, tier 1)

## Status

Accepted

## Context

`ScanOrchestrator.run` re-runs every enabled scanner's `scan(target_path)` on every
pipeline invocation, even when nothing under `target_path` changed since the last run
against the same commit. Scanners today take a whole directory (`target_path`), not a
file list — `ScannerPort.scan` has no per-file granularity — so the cheapest correct
cache key is one covering the *entire scanned tree*, not individual files.

Three components must all agree for a cached `ScanResult` to be safely reused:

1. **The scanned content** — has `target_path`'s tree changed?
2. **The tool** — did the scanner's own logic change (a caliper release, a rule/config
   change) since the cached result was produced?
3. **The scan configuration** — did anything that affects scanner behavior (enabled
   scanners, exclusion paths, timeouts, file-source strategy) change?

## Decision

**Tier 1 (this ADR): whole-target key, ships first.**

```
key = sha256(tree_sha ++ "\0" ++ scanner_name ++ "\0" ++ tool_version ++ "\0" ++ config_digest)
```

- **`tree_sha`** — the target repo's `HEAD` commit SHA, via the existing
  `pipeline_helpers.resolve_git_sha(repo_path)` (already computed and stamped onto
  every `ReviewRequest` for provenance — no new git plumbing). When `resolve_git_sha`
  returns `None` (not a git repo, or `git` unavailable), caching is skipped entirely for
  that run — fail-open, scanners just run uncached. This deliberately does **not**
  detect a dirty working tree (uncommitted changes since `HEAD`): the cache can serve a
  stale hit against uncommitted local edits. Caliper's primary use is CI, where the
  scanned tree is always a clean checkout of a specific commit, so this is an accepted
  limitation for tier 1, not a correctness bug for the target use case. A future
  tier could hash `git status --porcelain` output into the key for the local/dev case.

- **`tool_version`** — the plan that scoped this work assumed "existing per-scanner
  version probes" exist; they do not (`ScannerPort` has no `version` property, and no
  adapter shells out for `--version`). Rather than build that machinery now, tier 1 uses
  `caliper.core.version.get_version()` — the installed caliper package version — as a
  single proxy for "did the code that produces this result change." Every scanner
  adapter ships inside the caliper package, so a caliper release is the actual unit of
  change for scanner *logic*; external tool binary versions (osv-scanner, trivy, …) are
  pinned by the container image and change only alongside a caliper image rebuild, which
  also bumps the package version. Per-scanner version probes are a candidate follow-up if
  a scanner's binary is ever allowed to float independently of the image.

- **`config_digest`** — new `core.scan_cache_key.settings_digest(config: CaliperSettings)`,
  following the existing `core.parting.config_digest` precedent (`sha256` over
  `orjson.dumps(..., option=orjson.OPT_SORT_KEYS)`), but scoped to only the
  `CaliperSettings` fields that actually affect scanner behavior: `enabled_scanners`,
  `osv_exclude_paths`, `scanner_timeout`, `combined_scanner_timeout`, `file_source`.
  A pipeline-wide `config_digest` covering *all* settings does not exist in the codebase
  today (only the `PartingConfig`-scoped one) — a narrower, scan-scoped digest avoids
  spurious misses from settings changes (LLM config, publisher tokens, …) that have no
  bearing on scanner output.

**Cache composition, not orchestrator changes.** `ScanOrchestrator.run` stays untouched.
A new `core.caching_scanner.CachingScanner` wraps any `ScannerPort` with a
`ScanCachePort`, presenting the same `ScannerPort` shape (`name`, `scan`). The pipeline
wraps each scanner returned by `get_scanners(context)` before constructing the
`ScanOrchestrator`, only when `resolve_git_sha` succeeds. This keeps the orchestrator's
parallel/timeout logic exactly as tested today and makes the cache an optional decorator,
not a structural dependency.

**Port + adapters** (mirrors every other optional collaborator in this codebase):

- `ScanCachePort` in `core/ports.py`: `get(key) -> ScanResult | None`, `put(key, result) ->
  None`. Structural `Protocol`, matching `ScannerPort`/`RepoSnapshotPort` style.
- `SCAN_CACHES: Registry[ScanCachePort] = Registry("scan_cache")` in
  `core/port_registries.py`.
- `data/scan_cache.py`: `SqliteScanCache` (single-table sqlite db, `<evidence_path>/
  scan_cache.sqlite`) registered as `"sqlite"`, and `NullScanCache` (always-miss, discards
  writes) registered as `"null"` — the same fail-open fallback shape as `NullRepository`/
  `NullPublisher`. `build_scan_cache(settings)` in `composition/bootstrap.py` tries
  `SqliteScanCache`, falls back to `NullScanCache` on any construction failure (unwritable
  evidence dir, etc.) — mirrors `build_decision_store`.

**Safety invariant — a failed scan is never cached as success.** `CachingScanner.scan`
only calls `cache.put(...)` when the fresh result's `status == ScanResultStatus.success`.
A `failed`/`timeout`/`skipped` result is returned to the caller normally but never
written to the cache, so a transient scanner failure can never poison a future run with a
false "clean" result, and a subsequent successful run always has the chance to overwrite
a prior miss.

**Tier 2 (deferred, noted not built).** Per-file cache entries would let an unchanged
file within a changed tree still hit — richer, but requires a `ScannerPort` contract
change (scan takes a file list, or returns per-file results) that several scanners
(`syft`, SBOM-wide tools) cannot naturally support. Left for a follow-up ADR if the
combined-timeout budget still doesn't hold after tier 1 lands.

## Consequences

- A CI run against an unchanged commit (same tree, same caliper version, same config)
  skips every scanner subprocess entirely — the dominant cost in the 300s pipeline
  budget on a repeat run (e.g. a re-triggered CI job, or the SBOM and diff pipelines
  scanning the same commit back-to-back).
- Cache correctness degrades gracefully to "always miss" whenever `tree_sha` is
  unavailable (non-git target) or the sqlite adapter can't initialize — never a hard
  failure, consistent with caliper's fail-open design rule.
- The uncommitted-changes gap (tree_sha only reflects `HEAD`) is an accepted, documented
  limitation for tier 1 — correct for the CI use case, imprecise for uncommitted local
  scans. `caliper review` on a dirty working tree may reuse a stale result from the last
  scan of the same `HEAD`; this is no worse than any other commit-SHA-keyed provenance
  already in the pipeline (`ReviewRequest.commit_sha`).
- Property-test targets (DPS-12): **Determinism** (same key inputs → same cache key,
  same round-tripped `ScanResult`), **SAFETY** (a failed/timeout/skipped result is never
  written to the cache under any status).
