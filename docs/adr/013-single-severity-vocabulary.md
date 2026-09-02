# ADR-013: One severity vocabulary at the plugin boundary

## Status

Accepted (2026-09-02)

## Context

Every scanner speaks its own severity dialect: semgrep and opengrep emit `ERROR` / `WARNING` / `INFO`, OSV and trivy emit CVSS-derived `CRITICAL` ... `LOW`, GitHub advisories say `moderate`, SARIF says `note`. Before this decision those strings leaked past the plugins as-is. The renderer sorted `ERROR` after `info` because it was not in its rank table, the score weights silently treated it as zero, and the OPA policy compared lowercase literals against upstream uppercase ones. Worst, a semgrep `ERROR` was at one point mapped to `critical`, which let a "likely bug" pattern match block a merge with the same force as a CVSS 9 remote code execution.

## Decision

There is exactly one severity vocabulary inside caliper: the `FindingSeverity` enum in `src/caliper/core/models.py` with the values `critical`, `high`, `medium`, `low`, `info`, in that order. Every upstream string is translated to it once, at the plugin boundary, and never again.

- `normalize_severity` in `src/caliper/core/models.py` is the only translator. It lowercases, applies the alias table, and falls back to `info` for anything unrecognised (fail-open: an unknown label never blocks a build).
- The alias table is fixed: semgrep `ERROR` maps to `high`, never `critical` (an `ERROR` means "likely bug", not CVSS 9+); `WARNING` maps to `medium`; `INFO` and SARIF `note` map to `info`; `moderate` maps to `medium`.
- `normalize_finding` in `src/caliper/core/plugin.py` calls `normalize_severity` when it builds the frozen `PluginFinding`, so a typed finding cannot carry an off-vocabulary severity. The semgrep plugin (`src/caliper/plugins/semgrep.py`) normalises at parse time as well so even its raw dict findings are already in vocabulary.
- Everything downstream — the renderer's ordering and icons, the severity and quality scores, the semgrep severity floor, the policy input, SARIF level mapping — reads the enum and holds no alias knowledge of its own.

## Consequences

- Severity ordering, scores, and policy decisions are comparable across scanners and across time; a golden-file test and a Hypothesis ordering property pin the rendered order.
- Adding a scanner means adding at most an alias row, not a new comparison branch anywhere else.
- Some upstream nuance is lost (CVSS 9.0 and 10.0 are both `critical`); the raw upstream value remains available in the finding's `metadata` for anyone who needs it.
- A scanner that emits a new label caliper has not seen will surface as `info` until the alias table is extended, so new-scanner work must include a severity fixture.
