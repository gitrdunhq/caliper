# ADR-007: Supply-Chain Version-Bump Threat Analysis

## Status

Accepted

## Context

Supply-chain attacks rarely show up as a CVE. They arrive as a *new release* of an already-trusted
dependency: a maintainer account is compromised (or sold), and version `X.Y.Z+1` quietly adds a
`postinstall` script that exfiltrates secrets, an obfuscated blob, or a new outbound network call.
caliper already detects that `pkg X.Y → X.Z` (`core/diff.py`, `core/sbom_diff.py`) and fetches package
*metadata* (`data/pypi.py`), but it never looked at **what code changed between the two versions** —
which is exactly where the attack lives.

A Dependabot-style "watch the supply chain, analyze the bump" capability was requested, with the
explicit allowance that an **LLM may tell data-driven stories** about a bump. That has to be
reconciled with caliper's hard rule: **zero LLM in the decision path**.

## Decision

Add a **separate, feature-flag-gated step** — `caliper supply-chain-diff`
(`CALIPER_SUPPLY_CHAIN_DIFF_ENABLED=1`) — that is **not** part of the normal scan (it needs registry
egress and adds latency, so the default gate is untouched). The step is split into three layers with a
strict detect → gate → narrate separation:

1. **Fetch + diff (deterministic, `data/pkgsrc.py`).** Download both versions' distributions (PyPI
   sdist, npm tarball), extract them, and compute a deterministic `VersionDiff`. Archives are
   untrusted: `safe_extract` refuses absolute paths, `..` traversal (zip-slip / tar escape), and
   symlinks, and enforces total-size / file-count / single-file caps (zip-bomb defense).

2. **Score signals (deterministic, `core/supply_chain_diff.py`).** Turn the `VersionDiff` into
   `supply_chain` findings: new install hooks (critical), obfuscation/encoded payloads (high), newly
   introduced network/process-exec capability (high), publisher change (medium), plus info findings
   for clean upgrades and unfetchable sources.

3. **Gate via OPA (deterministic).** A new `supply_chain_diff` Rego rule denies on critical/high
   signals and warns on medium. The verdict is therefore produced entirely by deterministic signals +
   policy — never by a model.

4. **Narrate via LLM (advisory, opt-in, ADR-006).** The `supply_chain_threat` scribe (off by
   default) asks an LLM to tell the data-driven story of the bump over the *already-computed*
   deterministic facts and attaches it to `metadata['scribe']['threat_analysis']`. It is
   verdict-independent, fail-open, time-bounded, and structurally incapable of changing the decision.

## Consequences

- **Zero-LLM-in-decision-path is preserved.** The LLM only ever writes advisory metadata; the gate is
  OPA over deterministic signals. "The LLM tells data-driven stories" is satisfied without it deciding.
- **The trust boundary is explicit.** Archive extraction and the LLM prompt both treat package
  contents as untrusted (safe-extract caps; sanitized, capped facts placed in the user message). Both
  are covered by property tests (Integrity, Boundedness, Confidentiality/injection).
- **Fail-open end to end.** Blocked egress, a yanked release, a malformed archive, or an unavailable
  LLM degrade to an informational finding / unchanged finding — never a crash or a spurious block.
- **Separate step, not a plugin.** The analyzer needs the *diff* (old/new versions), which the
  `ANALYZERS` `run(files, repo_path)` contract does not carry, so it is its own CLI command and can run
  autonomously (e.g. a dedicated CI job) independent of the main review gate. Plugin count is unchanged;
  the only count change is OPA 6 → 8 rules.
- **PyPI + npm** ship first, behind one `PackageSourcePort` / `PACKAGE_SOURCES` registry; more
  ecosystems slot in behind the same port.
