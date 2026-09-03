# ADR-011: Semgrep community rules come from a pinned local snapshot, never the registry

## Status

Accepted (2026-09-02). Amended 2026-09-03: the local snapshot is **opt-in at build time**. The Semgrep Rules License v1.0 permits use only for your own internal business purposes and forbids distributing the rules or offering them as a service, so the published image no longer bakes the snapshot (`INCLUDE_SEMGREP_RULES=0`, the default). Building your own image with `--build-arg INCLUDE_SEMGREP_RULES=1` (or `INCLUDE_SEMGREP_RULES=1 bash scripts/build.sh`) restores it for internal use; host runs keep using `scripts/snapshot-semgrep-rules.sh`. Everything below about pinning, explicit `--config` paths and never touching the registry still holds; redistributable coverage now comes from `policies/semgrep`, the caliper-community-rules snapshot and its vendored MIT sets (see the Dockerfile).

## Context

caliper is a deterministic CI gate: the same commit scanned twice must produce the same verdict. The semgrep/opengrep community rules are the one scanner input that used to violate that. Registry packs (`p/default`, `p/python`, ...) are fetched over the network at scan time and change under you between runs — a rule added upstream on Tuesday turns a green Monday build red on Wednesday with no change to the code under review. The registry also needs outbound network from the scan container, which the hardened image does not otherwise require, and it is unavailable in air-gapped CI.

`semgrep/semgrep-rules` publishes no release tags, so there is nothing to pin by version.

## Decision

Community rules are read only from a local snapshot of `semgrep/semgrep-rules`, checked out at a single commit and baked into the image.

- The commit is pinned in one place, `SEMGREP_RULES_COMMIT` in `src/caliper/core/scanner_pins.py`, mirrored by the `Dockerfile` build argument that fetches the tarball into `/opt/caliper/semgrep-rules`.
- The runner in `src/caliper/plugins/_runners/semgrep_runner.py` resolves the language sub-directories the changed files call for inside that snapshot and passes each as an explicit `--config` path. A missing snapshot fails open to no community rules; it never falls back to the registry.
- caliper's own org rules (`policies/semgrep`) are passed explicitly alongside the snapshot so they apply to every target, not only to caliper's own checkout.
- The image build writes the pinned commit into `release-revisions.txt` next to the other tool revisions, so the rule set behind any scan is auditable from the image alone.

Bumping the snapshot is a deliberate, reviewed change: edit the pin, rebuild the image, and record the move in the commit. It is never implicit.

## Consequences

- Verdicts are reproducible from the image digest alone; no scan-time network access is needed for rules.
- Rule freshness lags upstream by however long the pin sits. Dependabot cannot bump it (no tags), so a periodic manual bump is part of release hygiene.
- The image carries the full rules tree; the runner only loads the directories relevant to the changed files, so scan time is unaffected.
- Any future registry integration must go through the same pin-and-snapshot path; a `p/...` config string in the runner is a bug.
