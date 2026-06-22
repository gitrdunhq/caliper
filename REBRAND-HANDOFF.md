# Caliper Rebrand — Session Handoff

**Work branch — same name in every repo:** `claude/sleepy-einstein-o5zd76`

| Repo | Branch | State |
|------|--------|-------|
| `gitrdunhq/eedom` (Caliper) | `claude/sleepy-einstein-o5zd76` | renamed + pushed |
| `gitrdunhq/datum` | `claude/sleepy-einstein-o5zd76` | renamed + pushed |
| `gitrdunhq/eedom-community-rules` → `caliper-community-rules` | `claude/sleepy-einstein-o5zd76` (use same name) | pending — repo out of scope |

**Status:** eedom + datum renamed and pushed. `caliper-community-rules` pending (out of scope).
**Last session date:** 2026-06-22

The datum-ax stack rebrand. Naming family — **Caliper** (scanner, was eedom) *measures*,
**Scribe** (enrichment layer) *records*, **Foreman** (PR-review agent, was GATEKEEPER) *signs off*.

---

## ✅ Done and pushed

### `gitrdunhq/eedom` → Caliper (this repo) — branch `claude/sleepy-einstein-o5zd76`
- Package `src/eedom` → `src/caliper`; all imports; `EedomSettings` → `CaliperSettings`;
  console script `eedom` → `caliper`; pyproject/hatch/ruff; `uv.lock` regenerated.
- **Hard env cutover** `EEDOM_*` → `CALIPER_*` (no fallback shim) across config, CI, Docker,
  `action.yml`, scripts.
- **Scribe** (was detect-then-enrich / ADR-006): `core/enrich.py`→`scribe_pass.py`,
  `core/enrichment.py`→`scribe.py`, `plugins|detectors/enrichers`→`scribes`; `EnricherPort`→
  `ScribePort`, `*Enricher`→`*Scribe`, `Enrichment`→`ScribeNote`, `ENRICHERS`→`SCRIBES`; config
  `enabled_scribes`/`scribe_timeout`; output key `metadata['scribe']` (JSON + SARIF properties).
- **Detector IDs** `EED-001..021` → `CAL-001..021`.
- **Foreman** (was GATEKEEPER agent): `GATEKEEPER_*`→`FOREMAN_*`, agent module branding,
  `.github/workflows/gatekeeper.yml` → `foreman.yml`.
- Containers/images, release-please, dotfiles (`.caliperignore`, `.caliper/`, `.caliper.yaml`),
  brand strings, docs. **CHANGELOG history left intact** (only new entries use Caliper).
- Validated: ruff ✓, black ✓, all modules import ✓, lock resolves ✓, **opengrep AST scan = 0
  residual `eedom`/enrichment identifiers** across 162 py files.

### `gitrdunhq/datum` → Caliper integration — branch `claude/sleepy-einstein-o5zd76`
- `datum/eedom_blast_radius.py` → `caliper_blast_radius.py` (`caliper_available`,
  `_CALIPER_AVAILABLE`, `caliper-graph.sqlite`); `agent_loop.py` import + post-GREEN Caliper
  gate comments; `tests/test_eedom_blast_radius.py` → `test_caliper_blast_radius.py`.
- Optional dep import now `from caliper.plugins._runners.graph_builder import CodeGraph`.
- Vendored semgrep rules: `eedom-plugin`→`caliper-plugin`, `references:` URL →
  `gitrdunhq/caliper-community-rules`.
- Dotfiles renamed to `.caliper*`.
- **Scoped to the eedom family only** — datum's GitNexus "enrichment" and the generic
  "gatekeeper" word were deliberately left untouched.
- Validated: `caliper_blast_radius` suite 9 passed / 2 skipped (skips need the Caliper package
  installed); imports clean; **zero new test failures** (6 pre-existing `agent_loop` failures
  fail identically on baseline).

---

## ⏳ Pending — `gitrdunhq/eedom-community-rules` → `caliper-community-rules`
Could not be done last session: the repo is **outside session scope** and the repo-add tools
(`claude-code-remote` MCP) were not available. The canonical `KIRBY-SEC-*` security rules live
here; datum vendors a copy.

**To pick up:** once the repo is added to session scope —
1. Survey contents (rules, README, CI, metadata).
2. eedom→Caliper rename, eedom-family only: branding, `eedom-plugin`→`caliper-plugin`,
   self-referencing URLs → `caliper-community-rules`. **Keep rule `id`s** (descriptive, not
   branded) and **`KIRBY-*` ids** (external taxonomy) unchanged — zero consumer impact.
3. Validate the ruleset parses (`semgrep/opengrep --validate`); confirm no residual `eedom`.
4. Re-vendor the renamed rules into datum's `policies/semgrep/` to prevent drift.
5. Commit + push to `claude/sleepy-einstein-o5zd76`.

**Live risk — stale URLs (decided: keep new URLs):** datum already cites
`caliper-community-rules`, which **404s until the GitHub repo is actually renamed** (GitHub
redirects are old→new only). Rename the repo close to when this work merges.

---

## 📋 Out-of-band human actions (cannot be done from a session)
- Rename GitHub repos `eedom`→`caliper`, `eedom-community-rules`→`caliper-community-rules`
  (auto-redirects old URLs).
- Rename/create the GHCR `caliper` package; re-push images; update registry tokens.
- Register `caliper` on PyPI (old `eedom` name abandoned).
- Update branch-protection required-check names (`Dom Review` → `Foreman Review`).
- Rename working dirs `../eedom`→`../caliper` so datum's editable Caliper integration path resolves.
- Re-run release-please once (package-name changed → fresh release component).

## ⚠️ Verification gap
The **full Caliper container test suite did not run** last session — no container runtime was
available (Docker client but no daemon; no podman), and CLAUDE.md forbids the host-test
override. Run `bash scripts/build-test.sh` (or `make test`) on a container host, or rely on the
`foreman.yml` CI workflow, to fully validate before merge.

---
*Tooling note: the rename used an ordered scoped text pass + `git mv`, with opengrep 1.20.0
(the project's own pinned binary) as the AST-level verifier. No substring collisions exist
in-repo (`Eedom`/`EEDOM`/`EED-`/`eedom` only; "freedom" etc. absent from tracked source).*
