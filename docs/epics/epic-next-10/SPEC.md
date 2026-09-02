# Epic: caliper next 10 — what the app needs to do better

Source: the 2026-09-01 cleanup session assessment, ranked. Every item below is a deterministic change; none adds an LLM to the decision path. All tests run in the container (`make test`); TDD red-green; one commit per logical unit; `docs/CAPABILITIES.md` updated for any user-visible change.

## Context

- Repo: `src/caliper/` (ports-and-adapters: `cli/`, `core/`, `data/`, `adapters/`, `plugins/`, `detectors/`). Guard tests enforce tier direction and file-size ratchets.
- Rendering: `core/renderer.py`, `core/actionability.py`, `core/review_summary.py`, `core/json_report.py`, `core/sarif.py`, templates in `src/caliper/templates/*.j2` (`comment.md.j2` is the PR comment).
- Exclusions: `core/ignore.py` (`DEFAULT_PATTERNS`, `TEST_PATTERNS`, `load_ignore_patterns`, `should_ignore`), consumed by `core/file_source.py`, `core/manifest_discovery.py`, `plugins/trivy.py`, `plugins/osv_scanner.py`.
- Dependency plugins: `plugins/osv_scanner.py`, `plugins/trivy.py`, `plugins/syft.py`. Severity vocabulary: `core/models.py` `FindingSeverity` / `normalize_severity`.
- Scan cache: `core/scan_cache_key.py` (ADR-010).
- CLI: `cli/main.py` (`review`), `cli/install_cmd.py` (`install-scanners`), `cli/review_cmd.py`.
- Release/publish: `.github/workflows/release-please.yml`, `pyproject.toml` `[project] name`.
- ADRs: `docs/adr/001..010`. Decommission record: `docs/decommission-log.md`.
- Dogfood: `.github/workflows/dogfood.yml`, `make dogfood`, `scripts/dogfood.sh`; baseline mechanism `cli/baseline_cmd.py` + `.caliper-baseline.yaml`.

## Requirements

### R1. Readable report (highest priority)
The markdown report (`caliper review`, default format, and the PR comment) must be readable by a reviewer in one pass.
- AC1: Health/quality/security scores are mutually consistent: a report never shows a 0/100 quality score alongside an A maintainability grade; the grade is derived from the same score, or the score line is dropped where the grade exists.
- AC2: Verdict wording distinguishes "findings block merge" from "scan incomplete"; the word "blocked" appears only when policy actually rejects; an incomplete scan says "incomplete" and lists the plugins that did not finish and why (timeout / not installed / crashed).
- AC3: The plugin table lists only plugins that ran or errored; skipped plugins are summarized in one line ("skipped: swiftlint (no .swift files), ls-lint (no .ls-lint.yml)").
- AC4: File paths are shown relative to the repo root, never as absolute container paths (`/workspace/...` → `...`).
- AC5: Detector (CAL-NNN) and complexity findings get their own sections with the same shape as semgrep's (severity icon, `file:line`, rule id, one-line message, fix suggestion when present).
- AC6: Findings within a section are ordered by severity (critical → info) then file; sections are ordered by highest severity present.
- AC7: The report is capped at 65,536 chars with truncation that states how many findings were omitted per section.
- AC8: A golden-file test renders a fixture `list[PluginResult]` and compares against a committed expected markdown; a property test asserts AC6 ordering for arbitrary finding lists.

### R2. Signal-to-noise on real repositories
- AC1: `TEST_PATTERNS` additionally matches directory components `*-tests`, `*_tests`, `*-test`, `*_test` (e.g. `compatibility-tests/`), still never `spec/` or `fixtures/`; look-alikes (`attest/`, `latest.ts`, `contest.py`) remain unmatched.
- AC2: `.caliperignore` supports per-path rule scoping with the syntax `<glob> !<rule-id-or-prefix>` meaning "under this path, drop findings whose rule id starts with this prefix" (e.g. `compatibility-tests/** !DS-`, `tools/docs/** !CAL-002`); parsed in `core/ignore.py` into a typed `RuleScope`; applied post-detection, pre-policy, in the normalizer path; unknown syntax raises a `ValueError` at load naming the line.
- AC3: A default semgrep severity floor: findings below `medium` from semgrep do not count toward the verdict or scores and render in a collapsed "notes" section; configurable via `.caliper.yaml` `thresholds.semgrep.min_severity` (default `medium`).
- AC4: `caliper init` documents both new knobs in the standard config comments.

### R3. Actionable dependency findings
- AC1: Every osv-scanner finding carries `file` = the lockfile/manifest path relative to the repo (from `results[].source.path`), and `line` when present (issue #484).
- AC2: osv-scanner and trivy findings carry `metadata.dependency_kind` ∈ {`direct`, `transitive`, `unknown`}, determined deterministically from the manifest that declares the package (pyproject/requirements/package.json/pom.xml/go.mod/Cargo.toml) via `core/manifest_discovery.py`.
- AC3: The report's dependency section groups by advisory, shows `package installed → fixed`, the declaring manifest, and `direct`/`transitive`, and ends with a deterministic "fix-first" list: the minimal set of direct bumps that clears every critical/high finding (transitive-only CVEs list the direct parent when it can be resolved, else "transitive: needs `<tool> dependency tree`").
- AC4: SARIF places dependency findings on the manifest file/line so they appear inline in PR review.

### R4. PyPI distribution name
- AC1: `pyproject.toml` `[project] name` changes from `caliper` to a free name (default proposal `caliper-review`; the import package and console script stay `caliper`); `uv.lock` regenerated.
- AC2: `release-please.yml` publish job's environment URL and `docs/CAPABILITIES.md`/README install instructions reference the new name.
- AC3: A test asserts the wheel's distribution name ≠ `caliper` and the console script is still `caliper`.
- Note: the PyPI trusted publisher must be registered by the owner (repo `gitrdunhq/caliper`, workflow `release-please.yml`, environment `pypi`); document this in README release section.

### R5. Reproducibility of live-DB verdicts
- AC1: trivy and osv-scanner results carry `metadata.db_version` / `metadata.db_updated_at` taken from the scanner's own output or DB metadata file; the report prints one "vulnerability data as of <timestamp>" line per scanner.
- AC2: The scan cache key (`core/scan_cache_key.py`) includes each live-DB scanner's `db_updated_at`, so a newer DB never serves a stale cached verdict; a test proves a changed DB timestamp changes the key and an unchanged one does not.
- AC3: JSON report schema (`docs/schema/report-v1.0.json`) gains the optional field; schema test updated.

### R6. ADRs match reality
- AC1: `docs/adr/001`, `002`, `003`, `004`, `008` status → `Superseded` with a dated pointer to the relevant `docs/decommission-log.md` entry.
- AC2: New ADRs (next free numbers) for: semgrep rules pinned to a local snapshot never the registry; test code excluded by default; one severity vocabulary at the plugin boundary (ERROR→high); tag-then-drop decommissioning with the log as the record.
- AC3: A test asserts every ADR has a `## Status` of Accepted/Superseded/Proposed and that no `Accepted` ADR references a module path that no longer exists in `src/caliper/`.

### R7. CI honesty about host tests
- AC1: The contract and e2e jobs in `foreman.yml` and `release-candidate.yml` run inside the test image (`scripts/build-test.sh`) instead of setting `CALIPER_ALLOW_HOST_TESTS`, OR CLAUDE.md's rule is amended to name those two jobs as the sanctioned exception with the reason. Pick the first unless the image cannot run them; state why in the commit.
- AC2: `test_github_actions_policy.py` asserts no workflow sets `CALIPER_ALLOW_HOST_TESTS` (or only the sanctioned jobs do).

### R8. Container runner from the CLI
- AC1: `caliper review --runner auto|container|native` (default `auto`); `auto` uses the container when a container engine (podman, then docker) is on PATH and the `caliper` image is present or pullable, else native with a one-line stderr notice.
- AC2: Container mode mounts the repo read-only at `/workspace`, `.temp` read-write, forwards `CALIPER_*` env vars and the CLI args verbatim, runs as the image's non-root user, and returns the container's exit code and stdout unchanged.
- AC3: `caliper part` always runs native (it needs the user's jj/git state).
- AC4: Tests exercise the argument/mount assembly through a fake `ToolRunnerPort`; no test spawns a real container.

### R9. `install-scanners` pins win over PATH
- AC1: `caliper install-scanners` installs into `--bin-dir` even when a same-named binary exists elsewhere on PATH, unless `--skip-present` is passed; the plan reports `present elsewhere: <path> (version mismatch unknown)` for such tools.
- AC2: `path_hint` tells the user the bin dir must precede the other location on PATH.
- AC3: The CI composite action relies on this (no behaviour change needed there beyond the flag default).

### R10. Dogfood is a real signal
- AC1: `make dogfood` / `dogfood.yml` runs the standard review on caliper itself and must produce verdict ≠ `blocked`; every currently-blocking finding is either fixed or baselined in `.caliper-baseline.yaml` with a `--reason` and TTL via `caliper baseline update`.
- AC2: `dogfood.yml` fails the job when the verdict is `blocked` or `incomplete` (previously it only uploaded SARIF).
- AC3: A unit test asserts the baseline file parses and no entry is expired at test time relative to a pinned "as of" date in the test (so expiry is visible in CI, not silent).

## Non-functional
- Zero LLM in any of the above. No new runtime dependencies without a lockfile entry ≥ 7 days old.
- Every new/changed source file keeps its `# tested-by:` annotation; count/ratchet guard tests updated in the same commit as the change that moves them.
- No file grows past its ratchet without a stated seam reason.

## Out of scope
- Wolfi base image; report HTML output; any change to `caliper part` beyond R8 AC3.
