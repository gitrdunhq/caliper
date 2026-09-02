# ADR-012: Test code is excluded from scans by default

## Status

Accepted (2026-09-02)

## Context

Running the scanners over test code on real repositories produced a large share of the total findings and almost none of the actionable ones: hard-coded credentials in fixtures, `shell=True` in harness helpers, deliberately vulnerable pinned dependencies under `tests/e2e/fixtures/`, intentionally bad code that a detector test asserts is flagged. Each of those is correct in a test and wrong in production, and a gate that cannot tell the difference trains reviewers to ignore it.

The reviewer's question is "is the code we ship safe to merge", and test code does not ship.

## Decision

Test code is excluded from every scan unless the operator opts in.

- `TEST_PATTERNS` in `src/caliper/core/ignore.py` is the single list of test-code patterns: `tests/`, `test/`, `__tests__/`, the directory-name variants `*-tests/`, `*_tests/`, `*-test/`, `*_test/`, `testdata/`, and the per-language file conventions (`test_*.py`, `*_test.py`, `conftest.py`, `*_test.go`, `*.test.{js,jsx,ts,tsx}`, ...). It deliberately does not match `spec/` or `fixtures/` on their own, and look-alikes such as `attest/` or `latest.ts` stay unmatched.
- `load_ignore_patterns` appends `TEST_PATTERNS` to the default exclusion layer unless `include_tests` is true. That flag is `CaliperSettings.include_tests` in `src/caliper/core/config.py` (default `False`), set by `caliper review --include-tests` or `CALIPER_INCLUDE_TESTS=1`.
- The exclusion is applied at the file-enumeration seam (`FileSourcePort`, both the git and walk adapters), so every plugin and detector sees the same file set and no scanner can re-include test code on its own.
- Finer control stays with `.caliperignore`: a repository that wants its tests scanned except for one rule uses the per-path rule scoping (`<glob> !<rule-prefix>`) rather than a fork of the pattern list.

## Consequences

- Default reports on real repositories are shorter and every remaining finding is in code that ships.
- Repositories whose tests are the product (a test-harness library, a compliance suite) must set `--include-tests`; `caliper init` documents the knob.
- A test-only vulnerability (a fixture lockfile with a known CVE) is invisible by default. That is the intended trade: `tests/e2e/fixtures/` in caliper's own tree is exactly such a case and is additionally listed in `config/scan-exclusions.toml`.
- Adding a new test convention means editing `TEST_PATTERNS` once; the pattern list is guarded by unit tests that pin both the matches and the non-matches.
