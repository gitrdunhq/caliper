# Dogfood Findings Log

Tracked findings from running caliper against itself during the `next` branch architecture refactoring. Each finding produces a deterministic regression test.

## Run 1: Post-P0/P1/P2.1/P4.1 (2026-04-28)

Verdict: PASS WITH WARNINGS | Security: 100/100 | Quality: 100/100

| # | Finding | Severity | Detail | Regression Test | Status |
|---|---------|----------|--------|-----------------|--------|
| D1 | OPA parse error on semgrep YAML | bug | OPA eval `-d ./policies` includes non-Rego files | `test_opa_ignores_non_rego_files` | **FIXED** (config.py → policy.rego) |
| D2 | Semgrep 2279 findings on self-scan | noise | Runs against entire repo | `test_semgrep_respects_file_scoping` | OPEN |
| D3 | Actionability: all code findings "blocked" | bug | No fixed_version → classified as blocked | `test_actionability_handles_code_findings` | OPEN |
| D4 | MI score 38/100 with 163 grade-C | info | Expected for subprocess-heavy plugins | KNOWN |
| D5 | cspell NOT_INSTALLED | env | Host only | N/A |
| D6 | osv-scanner skipped | env | Host only | N/A |

## Run 2: Post-P2/P4 complete (2026-04-28)

Verdict: PASS WITH WARNINGS | Security: 100/100 | Quality: 100/100 | Findings: 4358 (-693)

| # | Finding | Severity | Detail | Regression Test | Status |
|---|---------|----------|--------|-----------------|--------|
| D1 | OPA parse error | — | — | — | **FIXED** |
| D2 | Semgrep 2353 findings | noise | +74 from new files (policy_port, tool_runner, etc) | OPEN |
| D3 | Actionability: code findings "blocked" | bug | Same as run 1 | OPEN |
| D7 | scancode TIMEOUT after 60s | env | Slow on full repo — fail-open working correctly | KNOWN |
| D8 | gitleaks: 0 findings | good | Allowlist working | OK |
| D9 | trivy: 0 findings | good | No vulns in deps | OK |

### Progress
- D1 fixed between runs
- No new bugs introduced by P2/P4
- Security score stable at 100/100
- Finding count dropped 693 (scancode timeout instead of 874 false findings)
