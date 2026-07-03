---
name: caliper-opa-policy-playbook
description: >-
  How to read, write, and test caliper's OPA/Rego policy rules in
  policies/policy.rego -- the deny/warn rule set that turns scanner findings
  into a reject/approve_with_constraints/approve decision. Load this BEFORE
  editing policies/policy.rego or policies/*_test.rego, BEFORE adding a new
  rules_enabled toggle, BEFORE debugging why a rule "never fires" (check the
  input.pkg vs input.package gotcha first), or when asked "how many OPA
  rules does caliper have", "how do I add a deny rule", "why does this
  specific Rego rule/test fail", "why does opa test fail on the semgrep
  yaml files", "what does dev_scope_exemption do", or "what does the
  unmaintained-package rule warn on". Not for: just invoking the `opa test`
  runner as part of a quality gate/CI check with no rule-authoring question
  attached (see caliper-diagnostics-and-tooling), the scanner plugins that
  produce findings (see
  caliper-plugin-architecture / caliper-plugin-authoring-playbook), the
  Python-side policy port/adapter wiring (see caliper-architecture-contract),
  general config flags outside policy (see caliper-config-and-flags), or
  code-graph/semgrep detector rules (see caliper-plugin-architecture).
---

# Caliper OPA Policy Playbook

Ground truth as of **2026-07-02**, commit `c78154b`, `opa version` 1.16.2
(darwin/arm64, Rego v1). Every count and command below was run against this
repo, not assumed. If anything here conflicts with `CLAUDE.md`'s "OPA
Policy" section or with `policies/policy.rego` itself, **the repo file
wins** — re-run `scripts/verify_policy.sh` (shipped alongside this skill) to
check.

## When NOT to use this skill

| If you're... | Use instead |
|---|---|
| Writing a new scanner plugin that produces findings | `caliper-plugin-authoring-playbook` |
| Debugging plugin registry / dependency graph internals | `caliper-plugin-architecture` |
| Touching `core/opa_adapter.py`, `core/opa_input.py`, or the ports/tiers boundary | `caliper-architecture-contract` |
| Editing `.caliper.yaml` flags unrelated to `policy.rules_enabled` | `caliper-config-and-flags` |
| Diagnosing a scanner timeout or fail-open path (not a policy decision) | `caliper-fail-open-resilience` |
| Splitting a policy change into RED/GREEN commits | `caliper-change-control` |

## What this policy does, in one sentence

`policies/policy.rego` takes `{findings, pkg, config}` as JSON input and
produces `{deny, warn, decision}` — a non-empty `deny` set means
`decision := "reject"`; empty `deny` + non-empty `warn` means
`"approve_with_constraints"`; both empty means `"approve"`. Full input/output
schema lives in `policies/INPUT_SCHEMA.md` — read that file for exact field
types before writing a new rule that reads `input.pkg.*` or
`input.config.*`.

## The `input.pkg` gotcha (read this before writing any rule)

**Use `input.pkg`. Never `input.package`, never `input.packages`.**

Rego v1 (`import rego.v1`, which `policy.rego` line 3 declares) reserves the
`package` keyword for the module's own package declaration — `package
policy` is line 1 of the file. Naming an input field `input.package` doesn't
error, but it collides semantically with the reserved keyword in ways that
have historically caused adapter bugs: `policies/INPUT_SCHEMA.md` explicitly
calls out that the OPA input builder once emitted `"packages"` (plural, a
typo compounding the confusion) instead of `"pkg"`, silently breaking every
rule that reads package metadata (age, transitive count, scope,
last-release-date) while `opa eval` still returned a valid — just
empty-of-those-rules — decision. Fail-open masked it.

The fix that stuck: **one canonical builder**, `core/opa_input.py`
(`build_opa_input`), is now the *only* place that constructs the OPA input
dict, and it hard-codes the `"pkg"` key:

```python
return {
    "findings": [_opa_finding_row(f) for f in findings],
    "pkg": package_metadata,
    "config": _merge_config(config),
}
```

Before that consolidation there were three separate builders that drifted
out of sync (see the module docstring in `core/opa_input.py` for the full
history) — one of them, the one actually wired into the live production
pipeline, emitted only `{id, severity, message}` per finding, so every rule
that reads `finding.category`, `.package_name`, `.license_id`,
`.advisory_id`, or `.source_tool` evaluated to `undefined` and silently
never fired. That's the architecture-boundary half of this story — see
`caliper-architecture-contract` if you're touching the adapter layer itself.
For policy-authoring purposes, the takeaway is: **when a rule you wrote
"never fires," check the input key names first** — `opa eval` does not
error on an unrecognized top-level key, it just leaves every reference to it
undefined, and an unmatched Rego rule body simply produces no result. This
is silent by design in Rego (partial/undefined evaluation, not an
exception) — there is no stack trace to catch this for you.

## Current rule set (verify yourself — see `scripts/verify_policy.sh`)

**16 rule blocks total: 7 `deny` + 9 `warn`.** This matches the top-line
figure in `CLAUDE.md` ("16 OPA policy rules"). Note: `CLAUDE.md`'s dedicated
"## OPA Policy" section still says "11 rules" — that line is **stale**, left
over from before the CISA-KEV / dev-scope / unmaintained-package / copyleft
rules landed. Trust the rule-block count from the file, not that prose line,
until someone updates it.

Verified 2026-07-02:
```
$ grep -c '^deny contains msg if {' policies/policy.rego
7
$ grep -c '^warn contains msg if {' policies/policy.rego
9
```

### Deny rules (7) — any one non-empty `deny` message rejects the build

| Tag | Rule | `rules_enabled` key | Default | Dev-scope exemptable? |
|---|---|---|---|---|
| T-010 | Critical/high severity vulnerability | `critical_vuln` | on | yes |
| T-011 | Forbidden license (`finding.license_id in config.forbidden_licenses`) | `forbidden_license` | on | yes |
| T-011 | Package age below `min_package_age_days` (default **90** in real runs, see note below) | `package_age` | on | no (not scope-gated at all) |
| T-011 | Known malicious package (`MAL-` prefixed `advisory_id`) | `malicious_package` | on | **never** |
| T-012 | Malicious version-bump / supply-chain signal, critical/high severity | `supply_chain_diff` | on | no |
| T-344 | CISA KEV — `advisory_id` in operator-supplied `config.kev_ids` | `cisa_kev` | **off** | **never** |
| T-347 | Copyleft propagation — strong-copyleft license, `link_type` `"static"` or `"unknown"` | `copyleft_propagation` | **off** | n/a (no dev-scope path for this rule) |

**Package-age default discrepancy, verified 2026-07-02:** `policy.rego`
line 40 (`object.get(input.config, "min_package_age_days", 30)`) and
`policies/data.json` (`"min_package_age_days": 30`) both say **30 days** —
but neither is reachable in a real caliper run. Every production and test
code path builds OPA's input via `build_opa_input()`
(`src/caliper/core/opa_input.py`), whose `_DEFAULT_CONFIG` sets
`min_package_age_days: 90` (line 89) and gets merged in *before* Rego ever
sees the input — so `object.get`'s `30` fallback and `data.json`'s `30` only
ever fire via a hand-rolled `opa eval` that bypasses the canonical builder
(nothing in `src/caliper/` even references `data.json`). `policies/
INPUT_SCHEMA.md`'s field table (**90**) is the one that matches real
behavior. **`CLAUDE.md`'s "Package age < 30 days denies" line (OPA Policy
section) is the stale one** — it should say 90. See
`caliper-config-and-flags` for the `PolicyInput(config={})` / `build_opa_input`
call chain that makes 90 the ground truth. Flagging here, not fixing —
this skill's write scope is `.claude/skills/` only.

### Warn rules (9) — non-empty `warn` with empty `deny` approves-with-constraints

| Tag | Rule | `rules_enabled` key | Default |
|---|---|---|---|
| T-345 | Dev-scope exemption: critical/high vuln downgraded from deny | `critical_vuln` + `dev_scope_exemption` | exemption off |
| T-348 | Unreachable-vulnerability exemption (ADR-009 reachability scribe) | `critical_vuln` + `unreachable_vuln_exemption` | exemption off |
| T-345 | Dev-scope exemption: forbidden license downgraded from deny | `forbidden_license` + `dev_scope_exemption` | exemption off |
| T-012 | Lower-severity supply-chain signal (maintainer change, etc.) | `supply_chain_diff` | on |
| T-010 | Medium-severity vulnerability | `critical_vuln` | on |
| T-011 | Transitive dependency count exceeds `max_transitive_deps` (default 200) | `transitive_count` | on |
| T-346 | Unmaintained package — no release in `max_days_since_release` days | `unmaintained_package` | **off** |
| T-347 | Copyleft propagation — strong-copyleft license, `link_type` `"dynamic"` | `copyleft_propagation` | off |
| T-347 | Copyleft propagation — weak-copyleft license, any `link_type` | `copyleft_propagation` | off |

## Two rules that can NEVER be downgraded by dev-scope exemption

`_dev_scope_downgraded(finding)` (the shared helper both T-345 warn rules
call) has an explicit carve-out: a `MAL-`-prefixed `advisory_id` (known
malicious package) is excluded from the helper's match, so the T-011
malicious-package deny rule always fires regardless of
`dev_scope_exemption` or `pkg.scope`. The T-344 CISA-KEV deny rule follows
the identical pattern independently — it doesn't call
`_dev_scope_downgraded` at all, by design: an actively-exploited CVE always
denies. If you're adding a new deny rule that represents an active,
known-bad signal (not a policy-configurable threshold), follow this
precedent — do not route it through the dev-scope helper.

## Two named exemption mechanisms

Both are opt-in (`rules_enabled.<key>`, default `false`) and both only ever
**downgrade a deny to a warn** — neither can silence a finding entirely.

**`dev_scope_exemption`** (added commit `692717f`, PR #345, 2026-07-01):
when `input.pkg.scope == "dev"`, downgrades the critical/high-vuln (T-010)
and forbidden-license (T-011) deny rules to warn. Does not touch
package-age, malicious-package, supply-chain-diff, or CISA-KEV — those deny
unconditionally regardless of scope.

**`unreachable_vuln_exemption`** (ADR-009 reachability scribe, T-348):
downgrades a critical/high vuln deny to warn when the reachability scribe
set `finding.reachable == false` — i.e. the package is declared but never
imported anywhere in the code graph. **Absence of evidence is not evidence
of absence**: `reachable == null` (unresolved import name, no code graph
available, or the scribe not enabled) never downgrades — only an explicit
`false` does. Same `MAL-` carve-out as `dev_scope_exemption`.

## Unmaintained-package rule (T-346) — fail-open contract

Added commit `20ed446`, PR #346, "unmaintained package rule — warn on stale
packages." Warns when `input.pkg.last_release_date` is older than
`config.max_days_since_release` (default 365 days). The field is sourced
from a new PyPI "latest upload" signal (mirrors the existing
`_compute_first_published` logic but takes the latest timestamp instead of
the earliest).

**Fail-open is load-bearing, not incidental**: if `last_release_date` is
absent or `null` (e.g. the PyPI lookup failed upstream), `time.
parse_rfc3339_ns(input.pkg.last_release_date)` errors internally in Rego,
which makes that specific rule instance **undefined** rather than raising —
Rego rules degrade to "did not fire" on internal errors inside a rule body,
they do not abort the whole evaluation. The rule simply never warns for that
package. This is the same fail-open posture `CLAUDE.md` mandates
project-wide ("No scanner failure blocks a build") applied inside Rego
itself — see `caliper-fail-open-resilience` for the Python-side version of
this contract.

## Copyleft propagation (T-347) — the one rule gated on `link_type`

Added commit `472b4c1`, PR #347, "copyleft propagation — link_type-aware
license enforcement." Two operator-supplied SPDX lists,
`config.copyleft_strong` and `config.copyleft_weak` (caliper ships no
default values for either):

- Strong-copyleft license + `link_type` `"static"` or `"unknown"` → **deny**.
  `"unknown"` is deliberately treated the same as `"static"` — the
  conservative default — because **no caliper scanner currently detects
  real linkage type**; `Finding.link_type` defaults to `"unknown"` upstream,
  so until a scanner is added that can tell static from dynamic linking,
  every copyleft hit is treated as if it were static.
- Strong-copyleft license + `link_type` `"dynamic"` → **warn**, not deny.
- Weak-copyleft license, any `link_type` → **always warn**, regardless of
  linkage.

## Writing a new rule — checklist

1. Pick `deny` (blocks the build) or `warn` (surfaces but doesn't block).
   Default to `warn` for any new signal unless it represents an
   already-established, unambiguous risk category (active exploit, known
   malware, license violation) — this matches every deny rule added after
   the original four.
2. Gate it behind a new `rules_enabled.<key>` boolean. Default it `false`
   ("opt-in") unless you're extending an existing on-by-default category
   (e.g. adding a new deny condition under `critical_vuln`).
3. Read `input.pkg`, never `input.package` — see the gotcha section above.
4. If the rule represents an active/known-bad signal (malware, actively
   exploited CVE), do **not** route it through `_dev_scope_downgraded` —
   follow the T-011/T-344 precedent of denying unconditionally.
5. If the rule reads a field that might legitimately be absent (like
   `last_release_date`), let Rego's natural undefined-on-error behavior
   fail the rule open — don't add manual null-checks that could
   accidentally fail it closed.
6. Add the config default to `core/opa_input.py`'s `_merge_config` (the
   single source of truth for default `rules_enabled` values — see that
   module's docstring for why there used to be three drifting copies of
   this).
7. Update `policies/INPUT_SCHEMA.md`'s `rules_enabled` table and
   `docs/CAPABILITIES.md`'s OPA rule count (`caliper-change-control` has the
   commit-discipline rules for pairing a `feat:` code change with its docs
   update in the same PR).
8. Write Rego tests in `policies/policy_test.rego` (or
   `policies/policy_supply_chain_test.rego` for supply-chain-category
   rules) *before* the rule, per this repo's RED/GREEN TDD discipline (see
   `caliper-change-control`) — a Rego test is a function named `test_*`
   that calls the rule and asserts on `deny`/`warn`/`decision`.

## Running the tests

**Always pass both `--ignore` flags.** Verified 2026-07-02, run from repo
root:

```bash
opa test policies/ --ignore "*.yaml" --ignore "*.yml"
```

Observed output (2026-07-02, `opa` 1.16.2):
```
PASS: 51/51
```
(46 tests in `policies/policy_test.rego` + 5 in
`policies/policy_supply_chain_test.rego`.)

**Why the `--ignore` flags are mandatory, not cosmetic:** `policies/`
contains `semgrep/*.yaml` (11 files — caliper's own semgrep rule configs,
unrelated to Rego) and `swiftlint/default.yml`. `opa test` walks the whole
directory tree and tries to parse every file it finds as Rego/JSON/YAML
policy data. Verified by running without the flags:

```bash
$ opa test policies/
10 errors occurred during loading:
policies/semgrep/banned.yaml: merge error
policies/semgrep/contracts.yaml: merge error
policies/semgrep/org-code-smells.yaml: merge error
... (10 total, one per policies/semgrep/*.yaml file)
```

`--ignore "*.yaml"` skips the semgrep configs; `--ignore "*.yml"` skips
`swiftlint/default.yml` (note the different extension — both globs are
needed, one won't cover the other). This matches the invocation documented
in `CLAUDE.md`'s Commands section verbatim.

## Quick self-check script

`scripts/verify_policy.sh` (shipped with this skill) re-derives every
count in this document — rule blocks, test counts, `opa test` pass count,
and a live re-check that the `--ignore` flags are still necessary. Run it
after any edit to `policies/policy.rego` or `policies/*_test.rego`, or any
time you suspect this skill has drifted:

```bash
bash .claude/skills/caliper-opa-policy-playbook/scripts/verify_policy.sh
```

## Provenance & maintenance

Facts in this document that are likely to drift, and the exact command to
re-verify each one:

| Fact | Re-verify with |
|---|---|
| Deny/warn rule block counts (7 + 9 = 16) | `grep -c '^deny contains msg if {' policies/policy.rego` and same for `warn` |
| `opa test` pass count (51/51) | `opa test policies/ --ignore "*.yaml" --ignore "*.yml"` |
| Test file test-function counts (46 + 5) | `grep -c '^test_' policies/policy_test.rego policies/policy_supply_chain_test.rego` |
| Package-age default (90 in real runs; Rego/data.json's 30 is unreachable dead code) | `grep min_package_age_days policies/policy.rego policies/data.json src/caliper/core/opa_input.py` |
| `opa` binary version (1.16.2, Rego v1) | `opa version` |
| Commit hashes cited (`472b4c1`, `20ed446`, `563058c`, `692717f`) | `git log --oneline --all -- policies/policy.rego \| grep -i 'copyleft\|unmaintained\|kev\|dev-scope'` |
| Whether `CLAUDE.md`'s "11 rules" line has been fixed yet | `grep -n "rules in .policies/policy.rego" CLAUDE.md` — if it now says 16, this skill's "stale line" callout can be deleted |
| `--ignore` flags still both required | `bash .claude/skills/caliper-opa-policy-playbook/scripts/verify_policy.sh` (last section re-checks this live) |

Or just run the whole bundle: `bash
.claude/skills/caliper-opa-policy-playbook/scripts/verify_policy.sh`.
