---
title: "Silent Safety Rule Bypasses"
component: src/caliper/data/scanners/osv.py, src/caliper/cli/main.py
tags: correctness, reliability, opa, policy-bypass, cvss, severity-mapping, silent-failure
category: runtime-errors
date: 2026-04-23
severity: high
status: diagnosed
root_cause: "Two independent code paths silently disable safety rules: (1) CVSS fallback is a no-op pass statement, rating critical CVEs as info, (2) OPA input dict missing required fields, causing package_age and transitive_count policy rules to silently never fire."
---

# Silent Safety Rule Bypasses

## Problem

**Symptoms:** The OPA policy bundle has 6 well-tested rules covering critical vulns, forbidden licenses, package age, malicious packages, and transitive dependency counts. In production, only 3 of the 6 rules can ever fire. The other 3 are permanently disabled by bugs in the data pipeline feeding OPA — but the system reports no errors, warnings, or degradation.

**Environment:** The policy engine and the data-feeding code were implemented by different agents. The OPA policy tests pass perfectly because they test the Rego rules with correctly-shaped input. The Python code that constructs the OPA input was never tested against the Rego schema.

### Bypass 1: CVSS fallback is a no-op (F-010, severity 8)

`osv.py:146` — The severity mapping function has a CVSS fallback loop that contains only `pass`:

```python
# Before — critical CVEs silently rated as info
def _map_severity(self, vuln: dict) -> FindingSeverity:
    db_severity = vuln.get("database_specific", {}).get("severity")
    if db_severity:
        return self._SEVERITY_MAP.get(db_severity.upper(), FindingSeverity.info)

    # CVSS fallback — supposed to parse CVSS vectors
    for entry in vuln.get("severity", []):
        pass  # BUG: never assigns severity

    return FindingSeverity.info  # Everything without database_specific is "info"
```

Many real-world CVEs (especially NVD-sourced) carry CVSS vectors but no `database_specific.severity`. These are all rated `info`, and the OPA deny rule (`severity in {"critical", "high"}`) never fires for them.

```python
# After — parse CVSS base score
for entry in vuln.get("severity", []):
    if entry.get("type") == "CVSS_V3":
        score = entry.get("score", 0)
        if isinstance(score, str):
            # Extract numeric score from CVSS vector if needed
            parts = score.split("/")
            try:
                score = float(parts[-1]) if "." in parts[-1] else 0
            except ValueError:
                continue
        if score >= 9.0:
            return FindingSeverity.critical
        if score >= 7.0:
            return FindingSeverity.high
        if score >= 4.0:
            return FindingSeverity.medium
        return FindingSeverity.low
```

### Bypass 2: OPA input missing required fields (F-012, severity 7)

`main.py:167` — The `package_metadata` dict passed to OPA contains only 4 fields, but the Rego policy expects 6:

```python
# Before — 2 fields missing, 2 policy rules permanently disabled
package_metadata = {
    "name": req.package_name,
    "version": req.target_version,
    "ecosystem": req.ecosystem,
    "scope": req.scope,
    # MISSING: first_published_date — package_age rule never fires
    # MISSING: transitive_dep_count — transitive_count rule never fires
}

# After — populate from PyPI metadata and SBOM
pypi_client = PyPIClient(timeout=config.pypi_timeout)
pypi_meta = pypi_client.fetch_metadata(req.package_name, req.target_version)

sbom_component_count = next(
    (sr for sr in scan_results if sr.tool_name == "syft"),
    None,
)
transitive_count = 0
if sbom_component_count and sbom_component_count.message:
    try:
        transitive_count = int(sbom_component_count.message.split()[0])
    except (ValueError, IndexError):
        pass

package_metadata = {
    "name": req.package_name,
    "version": req.target_version,
    "ecosystem": req.ecosystem,
    "scope": req.scope,
    "first_published_date": pypi_meta.get("first_published_date", ""),
    "transitive_dep_count": transitive_count,
}
```

## Root Cause Pattern

Both bypasses share the same root cause: **the contract between producer and consumer was never validated at the boundary.**

- The OSV scanner produces severity data. The normalizer and OPA consume it. Nobody tested that the severity values produced by real-world OSV output actually trigger the OPA deny rules.
- The CLI builds OPA input. The Rego policy consumes it. Nobody tested that the Python dict has the fields the Rego rules access. In Rego, missing fields evaluate to `undefined`, which silently skips the rule — no error, no warning, no log.

## Prevention

- **Test case — CVSS mapping:** Add a test with a real OSV JSON fixture that has CVSS vectors but no `database_specific.severity`. Assert the mapped severity is NOT `info`. Use hypothesis to generate CVSS scores across the full 0-10 range and verify severity bucketing is monotonic.

- **Test case — OPA input schema validation:** Add a test that loads `policies/INPUT_SCHEMA.md`, extracts the required field names, builds `package_metadata` via the same code path as `main.py`, and asserts all required fields are present. This is a contract test — it breaks when either side drifts.

- **Test case — end-to-end policy rule coverage:** For each OPA rule, add an integration test that constructs a scenario where that specific rule should fire, runs it through the full Python pipeline (not just `opa test`), and asserts the decision is `reject` or `warn`. If a rule can never fire from the Python side, the test catches it.

- **Best practice — Rego undefined is silent:** In Rego v1, accessing a field that doesn't exist produces `undefined`, not an error. This is by design for composability, but it makes missing-field bugs invisible. Always validate OPA input completeness before evaluation. Log a warning if any expected field is absent.

- **Best practice — no `pass` in fallback branches:** A `pass` in a fallback branch is a silent no-op. If the branch exists, it should either do something or be deleted. A `pass` that's intended as a placeholder must have a `# TODO` with a tracked issue, per the issues.jsonl rule.

## Related

- `.wfc/reviews/REVIEW-main-001.md` — findings F-010, F-012
- `policies/INPUT_SCHEMA.md` — the OPA input schema that the Python code should match
- `policies/policy_test.rego` — OPA tests that pass with correct input but never verify Python produces correct input
