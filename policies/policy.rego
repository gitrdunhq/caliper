package policy

import rego.v1

# --- deny rules (set of denial messages) ---

# T-010: Critical or high severity vulnerability
deny contains msg if {
	input.config.rules_enabled.critical_vuln
	some finding in input.findings
	finding.category == "vulnerability"
	finding.severity in {"critical", "high"}
	not _dev_scope_downgraded(finding)
	msg := sprintf("%s vulnerability %s in %s@%s", [
		upper(finding.severity),
		finding.advisory_id,
		finding.package_name,
		finding.version,
	])
}

# T-011: Forbidden license
deny contains msg if {
	input.config.rules_enabled.forbidden_license
	some finding in input.findings
	finding.category == "license"
	finding.license_id in input.config.forbidden_licenses
	not _dev_scope_downgraded(finding)
	msg := sprintf("Forbidden license %s in %s@%s", [
		finding.license_id,
		finding.package_name,
		finding.version,
	])
}

# T-011: Package age check (< min_package_age_days)
deny contains msg if {
	input.config.rules_enabled.package_age
	min_age_days := object.get(input.config, "min_package_age_days", 30)
	published_ns := time.parse_rfc3339_ns(input.pkg.first_published_date)
	now_ns := time.now_ns()
	age_days := (now_ns - published_ns) / ((1000 * 1000 * 1000) * 60 * 60 * 24)
	age_days < min_age_days
	msg := sprintf("Package %s@%s is only %d days old (minimum: %d)", [
		input.pkg.name,
		input.pkg.version,
		age_days,
		min_age_days,
	])
}

# T-011: Known malicious package (MAL- prefix advisory)
deny contains msg if {
	input.config.rules_enabled.malicious_package
	some finding in input.findings
	startswith(finding.advisory_id, "MAL-")
	msg := sprintf("Known malicious package detected: %s in %s@%s", [
		finding.advisory_id,
		finding.package_name,
		finding.version,
	])
}

# T-345: Dev-scope exemption helper — true when a finding's deny should be
# downgraded to warn because the package is dev-only and the operator opted
# in. A MAL- prefixed advisory is never downgraded: known-malicious packages
# always deny, regardless of scope or this exemption (see T-011 above).
_dev_scope_downgraded(finding) if {
	input.config.rules_enabled.dev_scope_exemption
	input.pkg.scope == "dev"
	not startswith(finding.advisory_id, "MAL-")
}

# T-012: Malicious version-bump signal (deterministic source-diff analysis).
# Critical/high supply-chain signals (new install hooks, obfuscation, risky
# imports) gate the build. The signal is deterministic; any LLM narrative is
# advisory metadata only and never reaches this rule.
deny contains msg if {
	input.config.rules_enabled.supply_chain_diff
	some finding in input.findings
	finding.category == "supply_chain"
	finding.severity in {"critical", "high"}
	msg := sprintf("Supply-chain risk %s in %s@%s", [
		finding.advisory_id,
		finding.package_name,
		finding.version,
	])
}

# T-344: CISA KEV — actively exploited CVE. Never downgradable via
# _dev_scope_downgraded — an actively-exploited CVE is exactly as severe as
# the MAL- known-malicious-package case above, which is also never
# downgraded. See _dev_scope_downgraded's comment for why.
deny contains msg if {
	input.config.rules_enabled.cisa_kev
	some finding in input.findings
	finding.category == "vulnerability"
	finding.advisory_id in object.get(input.config, "kev_ids", set())
	msg := sprintf("Actively exploited (CISA KEV) vulnerability %s in %s@%s", [
		finding.advisory_id,
		finding.package_name,
		finding.version,
	])
}

# --- warn rules (set of warning messages) ---

# T-345: Dev-scope exemption — critical/high vulnerability downgraded to warn.
# Only applies when dev_scope_exemption is enabled, the package is dev-scope,
# and the finding is not a known-malicious-package advisory (MAL- prefix
# always denies via _dev_scope_downgraded's exclusion, and via the dedicated
# malicious_package rule below).
warn contains msg if {
	input.config.rules_enabled.critical_vuln
	some finding in input.findings
	finding.category == "vulnerability"
	finding.severity in {"critical", "high"}
	_dev_scope_downgraded(finding)
	msg := sprintf("%s vulnerability %s in %s@%s (dev-scope exemption)", [
		upper(finding.severity),
		finding.advisory_id,
		finding.package_name,
		finding.version,
	])
}

# T-345: Dev-scope exemption — forbidden license downgraded to warn.
warn contains msg if {
	input.config.rules_enabled.forbidden_license
	some finding in input.findings
	finding.category == "license"
	finding.license_id in input.config.forbidden_licenses
	_dev_scope_downgraded(finding)
	msg := sprintf("Forbidden license %s in %s@%s (dev-scope exemption)", [
		finding.license_id,
		finding.package_name,
		finding.version,
	])
}

# T-012: Lower-severity supply-chain signal (maintainer change, etc.) — advisory.
warn contains msg if {
	input.config.rules_enabled.supply_chain_diff
	some finding in input.findings
	finding.category == "supply_chain"
	finding.severity == "medium"
	msg := sprintf("Supply-chain note %s in %s@%s", [
		finding.advisory_id,
		finding.package_name,
		finding.version,
	])
}

# T-010: Medium severity vulnerability
warn contains msg if {
	input.config.rules_enabled.critical_vuln
	some finding in input.findings
	finding.category == "vulnerability"
	finding.severity == "medium"
	msg := sprintf("Medium vulnerability %s in %s@%s", [
		finding.advisory_id,
		finding.package_name,
		finding.version,
	])
}

# T-011: Transitive dependency count exceeds threshold
warn contains msg if {
	input.config.rules_enabled.transitive_count
	max_deps := object.get(input.config, "max_transitive_deps", 200)
	input.pkg.transitive_dep_count > max_deps
	msg := sprintf("Transitive dependency count %d exceeds threshold %d for %s@%s", [
		input.pkg.transitive_dep_count,
		max_deps,
		input.pkg.name,
		input.pkg.version,
	])
}

# --- decision: computed from deny/warn sets ---

default decision := "approve"

decision := "reject" if {
	count(deny) > 0
}

decision := "approve_with_constraints" if {
	count(deny) == 0
	count(warn) > 0
}
