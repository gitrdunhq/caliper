package policy

import rego.v1

# --- deny rules (set of denial messages) ---

# T-010: Critical or high severity vulnerability
deny contains msg if {
	input.config.rules_enabled.critical_vuln
	some finding in input.findings
	finding.category == "vulnerability"
	finding.severity in {"critical", "high"}
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

# --- warn rules (set of warning messages) ---

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
