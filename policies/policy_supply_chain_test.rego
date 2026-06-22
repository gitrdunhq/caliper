package policy_supply_chain_test

import rego.v1

import data.policy

# Config with only the supply-chain-diff rule enabled (mirrors the focused,
# standalone evaluation in core.supply_chain_diff.evaluate_gate).
sc_config := {
	"forbidden_licenses": [],
	"max_transitive_deps": 200,
	"min_package_age_days": 90,
	"rules_enabled": {
		"critical_vuln": false,
		"forbidden_license": false,
		"package_age": false,
		"malicious_package": false,
		"transitive_count": false,
		"supply_chain_diff": true,
	},
}

sc_package := {"name": "", "version": ""}

sc_finding(severity, signal) := {
	"severity": severity,
	"category": "supply_chain",
	"description": "version bump signal",
	"package_name": "left-pad",
	"version": "1.3.1",
	"advisory_id": signal,
	"source_tool": "supply-chain-diff",
}

# --- critical install-hook signal denies ---
test_critical_supply_chain_denies if {
	inp := {"findings": [sc_finding("critical", "SC-INSTALL-HOOK")], "pkg": sc_package, "config": sc_config}
	result := policy.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "SC-INSTALL-HOOK")
	contains(msg, "left-pad@1.3.1")
	policy.decision == "reject" with input as inp
}

# --- high risky-import signal denies ---
test_high_supply_chain_denies if {
	inp := {"findings": [sc_finding("high", "SC-RISKY-IMPORT")], "pkg": sc_package, "config": sc_config}
	count(policy.deny) == 1 with input as inp
	policy.decision == "reject" with input as inp
}

# --- medium maintainer-change signal warns, does not deny ---
test_medium_supply_chain_warns if {
	inp := {"findings": [sc_finding("medium", "SC-MAINTAINER-CHANGE")], "pkg": sc_package, "config": sc_config}
	count(policy.deny) == 0 with input as inp
	count(policy.warn) == 1 with input as inp
	policy.decision == "approve_with_constraints" with input as inp
}

# --- info / clean signal neither denies nor warns ---
test_info_supply_chain_clean if {
	inp := {"findings": [sc_finding("info", "SC-CLEAN")], "pkg": sc_package, "config": sc_config}
	count(policy.deny) == 0 with input as inp
	count(policy.warn) == 0 with input as inp
	policy.decision == "approve" with input as inp
}

# --- disabled rule: even a critical supply_chain finding does not deny ---
test_disabled_rule_no_deny if {
	disabled := object.union(sc_config, {"rules_enabled": object.union(sc_config.rules_enabled, {"supply_chain_diff": false})})
	inp := {"findings": [sc_finding("critical", "SC-INSTALL-HOOK")], "pkg": sc_package, "config": disabled}
	count(policy.deny) == 0 with input as inp
}
