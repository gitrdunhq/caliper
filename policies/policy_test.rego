package policy_test

import rego.v1

import data.policy

# --- Helper: base input with no findings and all rules enabled ---

base_config := {
	"forbidden_licenses": ["GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0"],
	"max_transitive_deps": 200,
	"min_package_age_days": 90,
	"rules_enabled": {
		"critical_vuln": true,
		"forbidden_license": true,
		"package_age": true,
		"malicious_package": true,
		"transitive_count": true,
	},
}

base_package := {
	"name": "example-lib",
	"version": "1.0.0",
	"ecosystem": "pypi",
	"scope": "runtime",
	"environment_sensitivity": "internet-facing",
	"first_published_date": "2020-01-01T00:00:00Z",
	"transitive_dep_count": 42,
}

clean_input := {
	"findings": [],
	"pkg": base_package,
	"config": base_config,
}

# --- T-010: Critical vulnerability triggers deny ---

test_critical_vuln_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "critical",
		"category": "vulnerability",
		"description": "Remote code execution",
		"package_name": "requests",
		"version": "2.31.0",
		"advisory_id": "CVE-2024-1234",
		"source_tool": "osv-scanner",
	}]})
	result := policy.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "CVE-2024-1234")
	contains(msg, "requests@2.31.0")
}

# --- T-010: High vulnerability triggers deny ---

test_high_vuln_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "high",
		"category": "vulnerability",
		"description": "SQL injection",
		"package_name": "django",
		"version": "4.2.0",
		"advisory_id": "CVE-2024-5555",
		"source_tool": "trivy",
	}]})
	result := policy.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "CVE-2024-5555")
	contains(msg, "django@4.2.0")
}

# --- T-010: Medium vulnerability triggers warn only, not deny ---

test_medium_vuln_warn_only if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "medium",
		"category": "vulnerability",
		"description": "Information disclosure",
		"package_name": "flask",
		"version": "3.0.0",
		"advisory_id": "CVE-2024-5678",
		"source_tool": "osv-scanner",
	}]})
	deny_result := policy.deny with input as inp
	count(deny_result) == 0
	warn_result := policy.warn with input as inp
	count(warn_result) == 1
	some msg in warn_result
	contains(msg, "CVE-2024-5678")
	contains(msg, "flask@3.0.0")
}

# --- No findings results in allow ---

test_no_findings_approve if {
	deny_result := policy.deny with input as clean_input
	count(deny_result) == 0
	warn_result := policy.warn with input as clean_input
	count(warn_result) == 0
	decision := policy.decision with input as clean_input
	decision == "approve"
}

# --- T-011: Forbidden license triggers deny ---

test_forbidden_license_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "info",
		"category": "license",
		"description": "Package uses GPL-3.0-only license",
		"package_name": "some-gpl-lib",
		"version": "1.0.0",
		"advisory_id": "LIC-001",
		"source_tool": "scancode",
		"license_id": "GPL-3.0-only",
	}]})
	result := policy.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "GPL-3.0-only")
	contains(msg, "some-gpl-lib@1.0.0")
}

# --- T-011: Allowed license does not trigger deny ---

test_allowed_license_no_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "info",
		"category": "license",
		"description": "Package uses MIT license",
		"package_name": "nice-lib",
		"version": "2.0.0",
		"advisory_id": "LIC-002",
		"source_tool": "scancode",
		"license_id": "MIT",
	}]})
	result := policy.deny with input as inp
	count(result) == 0
}

# --- T-011: Package age < 90 days triggers deny ---

test_young_package_deny if {
	# Use a date far in the future so it's always "just published" relative to now
	young_package := object.union(base_package, {
		"first_published_date": "2099-01-01T00:00:00Z",
	})
	inp := object.union(clean_input, {"pkg": young_package})
	result := policy.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "days old")
}

# --- T-011: Package age >= 90 days is allowed ---

test_old_package_no_deny if {
	# 2020-01-01 is well over 90 days old
	result := policy.deny with input as clean_input
	count(result) == 0
}

# --- T-011: MAL- prefixed advisory triggers deny ---

test_malicious_package_deny if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "critical",
		"category": "malware",
		"description": "Known malicious package",
		"package_name": "evil-pkg",
		"version": "0.1.0",
		"advisory_id": "MAL-2024-9999",
		"source_tool": "osv-scanner",
	}]})
	result := policy.deny with input as inp
	some msg in result
	contains(msg, "MAL-2024-9999")
	contains(msg, "evil-pkg@0.1.0")
}

# --- T-011: Transitive deps over threshold triggers warn ---

test_transitive_deps_warn if {
	heavy_package := object.union(base_package, {"transitive_dep_count": 250})
	inp := object.union(clean_input, {"pkg": heavy_package})
	warn_result := policy.warn with input as inp
	count(warn_result) == 1
	some msg in warn_result
	contains(msg, "250")
	contains(msg, "200")
}

# --- Disabled rule does not fire even when condition matches ---

test_disabled_critical_vuln_no_deny if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"critical_vuln": false},
	)})
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "vulnerability",
			"description": "Remote code execution",
			"package_name": "requests",
			"version": "2.31.0",
			"advisory_id": "CVE-2024-1234",
			"source_tool": "osv-scanner",
		}],
		"pkg": base_package,
		"config": disabled_config,
	}
	deny_result := policy.deny with input as inp
	count(deny_result) == 0
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}

test_disabled_forbidden_license_no_deny if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"forbidden_license": false},
	)})
	inp := {
		"findings": [{
			"severity": "info",
			"category": "license",
			"description": "GPL license",
			"package_name": "gpl-lib",
			"version": "1.0.0",
			"advisory_id": "LIC-001",
			"source_tool": "scancode",
			"license_id": "GPL-3.0-only",
		}],
		"pkg": base_package,
		"config": disabled_config,
	}
	result := policy.deny with input as inp
	count(result) == 0
}

test_disabled_malicious_no_deny if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"malicious_package": false},
	)})
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "malware",
			"description": "Malicious",
			"package_name": "evil-pkg",
			"version": "0.1.0",
			"advisory_id": "MAL-2024-9999",
			"source_tool": "osv-scanner",
		}],
		"pkg": base_package,
		"config": disabled_config,
	}
	result := policy.deny with input as inp
	count(result) == 0
}

# --- Multiple deny reasons are collected ---

test_multiple_deny_reasons if {
	inp := {
		"findings": [
			{
				"severity": "critical",
				"category": "vulnerability",
				"description": "RCE",
				"package_name": "requests",
				"version": "2.31.0",
				"advisory_id": "CVE-2024-1111",
				"source_tool": "osv-scanner",
			},
			{
				"severity": "high",
				"category": "vulnerability",
				"description": "SSRF",
				"package_name": "requests",
				"version": "2.31.0",
				"advisory_id": "CVE-2024-2222",
				"source_tool": "trivy",
			},
			{
				"severity": "info",
				"category": "license",
				"description": "AGPL license",
				"package_name": "agpl-lib",
				"version": "3.0.0",
				"advisory_id": "LIC-010",
				"source_tool": "scancode",
				"license_id": "AGPL-3.0-only",
			},
		],
		"pkg": base_package,
		"config": base_config,
	}
	result := policy.deny with input as inp
	count(result) == 3
}

# --- Decision: reject when deny is non-empty ---

test_decision_reject if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "critical",
		"category": "vulnerability",
		"description": "RCE",
		"package_name": "bad-pkg",
		"version": "0.1.0",
		"advisory_id": "CVE-2024-0001",
		"source_tool": "osv-scanner",
	}]})
	decision := policy.decision with input as inp
	decision == "reject"
}

# --- Decision: approve_with_constraints when only warn ---

test_decision_approve_with_constraints if {
	inp := object.union(clean_input, {"findings": [{
		"severity": "medium",
		"category": "vulnerability",
		"description": "Info leak",
		"package_name": "leaky-lib",
		"version": "1.0.0",
		"advisory_id": "CVE-2024-9999",
		"source_tool": "osv-scanner",
	}]})
	decision := policy.decision with input as inp
	decision == "approve_with_constraints"
}

# --- Decision: approve when no deny and no warn ---

test_decision_approve if {
	decision := policy.decision with input as clean_input
	decision == "approve"
}

# --- T-348: Disabled package_age rule does not deny a just-published package ---

test_disabled_package_age_no_deny if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"package_age": false},
	)})
	young_package := object.union(base_package, {
		"first_published_date": "2099-01-01T00:00:00Z",
	})
	inp := {
		"findings": [],
		"pkg": young_package,
		"config": disabled_config,
	}
	result := policy.deny with input as inp
	count(result) == 0
}

# --- T-348: Disabled transitive_count rule does not warn even when count is extreme ---

test_disabled_transitive_count_no_warn if {
	disabled_config := object.union(base_config, {"rules_enabled": object.union(
		base_config.rules_enabled,
		{"transitive_count": false},
	)})
	heavy_package := object.union(base_package, {"transitive_dep_count": 500})
	inp := {
		"findings": [],
		"pkg": heavy_package,
		"config": disabled_config,
	}
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}

# --- T-348: reject takes precedence when both deny and warn fire simultaneously ---

test_reject_takes_precedence_when_deny_and_warn_both_fire if {
	inp := {
		"findings": [
			{
				"severity": "critical",
				"category": "vulnerability",
				"description": "RCE",
				"package_name": "bad-pkg",
				"version": "0.1.0",
				"advisory_id": "CVE-2024-0001",
				"source_tool": "osv-scanner",
			},
			{
				"severity": "medium",
				"category": "vulnerability",
				"description": "Info leak",
				"package_name": "bad-pkg",
				"version": "0.1.0",
				"advisory_id": "CVE-2024-0002",
				"source_tool": "osv-scanner",
			},
		],
		"pkg": object.union(base_package, {"transitive_dep_count": 500}),
		"config": base_config,
	}
	deny_result := policy.deny with input as inp
	count(deny_result) > 0
	warn_result := policy.warn with input as inp
	count(warn_result) > 0
	decision := policy.decision with input as inp
	decision == "reject"
}

# --- #345: Dev-scope exemption ---

dev_exempt_config := object.union(base_config, {"rules_enabled": object.union(
	base_config.rules_enabled,
	{"dev_scope_exemption": true},
)})

dev_package := object.union(base_package, {"scope": "dev"})

# T-345: dev-scope critical vuln + dev_scope_exemption:true -> warn, not deny.

test_dev_scope_critical_vuln_downgraded_to_warn if {
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "vulnerability",
			"description": "Remote code execution",
			"package_name": "requests",
			"version": "2.31.0",
			"advisory_id": "CVE-2024-1234",
			"source_tool": "osv-scanner",
		}],
		"pkg": dev_package,
		"config": dev_exempt_config,
	}
	deny_result := policy.deny with input as inp
	count(deny_result) == 0
	warn_result := policy.warn with input as inp
	count(warn_result) == 1
	some msg in warn_result
	contains(msg, "CVE-2024-1234")
	contains(msg, "dev-scope exemption")
}

# T-345: dev-scope critical vuln + dev_scope_exemption absent (default false)
# -> still deny, unchanged from today (backward-compat).

test_dev_scope_critical_vuln_deny_when_exemption_disabled if {
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "vulnerability",
			"description": "Remote code execution",
			"package_name": "requests",
			"version": "2.31.0",
			"advisory_id": "CVE-2024-1234",
			"source_tool": "osv-scanner",
		}],
		"pkg": dev_package,
		"config": base_config,
	}
	deny_result := policy.deny with input as inp
	count(deny_result) == 1
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}

# T-345: runtime-scope critical vuln + dev_scope_exemption:true -> still deny
# (the exemption only applies to dev-scope packages).

test_runtime_scope_critical_vuln_still_denies_with_exemption_enabled if {
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "vulnerability",
			"description": "Remote code execution",
			"package_name": "requests",
			"version": "2.31.0",
			"advisory_id": "CVE-2024-1234",
			"source_tool": "osv-scanner",
		}],
		"pkg": base_package, # scope: "runtime"
		"config": dev_exempt_config,
	}
	deny_result := policy.deny with input as inp
	count(deny_result) == 1
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}

# T-345: dev-scope MAL- prefixed advisory + dev_scope_exemption:true -> still
# deny, never warn. Known-malicious packages always deny regardless of scope
# or the exemption toggle. category=="vulnerability" + severity=="critical"
# means this finding matches BOTH the critical_vuln deny rule (T-010, whose
# downgrade-to-warn logic must exclude MAL- advisories) and the dedicated
# malicious_package deny rule (T-011) -- both must fire and neither may
# downgrade to warn.

test_dev_scope_malicious_advisory_never_downgraded if {
	inp := {
		"findings": [{
			"severity": "critical",
			"category": "vulnerability",
			"description": "Known malicious package",
			"package_name": "evil-pkg",
			"version": "0.1.0",
			"advisory_id": "MAL-2024-9999",
			"source_tool": "osv-scanner",
		}],
		"pkg": dev_package,
		"config": dev_exempt_config,
	}
	deny_result := policy.deny with input as inp
	count(deny_result) == 2
	some msg in deny_result
	contains(msg, "MAL-2024-9999")
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}

# T-345: dev-scope forbidden license + dev_scope_exemption:true -> warn, not
# deny (mirrors the vuln case for the license rule).

test_dev_scope_forbidden_license_downgraded_to_warn if {
	inp := {
		"findings": [{
			"severity": "info",
			"category": "license",
			"description": "Package uses GPL-3.0-only license",
			"package_name": "some-gpl-lib",
			"version": "1.0.0",
			"advisory_id": "LIC-001",
			"source_tool": "scancode",
			"license_id": "GPL-3.0-only",
		}],
		"pkg": dev_package,
		"config": dev_exempt_config,
	}
	deny_result := policy.deny with input as inp
	count(deny_result) == 0
	warn_result := policy.warn with input as inp
	count(warn_result) == 1
	some msg in warn_result
	contains(msg, "GPL-3.0-only")
	contains(msg, "dev-scope exemption")
}

# --- T-346: Unmaintained package rule ---

unmaintained_config := object.union(base_config, {"rules_enabled": object.union(
	base_config.rules_enabled,
	{"unmaintained_package": true},
)})

test_stale_package_unmaintained_warn if {
	stale_package := object.union(base_package, {"last_release_date": "2020-01-01T00:00:00Z"})
	inp := {
		"findings": [],
		"pkg": stale_package,
		"config": unmaintained_config,
	}
	warn_result := policy.warn with input as inp
	count(warn_result) == 1
	some msg in warn_result
	contains(msg, "no release")
}

test_stale_package_unmaintained_disabled_no_warn if {
	stale_package := object.union(base_package, {"last_release_date": "2020-01-01T00:00:00Z"})
	inp := {
		"findings": [],
		"pkg": stale_package,
		"config": base_config,
	}
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}

test_fresh_package_unmaintained_no_warn if {
	fresh_package := object.union(base_package, {"last_release_date": "2099-01-01T00:00:00Z"})
	inp := {
		"findings": [],
		"pkg": fresh_package,
		"config": unmaintained_config,
	}
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}

test_missing_last_release_date_unmaintained_no_warn if {
	inp := {
		"findings": [],
		"pkg": base_package,
		"config": unmaintained_config,
	}
	warn_result := policy.warn with input as inp
	count(warn_result) == 0
}
