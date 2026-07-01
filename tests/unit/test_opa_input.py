"""Tests for caliper.core.opa_input — the canonical OPA input builder.

This module is the single source of truth for input.findings/pkg/config
consumed by both core/policy.py (supply-chain-diff / legacy plugins/_opa.py
path, fed core `Finding` models) and core/opa_adapter.py's OpaRegoAdapter
(the live production path, fed PolicyInput's `PluginFinding` objects).
"""

from __future__ import annotations

from caliper.core.models import Finding, FindingCategory, FindingSeverity
from caliper.core.opa_input import _DEFAULT_RULES_ENABLED, build_opa_input
from caliper.core.plugin import PluginFinding


def _vuln_finding(**overrides) -> Finding:
    defaults = dict(
        severity=FindingSeverity.high,
        category=FindingCategory.vulnerability,
        description="Test vuln CVE-2024-1234",
        source_tool="osv-scanner",
        package_name="lodash",
        version="4.17.20",
        advisory_id="CVE-2024-1234",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestBuildOpaInputFromCoreFindingModel:
    """The supply-chain-diff / legacy plugins/_opa.py path — list[Finding]."""

    def test_finding_row_has_full_schema_shape(self) -> None:
        result = build_opa_input([_vuln_finding()], {"name": "lodash", "version": "4.17.20"})
        row = result["findings"][0]
        assert row["severity"] == "high"
        assert row["category"] == "vulnerability"
        assert row["description"] == "Test vuln CVE-2024-1234"
        assert row["package_name"] == "lodash"
        assert row["version"] == "4.17.20"
        assert row["advisory_id"] == "CVE-2024-1234"
        assert row["source_tool"] == "osv-scanner"

    def test_license_id_only_present_for_license_category(self) -> None:
        license_finding = _vuln_finding(
            category=FindingCategory.license,
            license_id="GPL-3.0",
        )
        vuln_finding = _vuln_finding()
        result = build_opa_input([vuln_finding, license_finding], {})
        assert "license_id" not in result["findings"][0]
        assert result["findings"][1]["license_id"] == "GPL-3.0"


class TestBuildOpaInputFromPluginFinding:
    """The LIVE production path — PolicyInput.findings is list[PluginFinding]."""

    def test_first_class_fields_map_to_schema_names(self) -> None:
        finding = PluginFinding(
            id="CVE-2026-0001",
            severity="high",
            message="critical vulnerability",
            category="vulnerability",
            package="dangerlib",
            version="1.0.0",
            metadata={"advisory_id": "CVE-2026-0001", "source_tool": "osv-scanner"},
        )
        result = build_opa_input([finding], {"name": "dangerlib", "version": "1.0.0"})
        row = result["findings"][0]
        assert row["severity"] == "high"
        assert row["category"] == "vulnerability"
        assert row["description"] == "critical vulnerability"
        assert row["package_name"] == "dangerlib"
        assert row["version"] == "1.0.0"
        assert row["advisory_id"] == "CVE-2026-0001"
        assert row["source_tool"] == "osv-scanner"

    def test_advisory_id_falls_back_to_id_when_metadata_absent(self) -> None:
        """PluginFinding has no first-class advisory_id field; historically
        .id carries it (pipeline._policy_evaluation sets id=advisory_id)."""
        finding = PluginFinding(id="MAL-2024-0007", severity="critical", message="malware")
        result = build_opa_input([finding], {})
        assert result["findings"][0]["advisory_id"] == "MAL-2024-0007"

    def test_license_id_read_from_metadata_only_for_license_category(self) -> None:
        finding = PluginFinding(
            id="LIC-1",
            severity="low",
            message="GPL-3.0 detected",
            category="license",
            metadata={"license_id": "GPL-3.0"},
        )
        result = build_opa_input([finding], {})
        assert result["findings"][0]["license_id"] == "GPL-3.0"

    def test_license_id_absent_for_non_license_category(self) -> None:
        finding = PluginFinding(
            id="CVE-1",
            severity="high",
            message="vuln",
            category="vulnerability",
            metadata={"license_id": "GPL-3.0"},
        )
        result = build_opa_input([finding], {})
        assert "license_id" not in result["findings"][0]


class TestConfigMerge:
    def test_default_rules_enabled_present_when_config_omitted(self) -> None:
        result = build_opa_input([], {})
        assert result["config"]["rules_enabled"] == _DEFAULT_RULES_ENABLED

    def test_partial_rules_enabled_override_preserves_other_defaults(self) -> None:
        """A shallow dict.update() would silently disable every rule not
        named in the override — this must be a deep merge of rules_enabled."""
        result = build_opa_input([], {}, config={"rules_enabled": {"critical_vuln": False}})
        rules = result["config"]["rules_enabled"]
        assert rules["critical_vuln"] is False
        assert rules["forbidden_license"] is True
        assert rules["package_age"] is True
        assert rules["malicious_package"] is True
        assert rules["transitive_count"] is True
        assert rules["supply_chain_diff"] is True

    def test_non_rules_enabled_overrides_merge_over_defaults(self) -> None:
        result = build_opa_input(
            [],
            {},
            config={"forbidden_licenses": ["GPL-3.0"], "max_transitive_deps": 50},
        )
        assert result["config"]["forbidden_licenses"] == ["GPL-3.0"]
        assert result["config"]["max_transitive_deps"] == 50
        assert result["config"]["min_package_age_days"] == 90


class TestTopLevelShape:
    def test_has_findings_pkg_config_keys(self) -> None:
        result = build_opa_input([], {"name": "pkg", "version": "1.0.0"})
        assert set(result.keys()) == {"findings", "pkg", "config"}
        assert result["pkg"] == {"name": "pkg", "version": "1.0.0"}
