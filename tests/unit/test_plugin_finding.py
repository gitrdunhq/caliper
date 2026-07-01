# tested-by: tests/unit/test_plugin_finding.py
"""Tests for the PluginFinding typed contract primitive."""

from __future__ import annotations


class TestPluginFindingContract:
    def test_finding_has_required_fields(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(
            id="CVE-2025-1234",
            severity="critical",
            message="Remote code execution",
        )
        assert f.id == "CVE-2025-1234"
        assert f.severity == "critical"
        assert f.message == "Remote code execution"

    def test_finding_has_optional_location_fields(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(
            id="CVE-1",
            severity="high",
            message="test",
            file="src/app.py",
            line=42,
        )
        assert f.file == "src/app.py"
        assert f.line == 42

    def test_finding_defaults(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(id="X", severity="info", message="x")
        assert f.file == ""
        assert f.line == 0
        assert f.url == ""
        assert f.category == ""
        assert f.package == ""
        assert f.version == ""
        assert f.fixed_version == ""
        assert f.rule_id == ""
        assert f.fix_suggestion == ""
        assert f.metadata == {}

    def test_finding_has_fix_suggestion_field(self) -> None:
        """fix_suggestion carries a rule's remediation text (#276)."""
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(
            id="X",
            severity="high",
            message="SQL injection",
            fix_suggestion="Use parameterized queries instead of string interpolation",
        )
        assert f.fix_suggestion == "Use parameterized queries instead of string interpolation"

    def test_metadata_preserves_unknown_keys(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(
            id="X",
            severity="info",
            message="x",
            metadata={"entropy": 4.5, "fingerprint": "abc123"},
        )
        assert f.metadata["entropy"] == 4.5
        assert f.metadata["fingerprint"] == "abc123"

    def test_finding_to_dict(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(
            id="CVE-1",
            severity="high",
            message="bad",
            file="x.py",
            line=10,
        )
        d = f.to_dict()
        assert d["id"] == "CVE-1"
        assert d["severity"] == "high"
        assert d["file"] == "x.py"
        assert isinstance(d, dict)

    def test_finding_to_dict_includes_fix_suggestion(self) -> None:
        """to_dict() surfaces fix_suggestion instead of silently dropping it (#276)."""
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(
            id="CVE-1",
            severity="high",
            message="bad",
            fix_suggestion="patch it",
        )
        d = f.to_dict()
        assert d["fix_suggestion"] == "patch it"


class TestPluginFindingIsFrozenContract:
    """PluginFinding is a strict, frozen Contract — no dict-style access (#412)."""

    def test_is_frozen(self) -> None:
        import pytest

        from caliper.core.plugin import PluginFinding

        f = PluginFinding(id="CVE-1", severity="high", message="bad")
        with pytest.raises(Exception):
            f.severity = "low"

    def test_rejects_extra_fields(self) -> None:
        import pytest

        from caliper.core.plugin import PluginFinding

        with pytest.raises(Exception):
            PluginFinding(id="CVE-1", severity="high", message="bad", bogus="x")

    def test_no_dict_shims_remain(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(id="CVE-1", severity="high", message="bad")
        assert not hasattr(f, "get")

    def test_fields_read_by_attribute(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(id="CVE-1", severity="high", message="bad", package="requests")
        assert f.severity == "high"
        assert f.package == "requests"

    def test_metadata_read_via_metadata_dict(self) -> None:
        from caliper.core.plugin import PluginFinding

        f = PluginFinding(id="CVE-1", severity="high", message="bad", metadata={"entropy": 4.5})
        assert f.metadata["entropy"] == 4.5


class TestFindingGet:
    """finding_get bridges PluginFinding and raw-dict findings transitionally."""

    def test_known_field_from_model(self) -> None:
        from caliper.core.plugin import PluginFinding, finding_get

        f = PluginFinding(id="CVE-1", severity="high", message="bad", package="requests")
        assert finding_get(f, "severity") == "high"
        assert finding_get(f, "package") == "requests"

    def test_metadata_key_from_model(self) -> None:
        from caliper.core.plugin import PluginFinding, finding_get

        f = PluginFinding(id="CVE-1", severity="high", message="bad", metadata={"entropy": 4.5})
        assert finding_get(f, "entropy") == 4.5

    def test_missing_returns_default(self) -> None:
        from caliper.core.plugin import PluginFinding, finding_get

        f = PluginFinding(id="CVE-1", severity="high", message="bad")
        assert finding_get(f, "missing") is None
        assert finding_get(f, "missing", 99) == 99

    def test_works_on_raw_dict(self) -> None:
        from caliper.core.plugin import finding_get

        d = {"severity": "low", "check": "x"}
        assert finding_get(d, "severity") == "low"
        assert finding_get(d, "check") == "x"
        assert finding_get(d, "missing", "def") == "def"


class TestNormalizeFindings:
    def test_normalize_dict_to_plugin_finding(self) -> None:
        from caliper.core.plugin import PluginFinding, normalize_finding

        raw = {
            "id": "CVE-2025-1234",
            "severity": "critical",
            "message": "RCE vulnerability",
            "file": "app.py",
            "line": 10,
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-1234",
            "package": "requests",
            "version": "2.25.0",
            "fixed_version": "2.31.0",
            "custom_field": "preserved",
        }
        finding = normalize_finding(raw)
        assert isinstance(finding, PluginFinding)
        assert finding.id == "CVE-2025-1234"
        assert finding.severity == "critical"
        assert finding.package == "requests"
        assert finding.fixed_version == "2.31.0"
        assert finding.metadata["custom_field"] == "preserved"

    def test_normalize_missing_fields_get_defaults(self) -> None:
        from caliper.core.plugin import PluginFinding, normalize_finding

        raw = {"severity": "high", "message": "something bad"}
        finding = normalize_finding(raw)
        assert isinstance(finding, PluginFinding)
        assert finding.id == ""
        assert finding.file == ""
        assert finding.line == 0

    def test_normalize_treats_fix_suggestion_as_known_key(self) -> None:
        """fix_suggestion round-trips as a typed field, not into metadata (#276)."""
        from caliper.core.plugin import normalize_finding

        raw = {
            "id": "rule.sql-injection",
            "severity": "critical",
            "message": "SQL injection",
            "fix_suggestion": "Use parameterized queries instead of string interpolation",
        }
        finding = normalize_finding(raw)
        assert finding.fix_suggestion == "Use parameterized queries instead of string interpolation"
        assert "fix_suggestion" not in finding.metadata

    def test_normalize_preserves_all_unknown_keys_in_metadata(self) -> None:
        from caliper.core.plugin import normalize_finding

        raw = {
            "id": "X",
            "severity": "info",
            "message": "x",
            "entropy": 4.5,
            "fingerprint": "abc",
            "logical_resource_ids": ["MyBucket"],
        }
        finding = normalize_finding(raw)
        assert finding.metadata["entropy"] == 4.5
        assert finding.metadata["fingerprint"] == "abc"
        assert finding.metadata["logical_resource_ids"] == ["MyBucket"]
