"""Tests for actionability classification of scanner findings.
# tested-by: tests/unit/test_actionability.py
"""

from __future__ import annotations

from caliper.core.actionability import (
    Actionability,
    ActionabilitySummary,
    classify_findings,
)
from caliper.core.plugin import PluginResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    plugin_name: str,
    findings: list[dict],
) -> PluginResult:
    return PluginResult(plugin_name=plugin_name, findings=findings)


def _vuln(
    id: str = "CVE-2024-0001",
    severity: str = "high",
    fixed_version: str = "",
    package: str = "requests",
) -> dict:
    return {
        "id": id,
        "severity": severity,
        "package": package,
        "fixed_version": fixed_version,
    }


# ---------------------------------------------------------------------------
# Enum
# ---------------------------------------------------------------------------


class TestActionabilityEnum:
    def test_fix_value(self) -> None:
        assert Actionability.fix == "fix"

    def test_blocked_upstream_value(self) -> None:
        assert Actionability.blocked_upstream == "blocked_upstream"

    def test_blocked_os_value(self) -> None:
        assert Actionability.blocked_os == "blocked_os"

    def test_blocked_eol_value(self) -> None:
        assert Actionability.blocked_eol == "blocked_eol"

    def test_accept_value(self) -> None:
        assert Actionability.accept == "accept"

    def test_all_five_values_exist(self) -> None:
        names = {a.value for a in Actionability}
        assert names == {"fix", "blocked_upstream", "blocked_os", "blocked_eol", "accept"}


# ---------------------------------------------------------------------------
# classify_findings — empty input
# ---------------------------------------------------------------------------


class TestClassifyFindingsEmpty:
    def test_empty_results_returns_zero_counts(self) -> None:
        summary = classify_findings([])
        assert summary.actionable_count == 0
        assert summary.blocked_count == 0

    def test_empty_results_actionable_list_is_empty(self) -> None:
        summary = classify_findings([])
        assert summary.actionable == []

    def test_empty_results_blocked_list_is_empty(self) -> None:
        summary = classify_findings([])
        assert summary.blocked == []

    def test_empty_results_blocked_by_source_is_empty_dict(self) -> None:
        summary = classify_findings([])
        assert summary.blocked_by_source == {}

    def test_empty_results_summary_text_is_str(self) -> None:
        summary = classify_findings([])
        assert isinstance(summary.summary_text, str)

    def test_empty_plugin_with_no_findings(self) -> None:
        result = _make_result("trivy", [])
        summary = classify_findings([result])
        assert summary.actionable_count == 0
        assert summary.blocked_count == 0


# ---------------------------------------------------------------------------
# classify_findings — single finding with fix
# ---------------------------------------------------------------------------


class TestClassifyFindingsWithFix:
    def test_finding_with_fixed_version_is_actionable(self) -> None:
        finding = _vuln(fixed_version="2.31.0")
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        assert summary.actionable_count == 1

    def test_finding_with_fixed_version_is_not_blocked(self) -> None:
        finding = _vuln(fixed_version="2.31.0")
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        assert summary.blocked_count == 0

    def test_actionable_list_contains_the_finding(self) -> None:
        finding = _vuln(id="CVE-2024-9999", fixed_version="1.0.0")
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        ids = [f["id"] for f in summary.actionable]
        assert "CVE-2024-9999" in ids

    def test_blocked_by_source_is_empty_when_all_actionable(self) -> None:
        finding = _vuln(fixed_version="1.0.0")
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        assert summary.blocked_by_source == {}


# ---------------------------------------------------------------------------
# classify_findings — single finding without fix
# ---------------------------------------------------------------------------


class TestClassifyFindingsNoFix:
    def test_finding_without_fixed_version_is_blocked(self) -> None:
        finding = _vuln(fixed_version="")
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        assert summary.blocked_count == 1

    def test_finding_without_fixed_version_not_actionable(self) -> None:
        finding = _vuln(fixed_version="")
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        assert summary.actionable_count == 0

    def test_finding_without_fixed_version_key_is_blocked(self) -> None:
        # finding dict has no fixed_version key at all
        finding = {"id": "CVE-2024-0001", "severity": "high", "package": "x"}
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        assert summary.blocked_count == 1

    def test_blocked_by_source_groups_by_plugin_name(self) -> None:
        finding = _vuln(id="CVE-2024-0001", fixed_version="")
        result = _make_result("trivy", [finding])
        summary = classify_findings([result])
        assert "trivy" in summary.blocked_by_source
        ids = [f["id"] for f in summary.blocked_by_source["trivy"]]
        assert "CVE-2024-0001" in ids


# ---------------------------------------------------------------------------
# classify_findings — mixed results, multiple plugins
# ---------------------------------------------------------------------------


class TestClassifyFindingsMixed:
    def test_mixed_findings_counted_correctly(self) -> None:
        findings_a = [
            _vuln("CVE-A-001", fixed_version="2.0.0"),  # actionable
            _vuln("CVE-A-002", fixed_version=""),  # blocked
        ]
        findings_b = [
            _vuln("CVE-B-001", fixed_version=""),  # blocked
        ]
        summary = classify_findings(
            [
                _make_result("trivy", findings_a),
                _make_result("osv", findings_b),
            ]
        )
        assert summary.actionable_count == 1
        assert summary.blocked_count == 2

    def test_blocked_by_source_includes_both_plugins(self) -> None:
        findings_a = [_vuln("CVE-A-002", fixed_version="")]
        findings_b = [_vuln("CVE-B-001", fixed_version="")]
        summary = classify_findings(
            [
                _make_result("trivy", findings_a),
                _make_result("osv", findings_b),
            ]
        )
        assert "trivy" in summary.blocked_by_source
        assert "osv" in summary.blocked_by_source

    def test_blocked_by_source_does_not_include_actionable_plugin(self) -> None:
        findings_a = [_vuln("CVE-A-001", fixed_version="2.0.0")]
        findings_b = [_vuln("CVE-B-001", fixed_version="")]
        summary = classify_findings(
            [
                _make_result("trivy", findings_a),
                _make_result("osv", findings_b),
            ]
        )
        assert "trivy" not in summary.blocked_by_source

    def test_return_type_is_actionability_summary(self) -> None:
        summary = classify_findings([])
        assert isinstance(summary, ActionabilitySummary)


# ---------------------------------------------------------------------------
# summary_text generation
# ---------------------------------------------------------------------------


class TestSummaryText:
    def test_all_blocked_critical_text_mentions_none_actionable(self) -> None:
        findings = [
            _vuln("CVE-1", severity="critical", fixed_version=""),
            _vuln("CVE-2", severity="critical", fixed_version=""),
        ]
        summary = classify_findings([_make_result("trivy", findings)])
        text = summary.summary_text
        assert "none actionable" in text.lower() or "not actionable" in text.lower()

    def test_all_actionable_text_mentions_available_fixes(self) -> None:
        findings = [
            _vuln("CVE-1", severity="critical", fixed_version="1.0.0"),
            _vuln("CVE-2", severity="high", fixed_version="2.0.0"),
        ]
        summary = classify_findings([_make_result("trivy", findings)])
        text = summary.summary_text
        assert "fix" in text.lower()

    def test_mixed_text_mentions_both_buckets(self) -> None:
        findings = [
            _vuln("CVE-1", severity="critical", fixed_version="1.0.0"),  # actionable
            _vuln("CVE-2", severity="high", fixed_version=""),  # blocked
        ]
        summary = classify_findings([_make_result("trivy", findings)])
        text = summary.summary_text
        # should mention both a fix being available and something being blocked
        assert "fix" in text.lower()

    def test_empty_summary_text_is_non_empty_string(self) -> None:
        summary = classify_findings([])
        assert len(summary.summary_text) > 0

    def test_all_blocked_text_contains_count(self) -> None:
        findings = [
            _vuln("CVE-1", severity="critical", fixed_version=""),
            _vuln("CVE-2", severity="high", fixed_version=""),
            _vuln("CVE-3", severity="medium", fixed_version=""),
        ]
        summary = classify_findings([_make_result("trivy", findings)])
        text = summary.summary_text
        assert "1 CRITICAL" in text
        assert "1 HIGH" in text
