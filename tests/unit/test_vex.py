"""Tests for the OpenVEX output format.
# tested-by: tests/unit/test_vex.py
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from caliper.core.plugin import PluginFinding, PluginResult
from caliper.core.port_registries import RENDERERS
from caliper.core.vex import VexRenderer, to_vex

_VALID_STATUSES = {"affected", "not_affected", "fixed", "under_investigation"}


def _vuln_finding(**overrides) -> dict:
    base = {
        "id": "CVE-2024-0001",
        "severity": "ERROR",
        "message": "some vuln",
        "category": "vulnerability",
        "package": "requests",
        "version": "2.1.0",
    }
    base.update(overrides)
    return base


def _result(*findings: dict, plugin_name: str = "osv") -> PluginResult:
    return PluginResult(plugin_name=plugin_name, findings=list(findings))


class TestEmptyResults:
    def test_empty_statements(self) -> None:
        doc = to_vex([])
        assert doc["statements"] == []

    def test_document_shape(self) -> None:
        doc = to_vex([])
        assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert doc["@id"].startswith("urn:caliper:vex:")
        assert doc["author"] == "caliper"
        assert "timestamp" in doc
        assert doc["version"] == 1

    def test_json_serialisable(self) -> None:
        doc = to_vex([])
        reloaded = json.loads(json.dumps(doc))
        assert reloaded["statements"] == []


class TestFiltering:
    def test_non_vulnerability_category_skipped(self) -> None:
        results = [_result(_vuln_finding(category="license"))]
        assert to_vex(results)["statements"] == []

    def test_missing_id_skipped(self) -> None:
        results = [_result(_vuln_finding(id="", rule_id=""))]
        assert to_vex(results)["statements"] == []

    def test_rule_id_fallback_used_when_id_missing(self) -> None:
        results = [_result(_vuln_finding(id="", rule_id="GHSA-xxxx"))]
        statements = to_vex(results)["statements"]
        assert statements[0]["vulnerability"]["name"] == "GHSA-xxxx"


class TestStatusMapping:
    def test_error_severity_maps_to_affected(self) -> None:
        results = [_result(_vuln_finding(severity="ERROR"))]
        statement = to_vex(results)["statements"][0]
        assert statement["status"] == "affected"
        assert "action_statement" in statement

    def test_affected_action_statement_uses_fixed_version(self) -> None:
        results = [_result(_vuln_finding(severity="ERROR", fixed_version="2.5.0"))]
        statement = to_vex(results)["statements"][0]
        assert "2.5.0" in statement["action_statement"]

    def test_warning_severity_maps_to_under_investigation(self) -> None:
        results = [_result(_vuln_finding(severity="WARNING"))]
        statement = to_vex(results)["statements"][0]
        assert statement["status"] == "under_investigation"

    def test_unreachable_maps_to_not_affected_regardless_of_severity(self) -> None:
        finding = _vuln_finding(
            severity="ERROR",
            metadata={"scribe": {"reachability": {"reachable": False, "evidence": []}}},
        )
        results = [_result(finding)]
        statement = to_vex(results)["statements"][0]
        assert statement["status"] == "not_affected"
        assert statement["justification"] == "vulnerable_code_not_in_execute_path"

    def test_reachable_true_does_not_override_affected(self) -> None:
        finding = _vuln_finding(
            severity="ERROR",
            metadata={"scribe": {"reachability": {"reachable": True, "evidence": []}}},
        )
        results = [_result(finding)]
        statement = to_vex(results)["statements"][0]
        assert statement["status"] == "affected"

    def test_reachable_none_is_never_treated_as_not_affected(self) -> None:
        """SAFETY: unknown reachability must never downgrade to not_affected."""
        finding = _vuln_finding(
            severity="ERROR",
            metadata={"scribe": {"reachability": {"reachable": None, "evidence": []}}},
        )
        results = [_result(finding)]
        statement = to_vex(results)["statements"][0]
        assert statement["status"] == "affected"

    def test_all_statuses_are_valid_enum_members(self) -> None:
        results = [
            _result(_vuln_finding(id="CVE-1", severity="ERROR")),
            _result(_vuln_finding(id="CVE-2", severity="NOTE")),
            _result(
                _vuln_finding(
                    id="CVE-3",
                    severity="ERROR",
                    metadata={"scribe": {"reachability": {"reachable": False, "evidence": []}}},
                )
            ),
        ]
        doc = to_vex(results)
        assert {s["status"] for s in doc["statements"]} <= _VALID_STATUSES


class TestDedup:
    def test_same_vuln_and_product_worst_status_wins(self) -> None:
        results = [
            _result(
                _vuln_finding(severity="WARNING"),  # under_investigation
                _vuln_finding(severity="ERROR"),  # affected
            )
        ]
        statements = to_vex(results)["statements"]
        assert len(statements) == 1
        assert statements[0]["status"] == "affected"

    def test_different_products_produce_separate_statements(self) -> None:
        results = [
            _result(
                _vuln_finding(package="requests", version="2.1.0"),
                _vuln_finding(package="flask", version="1.0.0"),
            )
        ]
        assert len(to_vex(results)["statements"]) == 2


class TestPluginFindingModel:
    def test_typed_plugin_finding_is_accepted(self) -> None:
        finding = PluginFinding(
            id="CVE-2024-9999",
            severity="ERROR",
            message="vuln",
            category="vulnerability",
            package="lodash",
            version="4.0.0",
        )
        result = PluginResult(plugin_name="npm-audit", findings=[finding])
        statements = to_vex([result])["statements"]
        assert statements[0]["vulnerability"]["name"] == "CVE-2024-9999"


class TestDeterminism:
    def test_same_inputs_produce_same_statements(self) -> None:
        results = [_result(_vuln_finding())]
        first = to_vex(results)["statements"]
        second = to_vex(results)["statements"]
        assert first == second

    def test_doc_id_is_stable_for_identical_statements(self) -> None:
        results = [_result(_vuln_finding())]
        first = to_vex(results)["@id"]
        second = to_vex(results)["@id"]
        assert first == second


class TestGoldenDocument:
    def test_mixed_finding_set_produces_expected_statements(self) -> None:
        results = [
            _result(
                _vuln_finding(id="CVE-2024-AAAA", package="requests", severity="ERROR"),
                _vuln_finding(
                    id="CVE-2024-BBBB",
                    package="flask",
                    severity="ERROR",
                    metadata={"scribe": {"reachability": {"reachable": False, "evidence": []}}},
                ),
                _vuln_finding(id="CVE-2024-CCCC", package="jinja2", severity="NOTE"),
            )
        ]
        doc = to_vex(results)
        statements = {s["vulnerability"]["name"]: s["status"] for s in doc["statements"]}
        assert statements == {
            "CVE-2024-AAAA": "affected",
            "CVE-2024-BBBB": "not_affected",
            "CVE-2024-CCCC": "under_investigation",
        }


class TestRendererRegistration:
    def test_vex_renderer_registered(self) -> None:
        assert "vex" in RENDERERS

    def test_renderer_produces_valid_json_matching_to_vex(self) -> None:
        results = [_result(_vuln_finding())]
        report = SimpleNamespace(plugin_results=results)
        text = VexRenderer().render(report)
        parsed = json.loads(text)
        assert parsed["statements"] == to_vex(results)["statements"]

    def test_registry_builds_a_working_renderer(self) -> None:
        renderer = RENDERERS.create("vex")
        report = SimpleNamespace(plugin_results=[])
        assert json.loads(renderer.render(report))["statements"] == []
