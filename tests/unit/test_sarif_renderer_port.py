# tested-by: tests/unit/test_sarif_renderer_port.py
"""Tests for SarifRenderer — ReportRendererPort implementation."""

from __future__ import annotations

import json

from caliper.core.plugin import PluginResult
from caliper.core.ports import ReportRendererPort, ReviewReport


def _make_report(plugin_results=None):
    return ReviewReport(
        verdict="clear",
        security_score=100.0,
        quality_score=100.0,
        plugin_results=plugin_results or [],
        actionability={},
    )


class TestSarifRendererPort:
    def test_class_exists(self):
        from caliper.core.sarif import SarifRenderer

        assert SarifRenderer is not None

    def test_implements_report_renderer_port(self):
        from caliper.core.sarif import SarifRenderer

        renderer = SarifRenderer()
        assert isinstance(renderer, ReportRendererPort)

    def test_render_returns_string(self):
        from caliper.core.sarif import SarifRenderer

        renderer = SarifRenderer()
        report = _make_report()
        result = renderer.render(report)
        assert isinstance(result, str)

    def test_render_produces_valid_sarif_json(self):
        from caliper.core.sarif import SarifRenderer

        renderer = SarifRenderer()
        report = _make_report()
        result = renderer.render(report)
        doc = json.loads(result)
        assert doc["version"] == "2.1.0"
        assert "runs" in doc

    def test_render_with_findings(self):
        from caliper.core.sarif import SarifRenderer

        pr = PluginResult(
            plugin_name="trivy",
            category="dependency",
            findings=[{"severity": "critical", "message": "CVE-2023-0001"}],
            summary={},
        )
        renderer = SarifRenderer()
        report = _make_report(plugin_results=[pr])
        result = renderer.render(report)
        doc = json.loads(result)
        assert len(doc["runs"]) == 1
        assert doc["runs"][0]["results"][0]["level"] == "error"
