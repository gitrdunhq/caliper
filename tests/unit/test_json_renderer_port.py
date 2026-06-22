# tested-by: tests/unit/test_json_renderer_port.py
"""Tests for JsonRenderer — ReportRendererPort implementation."""

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


class TestJsonRendererPort:
    def test_class_exists(self):
        from caliper.core.json_report import JsonRenderer

        assert JsonRenderer is not None

    def test_implements_report_renderer_port(self):
        from caliper.core.json_report import JsonRenderer

        renderer = JsonRenderer()
        assert isinstance(renderer, ReportRendererPort)

    def test_render_returns_string(self):
        from caliper.core.json_report import JsonRenderer

        renderer = JsonRenderer()
        report = _make_report()
        result = renderer.render(report)
        assert isinstance(result, str)

    def test_render_produces_valid_json(self):
        from caliper.core.json_report import JsonRenderer

        renderer = JsonRenderer()
        report = _make_report()
        result = renderer.render(report)
        doc = json.loads(result)
        assert "verdict" in doc
        assert "schema_version" in doc

    def test_render_with_findings(self):
        from caliper.core.json_report import JsonRenderer

        pr = PluginResult(
            plugin_name="gitleaks",
            category="supply_chain",
            findings=[{"severity": "high", "message": "secret found"}],
            summary={},
        )
        renderer = JsonRenderer()
        report = _make_report(plugin_results=[pr])
        result = renderer.render(report)
        doc = json.loads(result)
        assert doc["total_findings"] == 1
        assert doc["plugins"][0]["name"] == "gitleaks"
