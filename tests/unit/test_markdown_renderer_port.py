# tested-by: tests/unit/test_markdown_renderer_port.py
"""Tests for MarkdownRenderer — ReportRendererPort implementation."""

from __future__ import annotations

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


class TestMarkdownRendererPort:
    def test_class_exists(self):
        from caliper.core.renderer import MarkdownRenderer

        assert MarkdownRenderer is not None

    def test_implements_report_renderer_port(self):
        from caliper.core.renderer import MarkdownRenderer

        renderer = MarkdownRenderer()
        assert isinstance(renderer, ReportRendererPort)

    def test_render_returns_string(self):
        from caliper.core.renderer import MarkdownRenderer

        renderer = MarkdownRenderer()
        report = _make_report()
        result = renderer.render(report)
        assert isinstance(result, str)

    def test_render_with_findings(self):
        from caliper.core.renderer import MarkdownRenderer

        pr = PluginResult(
            plugin_name="semgrep",
            category="code",
            findings=[{"severity": "high", "message": "bad thing"}],
            summary={},
        )
        renderer = MarkdownRenderer()
        report = _make_report(plugin_results=[pr])
        result = renderer.render(report)
        assert isinstance(result, str)
        assert len(result) > 0
