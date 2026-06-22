"""Tests for two-axis scoring — security blocks, quality advises.
# tested-by: tests/unit/test_two_axis_scoring.py
"""

from __future__ import annotations

from caliper.core.plugin import PluginResult
from caliper.core.renderer import _build_sections

_SECURITY_CATEGORIES = {"dependency", "supply_chain", "infra"}
_QUALITY_CATEGORIES = {"quality", "code"}


def _result(
    name: str,
    category: str,
    findings: list[dict] | None = None,
) -> PluginResult:
    return PluginResult(
        plugin_name=name,
        findings=findings or [],
        category=category,
    )


class TestTwoAxisVerdict:
    def test_security_critical_blocks(self) -> None:
        results = [
            _result(
                "trivy",
                "dependency",
                [{"id": "CVE-1", "severity": "critical"}],
            ),
        ]
        verdict, _, _ = _build_sections(results, None)
        assert verdict == "blocked"

    def test_quality_critical_does_not_block(self) -> None:
        results = [
            _result(
                "complexity",
                "quality",
                [{"severity": "critical", "check": "high_fan_out"}],
            ),
        ]
        verdict, _, _ = _build_sections(results, None)
        assert verdict != "blocked"

    def test_quality_findings_produce_warnings(self) -> None:
        results = [
            _result(
                "blast-radius",
                "quality",
                [{"severity": "high", "check": "layer_violation"}],
            ),
        ]
        verdict, _, _ = _build_sections(results, None)
        assert verdict == "warnings"

    def test_mixed_security_and_quality(self) -> None:
        results = [
            _result(
                "trivy",
                "dependency",
                [{"id": "CVE-1", "severity": "critical"}],
            ),
            _result(
                "complexity",
                "quality",
                [{"severity": "critical", "check": "god_function"}],
            ),
        ]
        verdict, _, _ = _build_sections(results, None)
        assert verdict == "blocked"

    def test_no_findings_is_clear(self) -> None:
        results = [
            _result("trivy", "dependency"),
            _result("complexity", "quality"),
        ]
        verdict, _, _ = _build_sections(results, None)
        assert verdict == "clear"
