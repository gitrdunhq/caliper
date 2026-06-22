"""Tests for ComplexityPlugin render output capping.
# tested-by: tests/unit/test_complexity_plugin.py
"""

from __future__ import annotations

from caliper.core.plugin import PluginResult
from caliper.plugins.complexity import ComplexityPlugin


def _make_finding(name: str, ccn: int = 3, nloc: int = 10) -> dict:
    return {
        "function": name,
        "file": "src/mod.py",
        "cyclomatic_complexity": ccn,
        "maintainability_index": 85.0,
        "nloc": nloc,
    }


class TestComplexityRenderCapping:
    """Complexity render output must cap rows to prevent report truncation."""

    def test_render_caps_at_25_rows(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(40)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 400,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        rows = [line for line in output.split("\n") if line.startswith("| `func_")]
        assert len(rows) == 25

    def test_render_shows_remaining_count(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(40)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 400,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        assert "15 more" in output

    def test_render_no_truncation_under_cap(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(10)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 100,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        rows = [line for line in output.split("\n") if line.startswith("| `func_")]
        assert len(rows) == 10
        assert "more" not in output


class TestComplexityRenderTypeCoercion:
    """_render_inline must handle string-typed numeric fields without raising."""

    def test_string_summary_values_do_not_raise(self) -> None:
        """Summary metrics as strings (e.g. from JSON) must coerce without TypeError."""
        result = PluginResult(
            plugin_name="complexity",
            findings=[_make_finding("func_a", ccn=3)],
            summary={
                "avg_cyclomatic_complexity": "10.5",
                "max_cyclomatic_complexity": "15",
                "total_nloc": "200",
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        assert "<details>" in output
        assert "Complexity" in output

    def test_string_ccn_above_10_appears_in_high_section(self) -> None:
        """A finding with cyclomatic_complexity='12' (string) must land in the high section."""
        result = PluginResult(
            plugin_name="complexity",
            findings=[
                {
                    "function": "hot_func",
                    "file": "src/mod.py",
                    "cyclomatic_complexity": "12",
                    "maintainability_index": "65.5",
                    "nloc": "50",
                }
            ],
            summary={
                "avg_cyclomatic_complexity": "12",
                "max_cyclomatic_complexity": "12",
                "total_nloc": "50",
            },
        )
        plugin = ComplexityPlugin()
        # Before fix: TypeError because "12" > 10 is invalid in Python 3
        output = plugin._render_inline(result)
        assert "High complexity" in output, "CCN=12 string should be in high-complexity section"

    def test_invalid_string_ccn_does_not_crash(self) -> None:
        """Completely non-numeric cyclomatic_complexity values must not crash _render_inline."""
        result = PluginResult(
            plugin_name="complexity",
            findings=[
                {
                    "function": "bad_func",
                    "file": "test.py",
                    "cyclomatic_complexity": "not_a_number",
                    "maintainability_index": "also_bad",
                    "nloc": "50",
                }
            ],
            summary={
                "avg_cyclomatic_complexity": "abc",
                "max_cyclomatic_complexity": "def",
                "total_nloc": "xyz",
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        assert output  # must produce some output rather than crashing
