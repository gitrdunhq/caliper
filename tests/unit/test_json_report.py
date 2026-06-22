"""Tests for JSON structured output.
# tested-by: tests/unit/test_json_report.py
"""

from __future__ import annotations

import json

from caliper.core.plugin import PluginResult


def _make_result(
    name: str = "trivy",
    findings: list[dict] | None = None,
    error: str = "",
    skip_reason: str = "",
    skip_remediation: str = "",
    category: str = "dependency",
) -> PluginResult:
    return PluginResult(
        plugin_name=name,
        findings=findings or [],
        summary={"status": "skipped"} if skip_reason else {},
        error=error,
        category=category,
        skip_reason=skip_reason,
        skip_remediation=skip_remediation,
    )


class TestJsonReport:
    def test_output_is_valid_json(self) -> None:
        from caliper.core.json_report import render_json

        results = [_make_result()]
        output = render_json(results)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_has_schema_version(self) -> None:
        from caliper.core.json_report import render_json

        output = json.loads(render_json([_make_result()]))
        assert "schema_version" in output
        assert output["schema_version"] == "1.0"

    def test_has_verdict(self) -> None:
        from caliper.core.json_report import render_json

        output = json.loads(render_json([_make_result()]))
        assert "verdict" in output

    def test_includes_all_plugins(self) -> None:
        from caliper.core.json_report import render_json

        results = [
            _make_result("trivy"),
            _make_result("gitleaks", category="supply_chain"),
            _make_result("semgrep", category="code"),
        ]
        output = json.loads(render_json(results))
        names = [p["name"] for p in output["plugins"]]
        assert "trivy" in names
        assert "gitleaks" in names
        assert "semgrep" in names

    def test_includes_skip_reasons(self) -> None:
        from caliper.core.json_report import render_json

        results = [
            _make_result(
                "osv-scanner",
                skip_reason="Binary not installed",
                skip_remediation="brew install osv-scanner",
            ),
        ]
        output = json.loads(render_json(results))
        plugin = output["plugins"][0]
        assert plugin["skip_reason"] == "Binary not installed"
        assert plugin["skip_remediation"] == "brew install osv-scanner"
        assert plugin["status"] == "skipped"

    def test_includes_error(self) -> None:
        from caliper.core.json_report import render_json

        results = [_make_result("clamav", error="TIMEOUT after 60s")]
        output = json.loads(render_json(results))
        plugin = output["plugins"][0]
        assert plugin["status"] == "error"
        assert plugin["error"] == "TIMEOUT after 60s"

    def test_includes_findings(self) -> None:
        from caliper.core.json_report import render_json

        findings = [{"id": "CVE-2025-1234", "severity": "critical"}]
        results = [_make_result("trivy", findings=findings)]
        output = json.loads(render_json(results))
        plugin = output["plugins"][0]
        assert plugin["status"] == "ran"
        assert plugin["findings_count"] == 1
        assert plugin["findings"][0]["id"] == "CVE-2025-1234"

    def test_has_totals(self) -> None:
        from caliper.core.json_report import render_json

        findings = [{"id": "CVE-1"}, {"id": "CVE-2"}]
        results = [
            _make_result("trivy", findings=findings),
            _make_result("gitleaks", category="supply_chain"),
        ]
        output = json.loads(render_json(results))
        assert output["total_findings"] == 2
        assert output["total_plugins"] == 2

    def test_has_scores(self) -> None:
        from caliper.core.json_report import render_json

        output = json.loads(render_json([_make_result()]))
        assert "security_score" in output
        assert "quality_score" in output
