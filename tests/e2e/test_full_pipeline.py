# tested-by: self (e2e)
"""E2E: full pipeline integration — all plugins, all output sections."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.conftest import (
    E2E_ENABLED,
    _extract_json,
    breakpoint_dump,
    get_all_findings,
    run_review,
)

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")


class TestFullReviewMarkdown:
    def test_full_review_markdown_structure(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, output = run_review(vuln_repo, run_all=True, output_format="markdown")
        breakpoint_dump(tmp_path, "layer3_markdown", {"output": output})

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"
        assert "Caliper" in output, "Missing header"
        assert "Plugin" in output, "Missing scanner table header"

    def test_full_review_all_plugins_present(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, output = run_review(vuln_repo, run_all=True, output_format="markdown")

        assert result.exit_code == 0

        expected_plugins = [
            "gitleaks",
            "semgrep",
            "clamav",
            "osv-scanner",
            "trivy",
            "syft",
            "scancode",
            "complexity",
            "cpd",
            "mypy",
            "typos",
            "ls-lint",
            "kube-linter",
            "cfn-nag",
            "cdk-nag",
            "supply-chain",
            "blast-radius",
        ]
        output_lower = output.lower()
        missing = [p for p in expected_plugins if p not in output_lower]
        assert len(missing) == 0, f"Plugins missing from output: {missing}"

    def test_full_review_severity_counts(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, run_all=True, output_format="json")
        breakpoint_dump(tmp_path, "layer2_json_full", parsed)

        assert result.exit_code == 0

        total_findings = len(get_all_findings(parsed))
        assert total_findings > 0, "vuln-repo should produce findings"


class TestFullReviewSarif:
    def test_sarif_schema_valid(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, _ = run_review(vuln_repo, run_all=True, output_format="sarif")
        parsed = _extract_json(result.output)
        breakpoint_dump(tmp_path, "layer3_sarif", parsed)

        assert result.exit_code == 0
        assert isinstance(parsed, dict), f"SARIF should be JSON dict: {type(parsed)}"
        assert parsed.get("version") == "2.1.0", f"SARIF version: {parsed.get('version')}"
        assert "$schema" in parsed, "Missing $schema"
        assert "runs" in parsed, "Missing runs[]"
        assert len(parsed["runs"]) > 0, "Empty runs[]"

    def test_sarif_run_per_plugin(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, _ = run_review(vuln_repo, run_all=True, output_format="sarif")
        parsed = _extract_json(result.output)

        assert result.exit_code == 0
        assert isinstance(parsed, dict)

        for run in parsed.get("runs", []):
            tool = run.get("tool", {}).get("driver", {})
            assert "name" in tool, f"Run missing tool.driver.name: {run}"

    def test_sarif_finding_structure(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, _ = run_review(vuln_repo, run_all=True, output_format="sarif")
        parsed = _extract_json(result.output)

        assert result.exit_code == 0
        assert isinstance(parsed, dict)

        has_results = False
        for run in parsed.get("runs", []):
            for res in run.get("results", []):
                has_results = True
                assert "ruleId" in res or "rule" in res, f"Result missing ruleId: {res}"
                assert "level" in res, f"Result missing level: {res}"
                assert "message" in res, f"Result missing message: {res}"

        assert has_results, "SARIF should contain at least one result"


class TestFullReviewJson:
    def test_json_output_valid(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, run_all=True, output_format="json")
        breakpoint_dump(tmp_path, "layer3_json", parsed)

        assert result.exit_code == 0
        assert isinstance(parsed, (dict, list)), f"JSON should be dict or list: {type(parsed)}"

    def test_json_output_plugin_keys(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, run_all=True, output_format="json")

        assert result.exit_code == 0
        assert isinstance(parsed, (dict, list))

        total_findings = len(get_all_findings(parsed))
        assert total_findings > 0, "JSON output should have findings"
