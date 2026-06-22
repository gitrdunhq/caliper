# tested-by: self (e2e)
"""E2E: quality scanners find planted code smells in vuln-repo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    E2E_ENABLED,
    breakpoint_dump,
    get_plugin_findings,
    run_review,
)

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")


class TestComplexity:
    def test_complexity_finds_high_ccn(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="complexity", output_format="json")
        breakpoint_dump(tmp_path, "scanner_complexity", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "complexity")
        high_ccn = [
            f
            for f in findings
            if (f.get("ccn", 0) or 0) > 10
            or "complex" in json.dumps(f).lower()
            or "overly_complex" in json.dumps(f).lower()
        ]
        assert (
            len(high_ccn) >= 1
        ), f"Should find high CCN function. Findings: {json.dumps(findings, indent=2)}"


class TestCpd:
    def test_cpd_finds_duplicate(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="cpd", output_format="json")
        breakpoint_dump(tmp_path, "scanner_cpd", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "cpd")
        assert (
            len(findings) >= 1
        ), f"CPD should find duplicate blocks. Findings: {json.dumps(findings, indent=2)}"


class TestMypy:
    def test_mypy_finds_type_error(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="mypy", output_format="json")
        breakpoint_dump(tmp_path, "scanner_mypy", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "mypy")
        type_errors = [
            f
            for f in findings
            if "type" in json.dumps(f).lower() or "arg-type" in json.dumps(f).lower()
        ]
        assert (
            len(type_errors) >= 1
        ), f"Mypy should find type error. Findings: {json.dumps(findings, indent=2)}"


class TestCspell:
    def test_cspell_finds_typo(self, vuln_repo: Path, tmp_path: Path) -> None:
        """Cspell detects misspelled words."""
        result, parsed = run_review(vuln_repo, scanners="cspell", output_format="json")
        breakpoint_dump(tmp_path, "scanner_cspell", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "cspell")
        assert (
            len(findings) >= 1
        ), f"Cspell should find typos. Findings: {json.dumps(findings, indent=2)}"


class TestLsLint:
    def test_ls_lint_finds_naming_violation(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="ls-lint", output_format="json")
        breakpoint_dump(tmp_path, "scanner_ls_lint", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"
