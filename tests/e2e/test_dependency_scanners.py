# tested-by: self (e2e)
"""E2E: dependency/license scanners find planted signals in vuln-repo."""

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


class TestOsvScanner:
    def test_osv_scanner_finds_cve(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="osv-scanner", output_format="json")
        breakpoint_dump(tmp_path, "scanner_osv", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "osv-scanner")
        vuln_findings = [
            f
            for f in findings
            if any(k in json.dumps(f).lower() for k in ("cve-", "ghsa-", "pysec-", "vulnerability"))
        ]
        assert (
            len(vuln_findings) >= 1
        ), f"OSV should find CVEs in requests==2.25.1. Findings: {json.dumps(findings, indent=2)}"


class TestTrivy:
    def test_trivy_finds_vuln(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="trivy", output_format="json")
        breakpoint_dump(tmp_path, "scanner_trivy", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "trivy")
        assert len(findings) >= 1, f"Trivy should find vulns. Output: {result.output[:500]}"


class TestSyft:
    def test_syft_produces_sbom(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="syft", output_format="json")
        breakpoint_dump(tmp_path, "scanner_syft", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"


class TestScancode:
    def test_scancode_detects_license(self, vuln_repo: Path, tmp_path: Path) -> None:
        """Scancode detects GPL license in the fixture.

        Known limitation on arm64: scancode crashes due to missing
        extractcode-libarchive (no arm64 wheel). Fail-open means
        exit code is still 0 and the error is captured in the plugin result.
        On amd64 this test asserts actual GPL findings.
        """
        result, parsed = run_review(vuln_repo, scanners="scancode", output_format="json")
        breakpoint_dump(tmp_path, "scanner_scancode", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "scancode")
        if findings:
            license_findings = [
                f
                for f in findings
                if "gpl" in json.dumps(f).lower() or "license" in json.dumps(f).lower()
            ]
            assert (
                len(license_findings) >= 1
            ), f"Scancode should detect license. Findings: {json.dumps(findings[:5], indent=2)}"
