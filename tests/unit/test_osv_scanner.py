"""Tests for the OSV-Scanner vulnerability scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.models import (
    FindingCategory,
    FindingSeverity,
    ScanResultStatus,
)
from caliper.data.scanners.osv import OsvScanner

# ---------------------------------------------------------------------------
# Fixtures: sample OSV-Scanner JSON output
# ---------------------------------------------------------------------------

OSV_OUTPUT_WITH_VULNS = json.dumps(
    {
        "results": [
            {
                "source": {"path": "requirements.txt", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.25.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-j8r2-6x86-q33q",
                                "summary": "Unintended leak of Proxy-Authorization header",
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
                                    },
                                ],
                                "database_specific": {"severity": "MODERATE"},
                                "aliases": ["CVE-2023-32681"],
                            },
                        ],
                        "groups": [{"ids": ["GHSA-j8r2-6x86-q33q"], "aliases": ["CVE-2023-32681"]}],
                    },
                    {
                        "package": {"name": "urllib3", "version": "1.26.5", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-v845-jxx5-vc9f",
                                "summary": "urllib3 cookie leak on redirect",
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                                    },
                                ],
                                "database_specific": {"severity": "HIGH"},
                                "aliases": ["CVE-2023-43804"],
                            },
                        ],
                        "groups": [{"ids": ["GHSA-v845-jxx5-vc9f"], "aliases": ["CVE-2023-43804"]}],
                    },
                ],
            }
        ]
    }
)

OSV_OUTPUT_ZERO_VULNS = json.dumps({"results": []})


class TestOsvScannerSuccess:
    """Tests for successful OSV-Scanner runs."""

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_parses_vulnerabilities_into_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_WITH_VULNS, "")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.tool_name == "osv-scanner"
        assert len(result.findings) == 2

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_finding_fields_populated(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_WITH_VULNS, "")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        finding = result.findings[0]
        assert finding.category == FindingCategory.vulnerability
        assert finding.advisory_id == "GHSA-j8r2-6x86-q33q"
        assert finding.source_tool == "osv-scanner"
        assert finding.package_name == "requests"
        assert finding.version == "2.25.0"

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_severity_mapping(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_WITH_VULNS, "")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        # First vuln is MODERATE -> medium
        assert result.findings[0].severity == FindingSeverity.medium
        # Second vuln is HIGH -> high
        assert result.findings[1].severity == FindingSeverity.high

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_zero_vulns_returns_success_empty_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_ZERO_VULNS, "")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.findings == []

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_exit_code_1_with_vulns_is_success(self, mock_run: MagicMock) -> None:
        """osv-scanner exits 1 when vulns are found — that is not an error."""
        mock_run.return_value = (1, OSV_OUTPUT_WITH_VULNS, "")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert len(result.findings) == 2

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_invokes_lockfile_mode(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_ZERO_VULNS, "")
        scanner = OsvScanner()

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "osv-scanner" in cmd
        assert "--format" in cmd
        assert "json" in cmd

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_sbom_mode_uses_sbom_flag(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_ZERO_VULNS, "")
        scanner = OsvScanner(sbom_path=Path("/evidence/sbom.json"))

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "--sbom" in cmd


class TestOsvScannerExcludePaths:
    """Tests for --experimental-exclude path exclusion support."""

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_exclude_paths_added_to_cmd(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_ZERO_VULNS, "")
        scanner = OsvScanner(exclude_paths=["tests/e2e/fixtures"])

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert any("--experimental-exclude" in arg for arg in cmd)
        assert any("tests/e2e/fixtures" in arg for arg in cmd)

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_multiple_exclude_paths_each_get_flag(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_ZERO_VULNS, "")
        scanner = OsvScanner(exclude_paths=["tests/e2e/fixtures", "vendor"])

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        exclude_args = [a for a in cmd if "--experimental-exclude" in a]
        assert len(exclude_args) == 2

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_no_exclude_paths_omits_flag(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, OSV_OUTPUT_ZERO_VULNS, "")
        scanner = OsvScanner()

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert not any("--experimental-exclude" in arg for arg in cmd)

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_exclude_paths_not_added_in_sbom_mode(self, mock_run: MagicMock) -> None:
        """Exclusions are path-based and irrelevant when scanning an SBOM directly."""
        mock_run.return_value = (0, OSV_OUTPUT_ZERO_VULNS, "")
        scanner = OsvScanner(
            sbom_path=Path("/evidence/sbom.json"),
            exclude_paths=["tests/e2e/fixtures"],
        )

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert not any("--experimental-exclude" in arg for arg in cmd)


class TestOsvScannerFailure:
    """Tests for OSV-Scanner failure modes."""

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_timeout_returns_timeout_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "timeout exceeded")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.timeout

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_not_installed_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "No such file or directory")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("caliper.data.scanners.osv.run_subprocess_with_timeout")
    def test_invalid_json_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, "not json", "")
        scanner = OsvScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed
