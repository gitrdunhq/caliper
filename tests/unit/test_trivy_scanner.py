"""Tests for the Trivy vulnerability scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.models import (
    FindingCategory,
    FindingSeverity,
    ScanResultStatus,
)
from caliper.data.scanners.trivy import TrivyScanner

# ---------------------------------------------------------------------------
# Fixtures: sample Trivy JSON output
# ---------------------------------------------------------------------------

TRIVY_OUTPUT_WITH_VULNS = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "MEDIUM",
                        "Title": "Unintended leak of Proxy-Authorization header",
                        "Description": "Requests leaks Proxy-Authorization headers.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-32681",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-35195",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.32.0",
                        "Severity": "CRITICAL",
                        "Title": "cert verification bypass",
                        "Description": "Requests sessions do not verify certs properly.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-35195",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-43804",
                        "PkgName": "urllib3",
                        "InstalledVersion": "1.26.5",
                        "FixedVersion": "1.26.18",
                        "Severity": "HIGH",
                        "Title": "Cookie leak on redirect",
                        "Description": "urllib3 leaks cookies on cross-origin redirect.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-43804",
                    },
                ],
            },
        ],
    }
)

TRIVY_OUTPUT_ZERO_VULNS = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": None,
            },
        ],
    }
)

TRIVY_OUTPUT_EMPTY_RESULTS = json.dumps({"SchemaVersion": 2, "Results": []})


class TestTrivyScannerSuccess:
    """Tests for successful Trivy scans."""

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_parses_vulnerabilities_into_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.tool_name == "trivy"
        assert len(result.findings) == 3

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_finding_fields_populated(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        finding = result.findings[0]
        assert finding.category == FindingCategory.vulnerability
        assert finding.advisory_id == "CVE-2023-32681"
        assert finding.source_tool == "trivy"
        assert finding.package_name == "requests"
        assert finding.version == "2.25.0"
        assert finding.advisory_url == "https://avd.aquasec.com/nvd/cve-2023-32681"

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_severity_mapping_critical(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        critical_finding = next(f for f in result.findings if f.advisory_id == "CVE-2024-35195")
        assert critical_finding.severity == FindingSeverity.critical

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_severity_mapping_high(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        high_finding = next(f for f in result.findings if f.advisory_id == "CVE-2023-43804")
        assert high_finding.severity == FindingSeverity.high

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_severity_mapping_medium(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_WITH_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        med_finding = next(f for f in result.findings if f.advisory_id == "CVE-2023-32681")
        assert med_finding.severity == FindingSeverity.medium

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_zero_vulns_returns_success_empty_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_ZERO_VULNS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.findings == []

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_empty_results_returns_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_EMPTY_RESULTS, "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.findings == []

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_invokes_correct_command(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, TRIVY_OUTPUT_EMPTY_RESULTS, "")
        scanner = TrivyScanner()

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "trivy" in cmd
        assert "fs" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert "--scanners" in cmd
        assert "vuln" in cmd

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_skip_dirs_excludes_node_modules_and_dist(self, mock_run: MagicMock) -> None:
        """Trivy must pass --skip-dirs for node_modules, dist, and .git.

        Scanning these directories on large repos causes Errno 5 I/O errors that
        corrupt the container overlay filesystem and kill the podman runtime.
        See issue #352.
        """
        mock_run.return_value = (0, TRIVY_OUTPUT_EMPTY_RESULTS, "")
        scanner = TrivyScanner()

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "--skip-dirs" in cmd, (
            "trivy invocation is missing --skip-dirs. Scanning node_modules or dist "
            "can cause Errno 5 I/O errors that corrupt the podman overlay storage. "
            "Add --skip-dirs node_modules,dist,.git to the trivy command. See #352."
        )
        skip_idx = cmd.index("--skip-dirs")
        skip_val = cmd[skip_idx + 1]
        assert (
            "node_modules" in skip_val
        ), f"--skip-dirs value {skip_val!r} must include node_modules"
        assert "dist" in skip_val, f"--skip-dirs value {skip_val!r} must include dist"

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_respects_gitignore(self, mock_run: MagicMock) -> None:
        """Trivy must pass --respect-gitignore to avoid scanning vendored/generated files.

        Without this flag trivy scans everything including files declared in
        .gitignore such as build output, vendored dependencies, and generated
        lockfiles — wasting time and producing noise. See issue #352.
        """
        mock_run.return_value = (0, TRIVY_OUTPUT_EMPTY_RESULTS, "")
        scanner = TrivyScanner()

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "--respect-gitignore" in cmd, (
            "trivy invocation is missing --respect-gitignore. "
            "Add it so trivy skips files declared in .gitignore. See #352."
        )


class TestTrivyScannerFailure:
    """Tests for Trivy failure modes."""

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_timeout_returns_timeout_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "timeout exceeded")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.timeout

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_not_installed_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "No such file or directory")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_invalid_json_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, "not json", "")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("caliper.data.scanners.trivy.run_subprocess_with_timeout")
    def test_nonzero_exit_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (2, "", "fatal error")
        scanner = TrivyScanner()

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed
