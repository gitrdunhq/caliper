"""Tests for the ScanCode license scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.models import (
    FindingCategory,
    FindingSeverity,
    ScanResultStatus,
)
from caliper.data.scanners.scancode import ScanCodeScanner, to_cyclonedx

# ---------------------------------------------------------------------------
# Fixtures: sample ScanCode JSON output
# ---------------------------------------------------------------------------

SCANCODE_OUTPUT = json.dumps(
    {
        "headers": [{"tool_name": "scancode-toolkit", "tool_version": "32.1.0"}],
        "files": [
            {
                "path": "src/caliper/__init__.py",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "apache-2.0",
                        "license_expression_spdx": "Apache-2.0",
                        "matches": [
                            {
                                "license_expression": "apache-2.0",
                                "score": 100.0,
                                "matched_text": "Licensed under the Apache License, Version 2.0",
                            },
                        ],
                    },
                ],
            },
            {
                "path": "vendor/lib.py",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "gpl-3.0",
                        "license_expression_spdx": "GPL-3.0-only",
                        "matches": [
                            {
                                "license_expression": "gpl-3.0",
                                "score": 95.5,
                                "matched_text": "GNU General Public License v3",
                            },
                        ],
                    },
                ],
            },
        ],
    }
)

SCANCODE_NO_LICENSES = json.dumps(
    {
        "headers": [{"tool_name": "scancode-toolkit", "tool_version": "32.1.0"}],
        "files": [
            {
                "path": "src/main.py",
                "type": "file",
                "license_detections": [],
            },
        ],
    }
)

SCAN_OUTPUT_WITH_COPYRIGHT = json.dumps(
    {
        "files": [
            {
                "path": "src/app.py",
                "license_detections": [],
                "copyrights": [
                    {
                        "copyright": "Copyright (c) 2024 Acme",
                        "start_line": 1,
                        "end_line": 1,
                    }
                ],
            }
        ]
    }
)


class TestScanCodeScannerSuccess:
    """Tests for successful ScanCode scans."""

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_parses_licenses_into_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_OUTPUT, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.tool_name == "scancode"
        assert len(result.findings) == 2

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_finding_fields_populated(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_OUTPUT, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        apache = result.findings[0]
        assert apache.category == FindingCategory.license
        assert apache.severity == FindingSeverity.info
        assert apache.license_id == "Apache-2.0"
        assert apache.confidence == 100.0
        assert apache.source_tool == "scancode"

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_gpl_license_detected(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_OUTPUT, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        gpl = result.findings[1]
        assert gpl.license_id == "GPL-3.0-only"
        assert gpl.confidence == 95.5

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_no_licenses_returns_empty_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_NO_LICENSES, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.findings == []

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_invokes_correct_command(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, SCANCODE_NO_LICENSES, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "scancode" in cmd
        assert "--license" in cmd
        assert "--json-pp" in cmd


class TestScanCodeScannerFailure:
    """Tests for ScanCode failure modes."""

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_timeout_returns_timeout_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "timeout exceeded")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.timeout

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_not_installed_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "No such file or directory")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_invalid_json_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, "not json", "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_nonzero_exit_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (1, "", "scancode: error")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed


class TestScanCodeScannerSettings:
    """Tests for new timeout/license_score params (closes #335)."""

    def test_accepts_timeout_and_license_score_params(self) -> None:
        """ScanCodeScanner accepts timeout and license_score constructor params."""
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"), timeout=30, license_score=50)
        assert scanner is not None

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_license_score_in_cmd_when_nonzero(self, mock_run: MagicMock) -> None:
        """--license-score is added to the command when license_score > 0."""
        mock_run.return_value = (0, SCANCODE_NO_LICENSES, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"), timeout=60, license_score=75)

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "--license-score" in cmd
        assert "75" in cmd

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_license_score_absent_when_zero(self, mock_run: MagicMock) -> None:
        """--license-score is NOT added when license_score == 0."""
        mock_run.return_value = (0, SCANCODE_NO_LICENSES, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"), timeout=60, license_score=0)

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "--license-score" not in cmd

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_copyright_in_cmd(self, mock_run: MagicMock) -> None:
        """--copyright is always present in the scancode command."""
        mock_run.return_value = (0, SCANCODE_NO_LICENSES, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "--copyright" in cmd

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_copyright_findings_extracted(self, mock_run: MagicMock) -> None:
        """Copyright detections produce FindingCategory.copyright findings."""
        mock_run.return_value = (0, SCAN_OUTPUT_WITH_COPYRIGHT, "")
        scanner = ScanCodeScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        copyright_findings = [f for f in result.findings if f.category == FindingCategory.copyright]
        assert len(copyright_findings) == 1
        assert "Copyright (c) 2024 Acme" in copyright_findings[0].description
        assert copyright_findings[0].severity == FindingSeverity.info
        assert copyright_findings[0].source_tool == "scancode"


class TestToCyclonedx:
    """Tests for the to_cyclonedx() standalone function."""

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_cyclonedx_calls_scancode_with_cyclonedx_flag(self, mock_run: MagicMock) -> None:
        """to_cyclonedx() invokes scancode with --cyclonedx."""
        mock_run.return_value = (0, "", "")

        result = to_cyclonedx(repo_path=Path("/project"), output_path=Path("/tmp/sbom.json"))

        assert result is True
        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "--cyclonedx" in cmd
        assert "--license" in cmd
        assert "--copyright" in cmd
        assert "--package" in cmd

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_cyclonedx_returns_false_on_failure(self, mock_run: MagicMock) -> None:
        """to_cyclonedx() returns False on non-zero exit."""
        mock_run.return_value = (1, "", "scancode error")

        result = to_cyclonedx(repo_path=Path("/project"), output_path=Path("/tmp/sbom.json"))

        assert result is False

    @patch("caliper.data.scanners.scancode.run_subprocess_with_timeout")
    def test_cyclonedx_returns_false_on_timeout(self, mock_run: MagicMock) -> None:
        """to_cyclonedx() returns False on timeout."""
        mock_run.return_value = (None, "", "timeout exceeded")

        result = to_cyclonedx(repo_path=Path("/project"), output_path=Path("/tmp/sbom.json"))

        assert result is False
