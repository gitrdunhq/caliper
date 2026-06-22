"""Tests for the Syft SBOM scanner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.models import ScanResultStatus
from caliper.data.scanners.syft import SyftScanner

# ---------------------------------------------------------------------------
# Fixtures: sample CycloneDX JSON output
# ---------------------------------------------------------------------------

CYCLONEDX_OUTPUT = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
            {
                "type": "library",
                "name": "urllib3",
                "version": "2.1.0",
                "purl": "pkg:pypi/urllib3@2.1.0",
            },
            {
                "type": "library",
                "name": "certifi",
                "version": "2024.2.2",
                "purl": "pkg:pypi/certifi@2024.2.2",
            },
        ],
    }
)

EMPTY_CYCLONEDX = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [],
    }
)


class TestSyftScannerSuccess:
    """Tests for successful Syft scans."""

    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_parses_component_count(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, CYCLONEDX_OUTPUT, "")
        scanner = SyftScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert result.tool_name == "syft"
        assert result.findings == []
        assert "3" in (result.message or "")

    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_zero_components(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, EMPTY_CYCLONEDX, "")
        scanner = SyftScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.success
        assert "0" in (result.message or "")

    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_invokes_correct_command(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, CYCLONEDX_OUTPUT, "")
        scanner = SyftScanner(evidence_dir=Path("/tmp/evidence"))

        scanner.scan(Path("/project"))

        cmd = mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
        assert "syft" in cmd
        assert "dir:/project" in cmd
        assert "cyclonedx-json" in cmd

    @patch("builtins.open", create=True)
    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_writes_evidence_file(self, mock_run: MagicMock, mock_open: MagicMock) -> None:
        mock_run.return_value = (0, CYCLONEDX_OUTPUT, "")
        evidence_dir = Path("/tmp/evidence")
        scanner = SyftScanner(evidence_dir=evidence_dir)

        result = scanner.scan(Path("/project"))

        assert result.raw_output_path is not None


class TestSyftScannerFailure:
    """Tests for Syft failure modes."""

    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_timeout_returns_timeout_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "timeout exceeded")
        scanner = SyftScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.timeout
        assert result.tool_name == "syft"

    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_not_installed_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (None, "", "No such file or directory")
        scanner = SyftScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed

    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_nonzero_exit_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (1, "", "syft error: bad input")
        scanner = SyftScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed
        assert "syft error" in (result.message or "").lower() or result.message is not None

    @patch("caliper.data.scanners.syft.run_subprocess_with_timeout")
    def test_invalid_json_returns_failed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = (0, "not json at all", "")
        scanner = SyftScanner(evidence_dir=Path("/tmp/evidence"))

        result = scanner.scan(Path("/project"))

        assert result.status == ScanResultStatus.failed
