"""Tests for scanner base class and subprocess utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from caliper.core.models import ScanResultStatus
from caliper.data.scanners.base import (
    Scanner,
    _make_failed_result,
    _make_not_installed_result,
    _make_timeout_result,
    run_subprocess_with_timeout,
)

# ---------------------------------------------------------------------------
# run_subprocess_with_timeout
# ---------------------------------------------------------------------------


class TestRunSubprocessWithTimeout:
    """Tests for the subprocess wrapper utility."""

    @patch("caliper.data.scanners.base.subprocess.run")
    def test_successful_run_returns_stdout(self, mock_run: patch) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["echo", "hello"],
            returncode=0,
            stdout="hello\n",
            stderr="",
        )

        returncode, stdout, stderr = run_subprocess_with_timeout(cmd=["echo", "hello"], timeout=10)

        assert returncode == 0
        assert stdout == "hello\n"
        assert stderr == ""
        mock_run.assert_called_once_with(
            ["echo", "hello"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=None,
        )

    @patch("caliper.data.scanners.base.subprocess.run")
    def test_timeout_returns_none_returncode_and_message(self, mock_run: patch) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["slow"], timeout=5)

        returncode, stdout, stderr = run_subprocess_with_timeout(cmd=["slow"], timeout=5)

        assert returncode is None
        assert stdout == ""
        assert stderr == "timeout exceeded"

    @patch("caliper.data.scanners.base.subprocess.run")
    def test_nonzero_exit_returns_stderr(self, mock_run: patch) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["fail"],
            returncode=1,
            stdout="",
            stderr="something went wrong",
        )

        returncode, stdout, stderr = run_subprocess_with_timeout(cmd=["fail"], timeout=10)

        assert returncode == 1
        assert stdout == ""
        assert stderr == "something went wrong"

    @patch("caliper.data.scanners.base.subprocess.run")
    def test_cwd_passed_to_subprocess(self, mock_run: patch) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ls"], returncode=0, stdout="file.txt\n", stderr=""
        )
        cwd = Path("/tmp/test-dir")

        run_subprocess_with_timeout(cmd=["ls"], timeout=10, cwd=cwd)

        mock_run.assert_called_once_with(
            ["ls"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=cwd,
        )

    @patch("caliper.data.scanners.base.subprocess.run")
    def test_oserror_returns_failure(self, mock_run: patch) -> None:
        mock_run.side_effect = OSError("No such file or directory")

        returncode, stdout, stderr = run_subprocess_with_timeout(cmd=["nonexistent"], timeout=10)

        assert returncode is None
        assert stdout == ""
        assert "No such file or directory" in stderr


# ---------------------------------------------------------------------------
# Helper result constructors
# ---------------------------------------------------------------------------


class TestMakeTimeoutResult:
    """Tests for _make_timeout_result helper."""

    def test_produces_timeout_status(self) -> None:
        result = _make_timeout_result("syft", timeout=60)

        assert result.tool_name == "syft"
        assert result.status == ScanResultStatus.timeout
        assert result.findings == []
        assert result.duration_seconds == 60
        assert "60" in (result.message or "")
        assert "timeout" in (result.message or "").lower()

    def test_scanner_name_in_message(self) -> None:
        result = _make_timeout_result("trivy", timeout=30)

        assert "trivy" in (result.message or "").lower()


class TestMakeFailedResult:
    """Tests for _make_failed_result helper."""

    def test_produces_failed_status(self) -> None:
        result = _make_failed_result("osv-scanner", "parse error on line 42")

        assert result.tool_name == "osv-scanner"
        assert result.status == ScanResultStatus.failed
        assert result.findings == []
        assert "parse error on line 42" in (result.message or "")
        assert result.duration_seconds == 0

    def test_custom_message_preserved(self) -> None:
        msg = "binary not found at /usr/local/bin/syft"
        result = _make_failed_result("syft", msg)

        assert result.message == msg


class TestMakeNotInstalledResult:
    """Tests for _make_not_installed_result helper."""

    def test_produces_failed_status(self) -> None:
        result = _make_not_installed_result("scancode")

        assert result.tool_name == "scancode"
        assert result.status == ScanResultStatus.failed
        assert result.duration_seconds == 0

    def test_message_mentions_scanner_name(self) -> None:
        result = _make_not_installed_result("trivy")

        assert "trivy" in (result.message or "").lower()
        assert "install" in (result.message or "").lower()


# ---------------------------------------------------------------------------
# ScannerPort Protocol (Scanner is a backward-compat alias)
# ---------------------------------------------------------------------------


class TestScannerPort:
    """Tests that ScannerPort is a runtime-checkable structural Protocol."""

    def test_cannot_instantiate_the_protocol(self) -> None:
        # Protocols cannot be instantiated directly.
        with pytest.raises(TypeError):
            Scanner()  # type: ignore[misc]

    def test_duck_typed_object_satisfies_the_protocol(self) -> None:
        class DummyScanner:
            @property
            def name(self) -> str:
                return "dummy"

            def scan(self, target_path: Path) -> None:
                return None  # type: ignore[return-value]

        scanner = DummyScanner()
        assert scanner.name == "dummy"
        # Structural conformance — no inheritance required.
        assert isinstance(scanner, Scanner)

    def test_object_missing_methods_does_not_satisfy_the_protocol(self) -> None:
        class NotAScanner:
            name = "incomplete"

        assert not isinstance(NotAScanner(), Scanner)
