"""Tests for the ScanCode plugin (diff-scoped invocation).
# tested-by: tests/unit/test_plugin_scancode.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.plugin import PluginCategory
from caliper.plugins.scancode import ScanCodePlugin

SCAN_OUTPUT = json.dumps(
    {
        "headers": [{"tool_name": "scancode-toolkit", "tool_version": "32.5.0"}],
        "files": [
            {
                "path": "src/app.py",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression_spdx": "MIT",
                        "license_expression": "mit",
                        "matches": [{"score": 95.0}],
                    }
                ],
            }
        ],
    }
)

EMPTY_OUTPUT = json.dumps(
    {
        "headers": [{"tool_name": "scancode-toolkit", "tool_version": "32.5.0"}],
        "files": [],
    }
)


class TestScanCodePluginMeta:
    def test_name(self):
        assert ScanCodePlugin().name == "scancode"

    def test_category(self):
        assert ScanCodePlugin().category == PluginCategory.dependency

    def test_can_run_returns_true(self):
        assert ScanCodePlugin().can_run(["src/app.py"], Path("/repo")) is True


class TestScanCodePluginEmptyFiles:
    def test_empty_files_returns_empty_without_subprocess(self):
        """When no changed files are provided, skip subprocess entirely."""
        with patch("caliper.plugins.scancode.subprocess.run") as mock_run:
            result = ScanCodePlugin().run([], Path("/repo"))
        mock_run.assert_not_called()
        assert result.findings == []
        assert result.error == ""

    def test_all_files_outside_repo_returns_empty(self):
        """Files that can't be made relative to repo_path are skipped; if none remain, return empty."""
        with patch("caliper.plugins.scancode.subprocess.run") as mock_run:
            result = ScanCodePlugin().run(["/other/repo/file.py"], Path("/repo"))
        mock_run.assert_not_called()
        assert result.findings == []


class TestScanCodePluginCommand:
    @patch("caliper.plugins.scancode.subprocess.run")
    def test_include_args_built_from_files(self, mock_run: MagicMock):
        """--include is added for each changed file relative to repo_path."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = EMPTY_OUTPUT
        mock_run.return_value.stderr = ""

        ScanCodePlugin().run(
            ["/repo/src/app.py", "/repo/lib/utils.py"],
            Path("/repo"),
        )

        cmd = mock_run.call_args[0][0]
        assert "--include" in cmd
        assert "src/app.py" in cmd
        assert "lib/utils.py" in cmd

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_strip_root_in_command(self, mock_run: MagicMock):
        """--strip-root must be present so --include patterns match resource paths."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = EMPTY_OUTPUT
        mock_run.return_value.stderr = ""

        ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        cmd = mock_run.call_args[0][0]
        assert "--strip-root" in cmd

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_only_findings_in_command(self, mock_run: MagicMock):
        """--only-findings drops files with no hits from JSON output."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = EMPTY_OUTPUT
        mock_run.return_value.stderr = ""

        ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        cmd = mock_run.call_args[0][0]
        assert "--only-findings" in cmd

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_repo_path_is_positional_arg(self, mock_run: MagicMock):
        """repo_path is the final positional argument to scancode."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = EMPTY_OUTPUT
        mock_run.return_value.stderr = ""

        ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        cmd = mock_run.call_args[0][0]
        assert cmd[-1] == "/repo"

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_files_outside_repo_skipped(self, mock_run: MagicMock):
        """Files not under repo_path are silently skipped; valid files still scanned."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = EMPTY_OUTPUT
        mock_run.return_value.stderr = ""

        ScanCodePlugin().run(
            ["/repo/src/app.py", "/other/file.py"],
            Path("/repo"),
        )

        cmd = mock_run.call_args[0][0]
        assert "src/app.py" in cmd
        assert "/other/file.py" not in cmd


class TestScanCodePluginResults:
    @patch("caliper.plugins.scancode.subprocess.run")
    def test_license_findings_extracted(self, mock_run: MagicMock):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = SCAN_OUTPUT
        mock_run.return_value.stderr = ""

        result = ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        assert result.error == ""
        assert len(result.findings) == 1
        assert result.findings[0]["license"] == "MIT"
        assert result.findings[0]["confidence"] == 95.0

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_not_installed_returns_error(self, mock_run: MagicMock):
        mock_run.side_effect = FileNotFoundError

        result = ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        assert result.error != ""
        assert result.findings == []

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_timeout_returns_error(self, mock_run: MagicMock):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="scancode", timeout=60)

        result = ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        assert result.error != ""


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


class TestScanCodePluginCopyright:
    """Tests for copyright detection in the plugin (closes #335)."""

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_copyright_flag_in_cmd(self, mock_run: MagicMock):
        """--copyright is always included in the scancode command."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = EMPTY_OUTPUT
        mock_run.return_value.stderr = ""

        ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        cmd = mock_run.call_args[0][0]
        assert "--copyright" in cmd

    @patch("caliper.plugins.scancode.subprocess.run")
    def test_copyright_entries_produce_copyright_findings(self, mock_run: MagicMock):
        """Copyright entries in JSON output produce findings with category 'copyright'."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = SCAN_OUTPUT_WITH_COPYRIGHT
        mock_run.return_value.stderr = ""

        result = ScanCodePlugin().run(["/repo/src/app.py"], Path("/repo"))

        assert result.error == ""
        copyright_findings = [f for f in result.findings if f.get("category") == "copyright"]
        assert len(copyright_findings) == 1
        assert copyright_findings[0]["copyright"] == "Copyright (c) 2024 Acme"
        assert copyright_findings[0]["severity"] == "info"
