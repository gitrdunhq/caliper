"""Tests for ClamAV plugin.
# tested-by: tests/unit/test_clamav_plugin.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from caliper.core.plugin import PluginCategory, PluginResult
from caliper.plugins.clamav import ClamAvPlugin

CLEAN_OUTPUT = """\
/workspace/src/app.py: OK
/workspace/src/utils.py: OK

----------- SCAN SUMMARY -----------
Known viruses: 8700000
Engine version: 1.4.2
Scanned files: 2
Infected files: 0
Data scanned: 0.01 MB
"""

INFECTED_OUTPUT = """\
/workspace/uploads/evil.bin: Eicar-Signature FOUND
/workspace/src/app.py: OK
/workspace/vendor/sketchy.so: Unix.Malware.Agent-123 FOUND

----------- SCAN SUMMARY -----------
Known viruses: 8700000
Engine version: 1.4.2
Scanned files: 3
Infected files: 2
Data scanned: 1.20 MB
"""


class TestClamAvPlugin:
    def test_name_and_category(self):
        p = ClamAvPlugin()
        assert p.name == "clamav"
        assert p.category == PluginCategory.supply_chain

    def test_can_run_always(self):
        p = ClamAvPlugin()
        assert p.can_run(["app.py"], Path(".")) is True

    @patch("caliper.plugins.clamav.subprocess.run")
    def test_clean_scan(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = CLEAN_OUTPUT
        mock_run.return_value.stderr = ""
        p = ClamAvPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))
        assert result.error == ""
        assert len(result.findings) == 0
        assert result.summary["infected"] == 0

    @patch("caliper.plugins.clamav.subprocess.run")
    def test_infected_scan(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = INFECTED_OUTPUT
        mock_run.return_value.stderr = ""
        p = ClamAvPlugin()
        result = p.run(["uploads/evil.bin"], Path("/workspace"))
        assert len(result.findings) == 2
        assert result.findings[0]["file"] == "/workspace/uploads/evil.bin"
        assert result.findings[0]["signature"] == "Eicar-Signature"
        assert result.findings[0]["severity"] == "critical"
        assert result.summary["infected"] == 2

    @patch(
        "caliper.plugins.clamav.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found(self, _mock):
        p = ClamAvPlugin()
        result = p.run(["app.py"], Path("."))
        assert "not installed" in result.error

    @patch("caliper.plugins.clamav.subprocess.run")
    def test_render_infected(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = INFECTED_OUTPUT
        mock_run.return_value.stderr = ""
        p = ClamAvPlugin()
        result = p.run(["uploads/evil.bin"], Path("/workspace"))
        md = p.render(result)
        assert "Malware" in md
        assert "Eicar-Signature" in md
        assert "evil.bin" in md

    def test_render_clean(self):
        p = ClamAvPlugin()
        result = PluginResult(
            plugin_name="clamav",
            summary={"infected": 0, "scanned": 2},
        )
        md = p.render(result)
        assert md == ""

    def test_render_error(self):
        p = ClamAvPlugin()
        result = PluginResult(
            plugin_name="clamav",
            error="not installed",
        )
        md = p.render(result)
        assert "not installed" in md

    @patch("caliper.plugins.clamav.subprocess.run")
    def test_clamscan_exit2_includes_stderr(self, mock_run):
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "LibClamAV Error: cl_load() error: No such file or directory"
        p = ClamAvPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))
        assert "BINARY_CRASHED" in result.error
        assert "LibClamAV Error" in result.error

    @patch("caliper.plugins.clamav.subprocess.run")
    def test_clamscan_exit2_no_stderr(self, mock_run):
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        p = ClamAvPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))
        assert "BINARY_CRASHED" in result.error
        # No trailing colon when stderr is empty
        assert not result.error.endswith(":")
