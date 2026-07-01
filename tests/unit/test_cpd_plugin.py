"""Tests for CpdPlugin scanner_timeout wiring (#432a).
# tested-by: tests/unit/test_cpd_plugin.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.config import CaliperSettings
from caliper.plugins import cpd as cpd_mod
from caliper.plugins.cpd import CpdPlugin


class TestCpdPluginTimeout:
    """CpdPlugin must honor CaliperSettings.scanner_timeout (#432a)."""

    def test_run_passes_scanner_timeout_from_settings(self, monkeypatch, tmp_path: Path) -> None:
        captured: dict = {}

        def fake_run(files, repo_path, timeout=60):
            captured["timeout"] = timeout
            return {"duplicates": [], "duplicate_count": 0, "files_scanned": 0}

        monkeypatch.setattr(cpd_mod, "_run", fake_run)

        plugin = CpdPlugin(settings=CaliperSettings(scanner_timeout=5))
        plugin.run(["a.py"], tmp_path)

        assert captured["timeout"] == 5

    def test_run_defaults_to_60_without_settings(self, monkeypatch, tmp_path: Path) -> None:
        captured: dict = {}

        def fake_run(files, repo_path, timeout=60):
            captured["timeout"] = timeout
            return {"duplicates": [], "duplicate_count": 0, "files_scanned": 0}

        monkeypatch.setattr(cpd_mod, "_run", fake_run)

        plugin = CpdPlugin()
        plugin.run(["a.py"], tmp_path)

        assert captured["timeout"] == 60
