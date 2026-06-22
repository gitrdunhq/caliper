"""Tests for ScanCode plugin.
# tested-by: tests/unit/test_scancode.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.plugins.scancode import ScanCodePlugin


class TestScanCodePluginDisabled:
    def test_can_run_returns_true(self) -> None:
        """Scancode re-enabled — diff-scoped via --include, timeout configurable. Closes #335."""
        p = ScanCodePlugin()
        assert p.can_run(["any.py"], Path(".")) is True

    def test_name(self) -> None:
        assert ScanCodePlugin().name == "scancode"
