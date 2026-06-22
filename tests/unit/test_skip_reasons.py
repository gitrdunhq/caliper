"""Tests for plugin skip reasons in PluginResult.
# tested-by: tests/unit/test_skip_reasons.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin


class _StubPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "stub"

    @property
    def description(self) -> str:
        return "stub plugin"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return False

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(plugin_name=self.name)

    def skip_reason(self) -> tuple[str, str]:
        return ("No source files found", "Add .py files to the repo")


class TestPluginResultSkipReason:
    def test_skip_reason_field_exists(self) -> None:
        r = PluginResult(plugin_name="test", skip_reason="not installed")
        assert r.skip_reason == "not installed"

    def test_skip_remediation_field_exists(self) -> None:
        r = PluginResult(
            plugin_name="test",
            skip_remediation="Install with: brew install tool",
        )
        assert r.skip_remediation == "Install with: brew install tool"

    def test_skip_fields_default_empty(self) -> None:
        r = PluginResult(plugin_name="test")
        assert r.skip_reason == ""
        assert r.skip_remediation == ""


class TestScannerPluginSkipReason:
    def test_base_class_has_default_skip_reason(self) -> None:
        plugin = _StubPlugin()
        reason, remediation = plugin.skip_reason()
        assert reason != ""
        assert remediation != ""

    def test_custom_skip_reason_override(self) -> None:
        plugin = _StubPlugin()
        reason, remediation = plugin.skip_reason()
        assert reason == "No source files found"
        assert remediation == "Add .py files to the repo"


class TestRegistryPopulatesSkipReason:
    def test_skipped_plugin_has_skip_reason_in_result(self) -> None:
        from caliper.core.registry import PluginRegistry

        registry = PluginRegistry()
        registry.register(_StubPlugin())
        results = registry.run_all([], Path("/fake"))
        assert len(results) == 1
        r = results[0]
        assert r.summary.get("status") == "skipped"
        assert r.skip_reason == "No source files found"
        assert r.skip_remediation == "Add .py files to the repo"
