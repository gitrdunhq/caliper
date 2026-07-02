"""Tests for third-party plugin discovery via the "caliper.plugins" entry-point group.
# tested-by: tests/unit/test_plugin_sdk.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.plugins import get_default_registry


class _FakeEntryPoint:
    def __init__(self, name: str, factory) -> None:
        self.name = name
        self._factory = factory

    def load(self):
        return self._factory


class _ThirdPartyPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "third-party-demo"

    @property
    def description(self) -> str:
        return "A fake third-party plugin used only in tests."

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(plugin_name=self.name, findings=[])


class _BrokenPluginClass:
    def __init__(self) -> None:
        raise RuntimeError("boom: this plugin always fails to construct")


def _patch_entry_points(monkeypatch, entry_points: list) -> None:
    def fake_entry_points(*, group=None):
        if group == "caliper.plugins":
            return entry_points
        return []

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)


class TestEntryPointDiscovery:
    def test_valid_entry_point_plugin_is_registered_and_runs(self, monkeypatch, tmp_path) -> None:
        _patch_entry_points(monkeypatch, [_FakeEntryPoint("demo", _ThirdPartyPlugin)])

        registry = get_default_registry()
        plugin = registry.get("third-party-demo")

        assert plugin is not None
        result = plugin.run([], tmp_path)
        assert result.plugin_name == "third-party-demo"

    def test_raising_entry_point_is_skipped_not_raised(self, monkeypatch) -> None:
        _patch_entry_points(monkeypatch, [_FakeEntryPoint("broken", _BrokenPluginClass)])

        registry = get_default_registry()  # must not raise

        assert registry.get("third-party-demo") is None

    def test_broken_and_valid_entry_points_coexist(self, monkeypatch) -> None:
        _patch_entry_points(
            monkeypatch,
            [
                _FakeEntryPoint("broken", _BrokenPluginClass),
                _FakeEntryPoint("demo", _ThirdPartyPlugin),
            ],
        )

        registry = get_default_registry()

        assert registry.get("third-party-demo") is not None

    def test_builtin_plugins_still_load_alongside_entry_points(self, monkeypatch) -> None:
        baseline_count = len(get_default_registry().list())
        _patch_entry_points(monkeypatch, [_FakeEntryPoint("demo", _ThirdPartyPlugin)])

        registry = get_default_registry()

        assert len(registry.list()) == baseline_count + 1

    def test_no_entry_points_registered_is_a_noop(self, monkeypatch) -> None:
        _patch_entry_points(monkeypatch, [])

        registry = get_default_registry()

        assert registry.get("third-party-demo") is None

    def test_entry_points_lookup_failure_is_fail_open(self, monkeypatch) -> None:
        def raising_entry_points(*, group=None):
            raise RuntimeError("metadata backend broken")

        monkeypatch.setattr("importlib.metadata.entry_points", raising_entry_points)

        registry = get_default_registry()  # must not raise

        assert len(registry.list()) > 0  # built-ins still loaded
