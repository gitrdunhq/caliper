# tested-by: tests/unit/test_registry_normalization.py
"""Tests for finding normalization at the registry boundary."""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import (
    PluginCategory,
    PluginFinding,
    PluginResult,
    ScannerPlugin,
)


class _DictPlugin(ScannerPlugin):
    """Plugin that returns old-style list[dict] findings."""

    @property
    def name(self) -> str:
        return "dict-plugin"

    @property
    def description(self) -> str:
        return "test"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            findings=[
                {
                    "id": "CVE-2025-001",
                    "severity": "critical",
                    "message": "Bad thing",
                    "package": "requests",
                    "custom_key": "preserved",
                },
            ],
        )


class TestRegistryNormalization:
    def test_registry_normalizes_findings_to_plugin_finding(self) -> None:
        from caliper.core.registry import PluginRegistry

        registry = PluginRegistry()
        registry.register(_DictPlugin())
        results = registry.run_all(["test.py"], Path("/fake"))

        assert len(results) == 1
        r = results[0]
        assert len(r.findings) == 1
        f = r.findings[0]
        assert isinstance(f, PluginFinding)
        assert f.id == "CVE-2025-001"
        assert f.severity == "critical"
        assert f.package == "requests"
        assert f.metadata["custom_key"] == "preserved"

    def test_already_typed_findings_pass_through(self) -> None:
        from caliper.core.plugin import normalize_finding

        raw = {"id": "X", "severity": "info", "message": "ok"}
        finding = normalize_finding(raw)
        assert isinstance(finding, PluginFinding)
        assert finding.id == "X"
