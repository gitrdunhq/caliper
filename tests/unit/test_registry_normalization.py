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
        from caliper.core.plugin_registry import PluginRegistry

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


class TestLineNormalizationIsNoneSafe:
    """A plugin may attach ``"line": None`` (osv-scanner does when source mapping is
    partial); that must normalize to 0, not crash the whole plugin run."""

    def test_explicit_none_line_becomes_zero(self) -> None:
        from caliper.core.plugin import normalize_finding

        f = normalize_finding({"id": "CVE-1", "severity": "high", "file": "a.py", "line": None})
        assert f.line == 0

    def test_string_line_is_coerced(self) -> None:
        from caliper.core.plugin import normalize_finding

        assert normalize_finding({"id": "x", "line": "12"}).line == 12


class TestOsvScannerDependencyKindSurvivesNormalization:
    """Regression: a raw finding dict keyed "metadata" (osv-scanner's
    dependency_kind carrier) must not collide with normalize_finding's own
    metadata bucket. A plugin-level test asserting on the raw dict cannot see
    this — it only appears after PluginRegistry normalizes the finding, which
    is the path every real `caliper review` takes."""

    def test_raw_metadata_key_is_not_double_nested_after_normalization(self) -> None:
        from caliper.core.plugin import normalize_finding

        raw = {
            "id": "CVE-2026-1",
            "severity": "high",
            "package": "@babel/core",
            "version": "7.21.4",
            "file": "yarn.lock",
            "line": None,
            "metadata": {"dependency_kind": "transitive"},
        }
        finding = normalize_finding(raw)
        assert finding.metadata.get("dependency_kind") == "transitive", (
            f"dependency_kind must be directly reachable at metadata['dependency_kind'], "
            f"got {finding.metadata!r}"
        )

    def test_via_registry_run_all(self, tmp_path: Path) -> None:
        from caliper.core.plugin_registry import PluginRegistry

        class _OsvLikePlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return "test-osv-like"

            @property
            def description(self) -> str:
                return "test plugin"

            @property
            def category(self) -> PluginCategory:
                return PluginCategory.dependency

            def can_run(self, files: list[str], repo_path: Path) -> bool:
                return True

            def run(self, files: list[str], repo_path: Path) -> PluginResult:
                return PluginResult(
                    plugin_name=self.name,
                    findings=[
                        {
                            "id": "CVE-2026-1",
                            "severity": "high",
                            "package": "@babel/core",
                            "version": "7.21.4",
                            "file": "yarn.lock",
                            "line": None,
                            "metadata": {"dependency_kind": "transitive"},
                        }
                    ],
                )

        reg = PluginRegistry()
        reg.register(_OsvLikePlugin())
        results = reg.run_all(["yarn.lock"], tmp_path)
        finding = results[0].findings[0]
        assert finding.metadata.get("dependency_kind") == "transitive"


class TestTrivyDependencyKindSurvivesNormalization:
    """Same collision as osv-scanner (#509), independently present in trivy.py."""

    def test_raw_metadata_key_is_not_double_nested_after_normalization(self) -> None:
        from caliper.core.plugin import normalize_finding

        raw = {
            "id": "CVE-2026-1",
            "severity": "high",
            "package": "aws-cdk-lib",
            "version": "2.138.0",
            "dependency_kind": "direct",
        }
        finding = normalize_finding(raw)
        assert finding.metadata.get("dependency_kind") == "direct"
