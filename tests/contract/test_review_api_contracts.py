# tested-by: self (contract)
"""Pure review API contracts that must not need scanner binaries or E2E fixtures."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.registry import PluginRegistry
from caliper.core.use_cases import ReviewOptions, review_repository

pytestmark = pytest.mark.contract


class RecordingPlugin(ScannerPlugin):
    def __init__(self, name: str, category: PluginCategory) -> None:
        self._name = name
        self._category = category
        self.received_files: list[str] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"{self._name} contract test plugin"

    @property
    def category(self) -> PluginCategory:
        return self._category

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        self.received_files = list(files)
        return PluginResult(plugin_name=self.name, findings=[])


class FakeAnalyzerRegistry:
    def __init__(self, results: list[PluginResult]) -> None:
        self.results = results
        self.calls: list[dict[str, object]] = []

    def run_all(self, files: list[str], repo_path: Path, **kwargs: object) -> list[PluginResult]:
        self.calls.append({"files": files, "repo_path": repo_path, **kwargs})
        return self.results


def test_registry_diff_scope_keeps_repo_wide_plugins_on_repo_files(tmp_path: Path) -> None:
    changed_files = ["src/caliper/core/use_cases.py"]
    repo_files = ["pyproject.toml", "src/caliper/core/use_cases.py", "Dockerfile"]
    quality_plugin = RecordingPlugin("quality-contract", PluginCategory.quality)
    dependency_plugin = RecordingPlugin("dependency-contract", PluginCategory.dependency)

    registry = PluginRegistry()
    registry.register(quality_plugin)
    registry.register(dependency_plugin)

    registry.run_all(changed_files, tmp_path, repo_files=repo_files)

    assert quality_plugin.received_files == changed_files
    assert dependency_plugin.received_files == repo_files


def test_review_repository_forwards_filter_contract_and_derives_blocked_verdict(
    tmp_path: Path,
) -> None:
    result = PluginResult(
        plugin_name="dependency-contract",
        category="dependency",
        findings=[
            {
                "id": "CVE-contract",
                "severity": "high",
                "message": "contract finding",
            }
        ],
    )
    registry = FakeAnalyzerRegistry([result])
    context = SimpleNamespace(analyzer_registry=registry)
    options = ReviewOptions(
        scanners=["dependency-contract"],
        disabled={"slow-scanner"},
        enabled={"dependency-contract"},
    )

    review_result = review_repository(
        context,  # type: ignore[arg-type]
        ["src/caliper/core/use_cases.py"],
        tmp_path,
        options,
        repo_files=["pyproject.toml"],
    )

    assert review_result.verdict == "blocked"
    assert registry.calls == [
        {
            "files": ["src/caliper/core/use_cases.py"],
            "repo_path": tmp_path,
            "names": ["dependency-contract"],
            "categories": None,
            "disabled_names": {"slow-scanner"},
            "enabled_names": {"dependency-contract"},
            "repo_files": ["pyproject.toml"],
        }
    ]
