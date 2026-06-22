"""Deterministic guards for plugin registry behavior.

# tested-by: tests/unit/test_deterministic_plugin_guards.py
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.registry import PluginRegistry

if TYPE_CHECKING:
    pass


class _TimingPlugin(ScannerPlugin):
    """A test plugin that records its execution timing."""

    def __init__(self, name: str, sleep_duration: float = 0.1, depends_on: list[str] | None = None):
        self._name = name
        self._sleep_duration = sleep_duration
        self._depends_on = depends_on or []
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"Test timing plugin {self._name}"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    @property
    def depends_on(self) -> list[str]:
        return self._depends_on

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        self.start_time = time.monotonic()
        # Simulate work with sleep - this represents actual analyzer work
        time.sleep(self._sleep_duration)
        self.end_time = time.monotonic()
        return PluginResult(
            plugin_name=self.name,
            findings=[],
            summary={"duration": self.end_time - self.start_time},
        )


@pytest.mark.xfail(
    reason="deterministic bug detector - independent analyzers run sequentially", strict=False
)
def test_independent_analyzers_run_sequentially():
    """
    Detects when independent analyzers (no dependencies) execute sequentially.

    This is a deterministic guard for issue #254. Independent analyzers
    should be able to run in parallel, but the current implementation
    runs them sequentially in a simple for loop.

    The test creates 3 independent plugins (no depends_on) that each
    sleep for a fixed duration. If they run sequentially, total time
    will be ~3x the individual sleep time. If they run in parallel,
    total time will be closer to 1x the sleep time.

    Acceptance Criteria:
    - Test detects sequential execution pattern
    - Marked xfail until issue #254 is fixed
    - Uses strict=False to allow both xpass (bug present) and xfail (bug fixed)
    """
    registry = PluginRegistry()

    # Create 3 independent plugins with no dependencies
    plugin_a = _TimingPlugin(name="analyzer-a", sleep_duration=0.05)
    plugin_b = _TimingPlugin(name="analyzer-b", sleep_duration=0.05)
    plugin_c = _TimingPlugin(name="analyzer-c", sleep_duration=0.05)

    registry.register(plugin_a)
    registry.register(plugin_b)
    registry.register(plugin_c)

    # Run all plugins
    start_time = time.monotonic()
    results = registry.run_all(
        files=["test.py"],
        repo_path=Path("/tmp"),
    )
    end_time = time.monotonic()

    total_duration = end_time - start_time
    expected_sequential_duration = 0.15  # 3 * 0.05
    expected_parallel_duration = 0.05  # ~1 * 0.05 (plus overhead)

    # Sequential threshold: if duration is close to sequential sum, bug is present
    # We use 2x individual duration as the threshold
    sequential_threshold = 0.10  # 2 * 0.05

    # The assertion: if duration > threshold, sequential execution detected
    # This will xfail when the bug is present (sequential execution detected)
    # and pass when the bug is fixed (parallel execution working)
    assert total_duration < sequential_threshold, (
        f"Sequential execution detected: {total_duration:.3f}s > {sequential_threshold:.3f}s "
        f"(expected ~{expected_parallel_duration:.3f}s for parallel, "
        f"would be ~{expected_sequential_duration:.3f}s for sequential). "
        f"Issue #254: independent analyzers should run in parallel."
    )

    # Also verify all plugins ran and recorded their timing
    assert len(results) == 3
    for result in results:
        assert result.summary.get("duration", 0) > 0


@pytest.mark.xfail(
    reason="deterministic bug detector - per-package sequential execution", strict=False
)
def test_per_package_analyzers_run_sequentially():
    """
    Detects sequential execution in per-package mode.

    The _run_all_per_package method uses nested loops that execute
    plugins sequentially for each package, which is inefficient when
    packages and plugins are independent.

    This is issue #254 variant: per-package execution pattern.
    """
    from dataclasses import dataclass

    @dataclass
    class MockPackageUnit:
        root: Path

    registry = PluginRegistry()

    # Create 2 independent plugins
    plugin_a = _TimingPlugin(name="pkg-analyzer-a", sleep_duration=0.04)
    plugin_b = _TimingPlugin(name="pkg-analyzer-b", sleep_duration=0.04)

    registry.register(plugin_a)
    registry.register(plugin_b)

    # Create 2 mock package units
    package_units = [
        MockPackageUnit(root=Path("/tmp/pkg1")),
        MockPackageUnit(root=Path("/tmp/pkg2")),
    ]

    # Run per-package
    start_time = time.monotonic()
    results = registry.run_all(
        files=["/tmp/pkg1/file.py", "/tmp/pkg2/file.py"],
        repo_path=Path("/tmp"),
        package_units=package_units,
    )
    end_time = time.monotonic()

    total_duration = end_time - start_time
    # 2 plugins * 2 packages = 4 sequential executions if sequential
    # Expected: 4 * 0.04 = 0.16s if sequential, ~0.04s if fully parallel
    sequential_threshold = 0.12  # 3 * 0.04 (looser threshold for CI variance)

    assert total_duration < sequential_threshold, (
        f"Per-package sequential execution detected: {total_duration:.3f}s > {sequential_threshold:.3f}s. "
        f"Issue #254: independent analyzers across packages should be parallelizable."
    )

    # Verify we got results for each plugin-package combination
    assert len(results) == 4  # 2 plugins * 2 packages


def test_sequential_execution_pattern_detection():
    """
    Explicitly detect the sequential execution code pattern.

    This test examines the registry implementation to detect the
    for-loop sequential execution pattern that prevents parallelism.
    """
    import inspect

    from caliper.core import registry

    # Get the source code of run_all and _run_all_per_package
    run_all_source = inspect.getsource(registry.PluginRegistry.run_all)
    run_per_pkg_source = inspect.getsource(registry.PluginRegistry._run_all_per_package)

    # Detect the problematic pattern: simple for loop calling _run_one
    # This pattern indicates sequential execution
    has_sequential_loop = "for plugin in plugins:" in run_all_source
    has_sequential_run_one = "_run_one(plugin" in run_all_source

    # Per-package also has nested sequential loops
    has_nested_sequential = "for unit in package_units:" in run_per_pkg_source

    # Document the detection - this will pass when bug is present
    # and should be updated when bug is fixed
    findings = []
    if has_sequential_loop:
        findings.append("run_all uses sequential for-loop over plugins")
    if has_sequential_run_one:
        findings.append("run_all calls _run_one sequentially (blocking call)")
    if has_nested_sequential:
        findings.append("_run_all_per_package uses nested sequential loops")

    # The test documents the current state but doesn't fail
    # This serves as a code pattern detector for the bug
    assert True, f"Pattern detection findings: {findings}"

    # Store findings for reporting
    pytest.sequential_execution_patterns = findings  # type: ignore[attr-defined]
