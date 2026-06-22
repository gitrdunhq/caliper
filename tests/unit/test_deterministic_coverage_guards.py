# tested-by: tests/unit/test_deterministic_coverage_guards.py
"""Deterministic coverage, timeout, concurrency, and property-boundary guards.

These tests encode known bug classes as RED rules. They intentionally inspect
the local suite and use fake executors/barriers so failures are deterministic
instead of relying on long wall-clock sleeps.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

import ast
import threading
from pathlib import Path
from typing import Any

from caliper.core.models import ScanResult, ScanResultStatus
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.registry import PluginRegistry

_ROOT = Path(__file__).resolve().parents[2]
_TESTS = _ROOT / "tests"

_OPTIONAL_EXTRA_SURFACES = (
    "src/caliper/agent/main.py",
    "src/caliper/agent/tools.py",
    "src/caliper/webhook/config.py",
    "src/caliper/webhook/server.py",
    "src/caliper/data/parquet_writer.py",
)

_PROPERTY_BOUNDARIES = {
    "unified diff parsing": (
        "DependencyDiffDetector",
        "diff --git",
    ),
    "path normalization/traversal": (
        "should_ignore",
        "is_relative_to",
        "_is_under",
        "../",
        "..",
    ),
    "manifest discovery/parsing": (
        "discover_packages",
        "PackageUnit",
        "MANIFEST_MAP",
    ),
}


def _rel(path: Path) -> str:
    return path.relative_to(_ROOT).as_posix()


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _is_pytest_importorskip_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node.func) == "pytest.importorskip"


def _is_module_level_importorskip(path: Path) -> bool:
    for node in _parse(path).body:
        value: ast.AST | None = None
        if isinstance(node, ast.Expr | ast.Assign):
            value = node.value
        if value is not None and _is_pytest_importorskip_call(value):
            return True
    return False


def _tested_by_refs(path: Path) -> list[Path]:
    refs: list[Path] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        marker = "# tested-by:"
        if marker not in line:
            continue
        raw_ref = line.split(marker, maxsplit=1)[1].strip().split()[0].rstrip(",")
        if raw_ref.startswith("tests/"):
            refs.append(_ROOT / raw_ref)
    return refs


def _has_hypothesis_given(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        _call_name(decorator) in {"given", "hypothesis.given"} for decorator in node.decorator_list
    )


def _hypothesis_function_sources() -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    for path in sorted(_TESTS.rglob("test_*.py")):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _has_hypothesis_given(node):
                continue
            source = ast.get_source_segment(text, node) or ""
            sources.append((f"{_rel(path)}:{node.lineno}:{node.name}", source))
    return sources


def test_combined_scanner_timeout_does_not_wait_for_unfinished_futures(monkeypatch) -> None:
    """#207: combined timeout must bound wall-clock runtime, not just result collection."""
    import caliper.core.orchestrator as orchestrator_mod
    from caliper.core.orchestrator import ScanOrchestrator

    class _FakeFuture:
        def __init__(self, name: str, result: ScanResult | None = None) -> None:
            self.name = name
            self._result = result
            self.cancelled = False

        @property
        def done(self) -> bool:
            return self._result is not None

        def result(self) -> ScanResult:
            assert self._result is not None
            return self._result

        def cancel(self) -> bool:
            self.cancelled = True
            return True

    class _FakeExecutor:
        def __init__(self, max_workers: int) -> None:
            self.max_workers = max_workers
            self.futures: list[_FakeFuture] = []
            self.non_waiting_shutdown = False

        def __enter__(self) -> _FakeExecutor:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            pending = [
                future.name for future in self.futures if not future.done and not future.cancelled
            ]
            assert not pending or self.non_waiting_shutdown, (
                "ScanOrchestrator must not leave ThreadPoolExecutor through the default "
                f"waiting shutdown with unfinished scanner futures: {pending}"
            )

        def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
            self.non_waiting_shutdown = wait is False
            if cancel_futures:
                for future in self.futures:
                    if not future.done:
                        future.cancel()

        def submit(self, fn: Any, target_path: Path) -> _FakeFuture:
            scanner_name = fn.__self__.name
            if scanner_name == "fast":
                result = ScanResult(
                    tool_name="fast",
                    status=ScanResultStatus.success,
                    findings=[],
                    duration_seconds=0.0,
                )
                future = _FakeFuture(scanner_name, result)
            else:
                future = _FakeFuture(scanner_name)
            self.futures.append(future)
            return future

    class _Scanner:
        def __init__(self, name: str) -> None:
            self.name = name

        def scan(self, target_path: Path) -> ScanResult:
            raise AssertionError("fake executor should not invoke real scanner work")

    def _fake_as_completed(futures: object, timeout: float):
        for future in list(futures):
            if future.done:
                yield future
        raise orchestrator_mod.TimeoutError()

    monotonic_values = iter([0.0, 0.0, 1.0, 1.0])

    monkeypatch.setattr(orchestrator_mod, "ThreadPoolExecutor", _FakeExecutor)
    monkeypatch.setattr(orchestrator_mod, "as_completed", _fake_as_completed)
    monkeypatch.setattr(orchestrator_mod.time, "monotonic", lambda: next(monotonic_values, 1.0))

    results = ScanOrchestrator(
        scanners=[_Scanner("fast"), _Scanner("blocked")],
        combined_timeout=1,
    ).run(Path("/repo"))

    assert [result.status for result in results] == [
        ScanResultStatus.success,
        ScanResultStatus.skipped,
    ]


class _BarrierPlugin(ScannerPlugin):
    def __init__(self, name: str, barrier: threading.Barrier) -> None:
        self._name = name
        self._barrier = barrier

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Barrier-synchronized independent analyzer"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        self._barrier.wait(timeout=0.25)
        return PluginResult(plugin_name=self.name, summary={"barrier": "passed"})


def test_independent_plugin_analyzers_are_started_concurrently() -> None:
    """#220: independent analyzers must not be serialized by PluginRegistry.run_all()."""
    barrier = threading.Barrier(2)
    registry = PluginRegistry()
    registry.register(_BarrierPlugin("independent-a", barrier))
    registry.register(_BarrierPlugin("independent-b", barrier))

    results = registry.run_all(["service.py"], Path("."))
    failed_barriers = {
        result.plugin_name: result.error or result.summary
        for result in results
        if result.summary.get("barrier") != "passed"
    }

    assert failed_barriers == {}, (
        "Independent plugins should reach the barrier together. "
        f"Sequential execution produced incomplete barrier results: {failed_barriers}"
    )
    assert {result.plugin_name for result in results} == {"independent-a", "independent-b"}


def test_optional_extra_surfaces_have_default_non_skipping_test_targets() -> None:
    """#212: copilot, webhook, and parquet surfaces need default-suite coverage."""
    violations: list[str] = []

    for relative_source in _OPTIONAL_EXTRA_SURFACES:
        source_path = _ROOT / relative_source
        refs = _tested_by_refs(source_path)
        if not refs:
            violations.append(f"{relative_source}: no # tested-by target")
            continue

        non_skipping_refs = [
            ref for ref in refs if ref.exists() and not _is_module_level_importorskip(ref)
        ]
        if not non_skipping_refs:
            ref_text = ", ".join(_rel(ref) for ref in refs)
            violations.append(
                f"{relative_source}: tested-by targets all module-skip optional extras: {ref_text}"
            )

    assert violations == [], (
        "Optional copilot/webhook/parquet modules must have at least one default "
        "unit-test target that does not module-skip via pytest.importorskip:\n"
        + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_259_property_based_coverage_detects_diff_path_manifest_gaps() -> None:
    """#259: deterministic detector for property-based coverage gaps in diff, path, and manifest parsing.

    Parent bug: #225 — Property-based coverage misses diff, path, and manifest parsing boundaries.
    This test intentionally fails when property-based tests (@given) do not cover:
    - Unified diff parsing boundaries (diff --git, DependencyDiffDetector)
    - Path normalization/traversal boundaries (../, is_relative_to, _is_under)
    - Manifest discovery/parsing boundaries (discover_packages, MANIFEST_MAP, PackageUnit)
    """
    hypothesis_sources = _hypothesis_function_sources()
    missing: list[str] = []

    for boundary_name, tokens in _PROPERTY_BOUNDARIES.items():
        if not any(
            any(token in source for token in tokens) for _label, source in hypothesis_sources
        ):
            missing.append(boundary_name)

    assert missing == [], (
        "Hypothesis coverage must include property tests for these boundary classes: "
        f"{missing}.\nCurrent @given tests:\n"
        + "\n".join(label for label, _source in hypothesis_sources)
    )
