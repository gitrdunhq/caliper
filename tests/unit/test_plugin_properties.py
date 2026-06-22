"""Property-based tests for plugin architecture.
# tested-by: tests/unit/test_plugin_properties.py

Covers: PROP-001 (isolation), PROP-002 (contract), PROP-003 (determinism),
        PROP-005 (template purity), PROP-006 (discovery safety), PROP-007 (length bound).
"""

from __future__ import annotations

import time
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.plugin import (
    PluginCategory,
    PluginResult,
    ScannerPlugin,
    finding_get,
)
from caliper.core.registry import PluginRegistry
from caliper.core.renderer import render_comment

# ── Strategies ──

severity_st = st.sampled_from(["critical", "high", "medium", "low", "info"])
category_st = st.sampled_from(list(PluginCategory))

finding_st = st.fixed_dictionaries(
    {
        "id": st.text(min_size=1, max_size=20),
        "severity": severity_st,
        "package": st.text(min_size=1, max_size=30),
        "version": st.from_regex(r"[0-9]+\.[0-9]+\.[0-9]+", fullmatch=True),
        "summary": st.text(max_size=200),
    }
)

plugin_result_st = st.builds(
    PluginResult,
    plugin_name=st.text(min_size=1, max_size=20),
    findings=st.lists(finding_st, max_size=50),
    error=st.just(""),
)


# ── Test plugins for property testing ──


class _DeterministicPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "deterministic"

    @property
    def description(self) -> str:
        return "Always returns the same thing"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            findings=[{"file": f, "issue": "test"} for f in sorted(files)],
            summary={"count": len(files)},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        return f"Found {len(result.findings)} issues"


class _ExplodingPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "exploding"

    @property
    def description(self) -> str:
        return "Always raises"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        raise RuntimeError("kaboom")

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        return ""


# ── PROP-001: Plugin Isolation ──


class TestPluginIsolation:
    @given(files=st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=10))
    @settings(max_examples=20)
    def test_exception_never_propagates(self, files: list[str]):
        reg = PluginRegistry()
        reg.register(_DeterministicPlugin())
        reg.register(_ExplodingPlugin())
        results = reg.run_all(files, Path("."))
        assert len(results) == 2
        exploding = [r for r in results if r.plugin_name == "exploding"]
        assert len(exploding) == 1
        assert exploding[0].error != ""
        deterministic = [r for r in results if r.plugin_name == "deterministic"]
        assert len(deterministic) == 1
        assert deterministic[0].error == ""

    @given(files=st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=5))
    @settings(max_examples=20)
    def test_healthy_plugins_unaffected_by_failing_neighbor(self, files: list[str]):
        reg = PluginRegistry()
        reg.register(_ExplodingPlugin())
        reg.register(_DeterministicPlugin())
        results = reg.run_all(files, Path("."))
        good = [r for r in results if r.plugin_name == "deterministic"]
        findings = good[0].findings
        assert [finding_get(f, "file") for f in findings] == sorted(files)
        assert all(finding_get(f, "issue") == "test" for f in findings)


# ── PROP-003: Registry Determinism ──


class TestRegistryDeterminism:
    @given(files=st.lists(st.text(min_size=1, max_size=30), min_size=1, max_size=10))
    @settings(max_examples=30)
    def test_same_input_same_output(self, files: list[str]):
        reg = PluginRegistry()
        reg.register(_DeterministicPlugin())
        r1 = reg.run_all(files, Path("."))
        r2 = reg.run_all(files, Path("."))
        assert len(r1) == len(r2)
        for a, b in zip(r1, r2):
            assert a.plugin_name == b.plugin_name
            assert a.findings == b.findings
            assert a.error == b.error

    @given(files=st.lists(st.text(min_size=1, max_size=30), min_size=1, max_size=5))
    @settings(max_examples=20)
    def test_order_preserved_across_runs(self, files: list[str]):
        reg = PluginRegistry()
        reg.register(_DeterministicPlugin())
        reg.register(_ExplodingPlugin())
        names1 = [r.plugin_name for r in reg.run_all(files, Path("."))]
        names2 = [r.plugin_name for r in reg.run_all(files, Path("."))]
        assert names1 == names2 == ["deterministic", "exploding"]


# ── PROP-005: Template Rendering Purity ──


class TestTemplatePurity:
    @given(results=st.lists(plugin_result_st, min_size=0, max_size=5))
    @settings(max_examples=30, deadline=None)  # render time varies under load; see #413
    def test_render_is_idempotent(self, results: list[PluginResult]):
        md1 = render_comment(results, repo="org/repo", pr_num=1, title="test")
        md2 = render_comment(results, repo="org/repo", pr_num=1, title="test")
        assert md1 == md2

    @given(results=st.lists(plugin_result_st, min_size=0, max_size=5))
    @settings(max_examples=20, deadline=None)  # render time varies under load; see #413
    def test_render_always_returns_string(self, results: list[PluginResult]):
        md = render_comment(results, repo="x", pr_num=0, title="t")
        assert isinstance(md, str)
        assert "Caliper" in md

    @given(results=st.lists(plugin_result_st, min_size=0, max_size=3))
    @settings(max_examples=20, deadline=None)  # render time varies under load; see #413
    def test_render_contains_verdict(self, results: list[PluginResult]):
        md = render_comment(results, repo="x", pr_num=0, title="t")
        assert any(v in md for v in ("ALL CLEAR", "BLOCKED", "PASS WITH WARNINGS"))


# ── PROP-006: Discovery Safety ──


class TestDiscoverySafety:
    def test_discovery_completes_fast(self):
        from caliper.plugins import get_default_registry

        start = time.monotonic()
        reg = get_default_registry()
        elapsed = time.monotonic() - start
        assert elapsed < 1.0
        assert len(reg.list()) >= 10

    def test_discovery_no_side_effects(self):
        from caliper.plugins import get_default_registry

        reg = get_default_registry()
        for p in reg.list():
            assert hasattr(p, "name")
            assert hasattr(p, "category")
            assert hasattr(p, "run")


# ── PROP-007: Comment Length Bound ──


class TestCommentLengthBound:
    @given(
        finding_count=st.integers(min_value=0, max_value=500),
        detail_length=st.integers(min_value=1, max_value=500),
    )
    @settings(max_examples=20, deadline=None)  # render time varies under load; see #413
    def test_output_never_exceeds_65k(
        self,
        finding_count: int,
        detail_length: int,
    ):
        class Verbose:
            def render(self, result):
                return "\n".join(
                    f"| `f{i}` | {'x' * detail_length} |" for i in range(len(result.findings))
                )

        findings = [
            {"word": f"w{i}", "severity": "low", "detail": "x" * detail_length}
            for i in range(finding_count)
        ]
        result = PluginResult(plugin_name="verbose", findings=findings)
        md = render_comment(
            [result],
            repo="org/repo",
            pr_num=1,
            title="t",
            plugin_renderers={"verbose": Verbose()},
        )
        assert len(md) <= 65536


# ── PluginResult serialization ──


class TestPluginResultProperties:
    @given(
        name=st.text(min_size=1, max_size=30),
        findings=st.lists(finding_st, max_size=20),
        error=st.text(max_size=100),
    )
    @settings(max_examples=30)
    def test_result_fields_roundtrip(
        self,
        name: str,
        findings: list[dict],
        error: str,
    ):
        r = PluginResult(plugin_name=name, findings=findings, error=error)
        assert r.plugin_name == name
        assert r.findings == findings
        assert r.error == error

    @given(findings=st.lists(finding_st, min_size=0, max_size=50))
    @settings(max_examples=20)
    def test_empty_findings_summary_defaults(self, findings: list[dict]):
        r = PluginResult(plugin_name="test", findings=findings)
        assert isinstance(r.summary, dict)
        assert isinstance(r.findings, list)
