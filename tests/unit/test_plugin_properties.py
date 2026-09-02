"""Property-based tests for plugin architecture.
# tested-by: tests/unit/test_plugin_properties.py

Covers: PROP-001 (isolation), PROP-002 (contract), PROP-003 (determinism),
        PROP-005 (template purity), PROP-006 (discovery safety), PROP-007 (length bound),
        R1 AC6 section ordering (epic-next-10: severities descend within a plugin section).
"""

from __future__ import annotations

import re
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
from caliper.core.plugin_registry import PluginRegistry
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


# ── R1 AC6: severity ordering within every plugin section (epic-next-10) ──
#
# Domain: Ordering — SAFETY — an out-of-sequence finding never renders.
# Arbitrary PluginResult lists with random severities/files/lines/rule ids and a
# UNIQUE (file, line, rule_id) per plugin (so dedup can never reorder them) must
# render, via the public render_comment, with severities critical → info inside
# each "### <plugin>" section. Severity is parsed off the rendered icon.

_ORDERED_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {sev: i for i, sev in enumerate(_ORDERED_SEVERITIES)}
_ICON_TO_SEVERITY = {"🔴": "critical", "🟠": "high", "🟡": "medium", "🔵": "low", "⚪": "info"}
_SECTION_HEADER_RE = re.compile(r"^### (?P<plugin>.+)$")
_FINDING_LINE_RE = re.compile(r"^- (?P<icon>[🔴🟠🟡🔵⚪]) ")

# Plugin names avoid "semgrep" (its low/info findings move to the notes block
# under the severity floor) and "complexity" (special-cased MI extraction).
_ordering_plugin_name_st = st.sampled_from(
    ["alpha", "beta", "gamma", "delta", "detectors", "osv-scanner"]
)
_finding_key_st = st.tuples(
    st.sampled_from(["a.py", "b.py", "c/d.py", "src/e.py", "z.go"]),
    st.integers(min_value=1, max_value=200),
    st.sampled_from(["R-1", "R-2", "CAL-001", "CAL-002", "GHSA-1"]),
)


@st.composite
def _ordering_plugin_result_st(draw: st.DrawFn) -> PluginResult:
    keys = draw(st.lists(_finding_key_st, min_size=1, max_size=40, unique=True))
    findings = [
        {
            "rule_id": rule_id,
            "severity": draw(severity_st),
            "file": file,
            "line": line,
            "message": "m",
        }
        for file, line, rule_id in keys
    ]
    return PluginResult(
        plugin_name=draw(_ordering_plugin_name_st),
        category=draw(st.sampled_from(["", "code", "dependency"])),
        findings=findings,
    )


@st.composite
def _ordering_results_st(draw: st.DrawFn) -> list[PluginResult]:
    """One section per plugin name: keep the first of any duplicate name."""
    seen: set[str] = set()
    unique: list[PluginResult] = []
    for r in draw(st.lists(_ordering_plugin_result_st(), min_size=1, max_size=4)):
        if r.plugin_name not in seen:
            seen.add(r.plugin_name)
            unique.append(r)
    return unique


def parse_section_severities(markdown: str) -> dict[str, list[str]]:
    """Map each ``### <plugin>`` section to the severities of its finding lines, in order."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in markdown.splitlines():
        header = _SECTION_HEADER_RE.match(line)
        if header:
            current = header.group("plugin")
            sections[current] = []
            continue
        if line.startswith("<details>") or line.startswith("---"):
            current = None
            continue
        if current is None:
            continue
        found = _FINDING_LINE_RE.match(line)
        if found:
            sections[current].append(_ICON_TO_SEVERITY[found.group("icon")])
    return sections


class TestSectionSeverityOrdering:
    @settings(deadline=None, max_examples=150)
    @given(results=_ordering_results_st())
    def test_severities_descend_within_every_plugin_section(self, results: list[PluginResult]):
        markdown = render_comment(results, repo="org/repo", pr_num=1, title="property")
        sections = parse_section_severities(markdown)

        for r in results:
            assert r.plugin_name in sections, f"plugin {r.plugin_name} rendered no section"
            rendered = sections[r.plugin_name]
            assert len(rendered) == len(r.findings), (
                f"{r.plugin_name}: rendered {len(rendered)} finding lines for "
                f"{len(r.findings)} findings"
            )
            ranks = [_SEVERITY_RANK[s] for s in rendered]
            assert ranks == sorted(ranks), f"{r.plugin_name}: severities out of order: {rendered}"

    @settings(deadline=None, max_examples=150)
    @given(results=_ordering_results_st())
    def test_rendered_severity_multiset_matches_input(self, results: list[PluginResult]):
        markdown = render_comment(results, repo="org/repo", pr_num=1, title="property")
        sections = parse_section_severities(markdown)
        for r in results:
            expected = sorted(f["severity"] for f in r.findings)
            assert sorted(sections[r.plugin_name]) == expected
