"""Tests for Jinja2 template-based plugin rendering.
# tested-by: tests/unit/test_plugin_templates.py

TDD: these tests were written BEFORE the templates and base render() changes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.plugin import PluginResult, ScannerPlugin
from caliper.plugins.blast_radius import BlastRadiusPlugin
from caliper.plugins.complexity import ComplexityPlugin
from caliper.plugins.kube_linter import KubeLinterPlugin
from caliper.plugins.semgrep import SemgrepPlugin
from caliper.plugins.supply_chain import SupplyChainPlugin

_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "src" / "caliper" / "templates"


# ── Helpers ──────────────────────────────────────────────────────────────────


def _semgrep_result_with_findings() -> PluginResult:
    return PluginResult(
        plugin_name="semgrep",
        findings=[
            {
                "rule_id": "python.security.injections.sql",
                "file": "app/db.py",
                "start_line": 42,
                "end_line": 43,
                "severity": "ERROR",
                "message": "SQL injection risk detected in query construction",
            },
            {
                "rule_id": "python.security.warnings.weak_hash",
                "file": "app/auth.py",
                "start_line": 15,
                "end_line": 15,
                "severity": "WARNING",
                "message": "MD5 is cryptographically weak",
            },
        ],
        summary={"total": 2},
    )


def _blast_radius_result_with_findings() -> PluginResult:
    return PluginResult(
        plugin_name="blast-radius",
        findings=[
            {
                "check": "high_fan_in",
                "severity": "high",
                "name": "process_order",
                "file": "core/orders.py",
                "dependents": 12,
                "description": "High fan-in symbol",
            },
            {
                "check": "god_module",
                "severity": "medium",
                "file": "utils.py",
                "description": "Module has too many responsibilities",
            },
        ],
        summary={
            "symbols_indexed": 240,
            "edges": 580,
            "files_indexed": 30,
            "checks_run": 8,
            "findings": 2,
        },
    )


def _blast_radius_result_empty_indexed() -> PluginResult:
    return PluginResult(
        plugin_name="blast-radius",
        findings=[],
        summary={
            "symbols_indexed": 50,
            "edges": 100,
            "files_indexed": 5,
            "checks_run": 8,
            "findings": 0,
        },
    )


def _complexity_result_with_findings() -> PluginResult:
    return PluginResult(
        plugin_name="complexity",
        findings=[
            {
                "function": "parse_manifest",
                "file": "core/manifest.py",
                "cyclomatic_complexity": 15,
                "maintainability_index": 45,
                "nloc": 80,
            },
            {
                "function": "resolve_deps",
                "file": "core/resolver.py",
                "cyclomatic_complexity": 6,
                "maintainability_index": 72,
                "nloc": 30,
            },
        ],
        summary={
            "avg_cyclomatic_complexity": 10.5,
            "max_cyclomatic_complexity": 15,
            "total_nloc": 110,
        },
    )


def _kube_linter_result_with_findings() -> PluginResult:
    return PluginResult(
        plugin_name="kube-linter",
        findings=[
            {
                "check": "no-read-only-root-fs",
                "object_kind": "Deployment",
                "object_name": "api-server",
                "message": "Container does not have a read-only root filesystem",
                "remediation": "Set securityContext.readOnlyRootFilesystem to true",
            },
        ],
        summary={"total": 1},
    )


def _supply_chain_result_with_findings() -> PluginResult:
    return PluginResult(
        plugin_name="supply-chain",
        findings=[
            {
                "type": "unpinned",
                "file": "package.json",
                "package": "lodash",
                "version": "^4.0.0",
                "ecosystem": "npm",
                "reason": "caret range — allows minor+patch",
            },
            {
                "type": "lockfile",
                "lockfile": "package-lock.json",
                "severity": "high",
                "sha256": "abc123def456" + "0" * 52,
                "message": "`package-lock.json` changed but package.json did NOT",
            },
            {
                "type": "docker_latest",
                "file": "/repo/Dockerfile",
                "severity": "medium",
                "description": "Dockerfile FROM uses floating image `node` — pin to a specific digest or version tag",
            },
        ],
        summary={"unpinned": 1, "lockfile_issues": 1, "docker_latest": 1},
    )


# ── Template file existence tests ────────────────────────────────────────────


class TestTemplateFilesExist:
    """Verify all 5 required template files are present."""

    @pytest.mark.parametrize(
        "plugin_name",
        ["semgrep", "blast-radius", "complexity", "kube-linter", "supply-chain"],
    )
    def test_template_file_exists(self, plugin_name: str):
        tpath = _TEMPLATES_DIR / f"{plugin_name}.md.j2"
        assert tpath.exists(), f"Missing template: {tpath}"

    def test_templates_dir_has_init(self):
        assert (_TEMPLATES_DIR / "__init__.py").exists()


# ── Base render() template-loading contract ──────────────────────────────────


class TestBaseRenderLoadsTemplate:
    """Base ScannerPlugin.render() must load template when file is available."""

    def test_base_render_uses_template_when_present(self, tmp_path: Path):
        """render() dispatches to Jinja2 when a template file exists."""
        tdir = tmp_path / "templates"
        tdir.mkdir()
        (tdir / "test-tpl.md.j2").write_text(
            "TEMPLATE: {{ findings | length }} findings, error={{ error }}"
        )

        class _TplPlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return "test-tpl"

            @property
            def description(self) -> str:
                return "x"

            @property
            def category(self):
                from caliper.core.plugin import PluginCategory

                return PluginCategory.code

            def can_run(self, files, repo_path):
                return True

            def run(self, files, repo_path):
                return PluginResult(plugin_name=self.name)

            def _render_inline(self, result: PluginResult) -> str:
                return "INLINE"

        plugin = _TplPlugin()
        result = PluginResult(
            plugin_name="test-tpl",
            findings=[{"x": 1}, {"x": 2}],
            error="",
        )
        out = plugin.render(result, template_dir=tdir)
        assert "TEMPLATE:" in out
        assert "2 findings" in out
        assert "INLINE" not in out

    def test_base_render_falls_back_to_inline_when_no_template(self, tmp_path: Path):
        """render() falls back to _render_inline() when no template file exists."""

        class _InlinePlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return "no-template"

            @property
            def description(self) -> str:
                return "x"

            @property
            def category(self):
                from caliper.core.plugin import PluginCategory

                return PluginCategory.code

            def can_run(self, files, repo_path):
                return True

            def run(self, files, repo_path):
                return PluginResult(plugin_name=self.name)

            def _render_inline(self, result: PluginResult) -> str:
                return f"INLINE:{len(result.findings)}"

        plugin = _InlinePlugin()
        result = PluginResult(plugin_name="no-template", findings=[{"x": 1}])
        out = plugin.render(result, template_dir=tmp_path)
        assert out == "INLINE:1"

    def test_existing_render_override_still_works(self):
        """Plugins that override render() are not broken by the base class change."""

        class _LegacyPlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return "legacy"

            @property
            def description(self) -> str:
                return "x"

            @property
            def category(self):
                from caliper.core.plugin import PluginCategory

                return PluginCategory.code

            def can_run(self, files, repo_path):
                return True

            def run(self, files, repo_path):
                return PluginResult(plugin_name=self.name)

            def render(self, result: PluginResult, template_dir=None) -> str:
                return "LEGACY_INLINE"

        plugin = _LegacyPlugin()
        result = PluginResult(plugin_name="legacy")
        assert plugin.render(result) == "LEGACY_INLINE"


# ── Semgrep template tests ────────────────────────────────────────────────────


class TestSemgrepTemplate:
    def test_renders_findings(self):
        plugin = SemgrepPlugin()
        out = plugin.render(_semgrep_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "Semgrep" in out
        assert "2" in out  # finding count
        assert "app/db.py" in out
        assert "sql" in out.lower()  # rule name fragment
        assert "SQL injection" in out

    def test_renders_warning_finding(self):
        plugin = SemgrepPlugin()
        out = plugin.render(_semgrep_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "app/auth.py" in out
        assert "weak_hash" in out or "MD5" in out

    def test_empty_findings_returns_empty_or_no_issues(self):
        plugin = SemgrepPlugin()
        result = PluginResult(plugin_name="semgrep", findings=[], summary={"total": 0})
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        # Either empty string or "No issues found" — no finding rows
        assert "app/db.py" not in out

    def test_error_renders_error_message(self):
        plugin = SemgrepPlugin()
        result = PluginResult(plugin_name="semgrep", error="semgrep binary not found")
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "semgrep" in out.lower()
        assert "not found" in out

    def test_has_details_block(self):
        plugin = SemgrepPlugin()
        out = plugin.render(_semgrep_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "<details" in out
        assert "<summary>" in out

    def test_severity_icons_present(self):
        plugin = SemgrepPlugin()
        out = plugin.render(_semgrep_result_with_findings(), template_dir=_TEMPLATES_DIR)
        # ERROR → 🔴, WARNING → 🟡
        assert "🔴" in out
        assert "🟡" in out


# ── Blast-Radius template tests ───────────────────────────────────────────────


class TestBlastRadiusTemplate:
    def test_renders_findings_grouped_by_severity(self):
        plugin = BlastRadiusPlugin()
        out = plugin.render(_blast_radius_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "Blast Radius" in out or "blast" in out.lower()
        assert "process_order" in out
        assert "utils.py" in out

    def test_renders_symbol_stats_footer(self):
        plugin = BlastRadiusPlugin()
        out = plugin.render(_blast_radius_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "240" in out  # symbols_indexed
        assert "580" in out  # edges

    def test_no_findings_but_indexed_shows_count(self):
        plugin = BlastRadiusPlugin()
        result = _blast_radius_result_empty_indexed()
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "50" in out or "no issues" in out.lower()

    def test_no_findings_no_symbols_returns_empty_or_no_issues(self):
        plugin = BlastRadiusPlugin()
        result = PluginResult(
            plugin_name="blast-radius",
            findings=[],
            summary={
                "symbols_indexed": 0,
                "edges": 0,
                "files_indexed": 0,
                "checks_run": 0,
                "findings": 0,
            },
        )
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        # should be empty or "no issues" — not show findings table
        assert "process_order" not in out

    def test_error_renders_error_message(self):
        plugin = BlastRadiusPlugin()
        result = PluginResult(plugin_name="blast-radius", error="graph build failed")
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "blast-radius" in out.lower() or "blast" in out.lower()
        assert "graph build failed" in out

    def test_high_severity_section_present(self):
        plugin = BlastRadiusPlugin()
        out = plugin.render(_blast_radius_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "HIGH" in out.upper() or "🟠" in out

    def test_details_block_present(self):
        plugin = BlastRadiusPlugin()
        out = plugin.render(_blast_radius_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "<details" in out


# ── Complexity template tests ─────────────────────────────────────────────────


class TestComplexityTemplate:
    def test_renders_high_ccn_table(self):
        plugin = ComplexityPlugin()
        out = plugin.render(_complexity_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "parse_manifest" in out
        assert "15" in out  # CCN value

    def test_renders_summary_stats(self):
        plugin = ComplexityPlugin()
        out = plugin.render(_complexity_result_with_findings(), template_dir=_TEMPLATES_DIR)
        # avg/max/nloc present in summary header
        assert "10.5" in out or "10" in out
        assert "110" in out  # nloc

    def test_empty_findings_returns_empty(self):
        plugin = ComplexityPlugin()
        result = PluginResult(plugin_name="complexity", findings=[], summary={})
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "parse_manifest" not in out

    def test_error_renders_error_message(self):
        plugin = ComplexityPlugin()
        result = PluginResult(plugin_name="complexity", error="lizard not found")
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "complexity" in out.lower()
        assert "lizard not found" in out

    def test_high_ccn_warning_section(self):
        plugin = ComplexityPlugin()
        out = plugin.render(_complexity_result_with_findings(), template_dir=_TEMPLATES_DIR)
        # parse_manifest has CCN=15 > 10, resolve_deps has CCN=6
        assert "parse_manifest" in out
        # High CCN section header
        assert "High complexity" in out or "CCN > 10" in out or "⚠️" in out

    def test_details_block_present(self):
        plugin = ComplexityPlugin()
        out = plugin.render(_complexity_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "<details" in out


# ── KubeLinter template tests ─────────────────────────────────────────────────


class TestKubeLinterTemplate:
    def test_renders_findings(self):
        plugin = KubeLinterPlugin()
        out = plugin.render(_kube_linter_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "K8s" in out or "Helm" in out or "kube" in out.lower()
        assert "no-read-only-root-fs" in out

    def test_renders_object_kind_and_name(self):
        plugin = KubeLinterPlugin()
        out = plugin.render(_kube_linter_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "Deployment" in out
        assert "api-server" in out

    def test_renders_message(self):
        plugin = KubeLinterPlugin()
        out = plugin.render(_kube_linter_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "read-only root filesystem" in out

    def test_renders_remediation(self):
        plugin = KubeLinterPlugin()
        out = plugin.render(_kube_linter_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "securityContext" in out or "true" in out

    def test_empty_findings_returns_empty(self):
        plugin = KubeLinterPlugin()
        result = PluginResult(plugin_name="kube-linter", findings=[], summary={"total": 0})
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "no-read-only-root-fs" not in out

    def test_error_renders_error_message(self):
        plugin = KubeLinterPlugin()
        result = PluginResult(plugin_name="kube-linter", error="kube-linter not installed")
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "kube-linter" in out.lower()
        assert "not installed" in out

    def test_details_block_present(self):
        plugin = KubeLinterPlugin()
        out = plugin.render(_kube_linter_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "<details" in out


# ── SupplyChain template tests ────────────────────────────────────────────────


class TestSupplyChainTemplate:
    def test_renders_unpinned_section(self):
        plugin = SupplyChainPlugin()
        out = plugin.render(_supply_chain_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "Unpinned" in out or "unpinned" in out.lower()
        assert "lodash" in out
        assert "^4.0.0" in out

    def test_renders_lockfile_section(self):
        plugin = SupplyChainPlugin()
        out = plugin.render(_supply_chain_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "Lockfile" in out or "lockfile" in out.lower()
        assert "package-lock.json" in out

    def test_renders_docker_section(self):
        plugin = SupplyChainPlugin()
        out = plugin.render(_supply_chain_result_with_findings(), template_dir=_TEMPLATES_DIR)
        assert "Docker" in out or "🐳" in out
        assert "Dockerfile" in out or "node" in out

    def test_empty_findings_returns_empty(self):
        plugin = SupplyChainPlugin()
        result = PluginResult(
            plugin_name="supply-chain",
            findings=[],
            summary={"unpinned": 0, "lockfile_issues": 0, "docker_latest": 0},
        )
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "lodash" not in out

    def test_error_renders_error_message(self):
        plugin = SupplyChainPlugin()
        result = PluginResult(plugin_name="supply-chain", error="yaml parse failure")
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "supply-chain" in out.lower() or "supply" in out.lower()
        assert "yaml parse failure" in out

    def test_lockfile_severity_icons(self):
        plugin = SupplyChainPlugin()
        out = plugin.render(_supply_chain_result_with_findings(), template_dir=_TEMPLATES_DIR)
        # high severity → 🔴
        assert "🔴" in out or "high" in out.lower()


# ── Regression: output unchanged from inline render ──────────────────────────


class TestRegressionOutputUnchanged:
    """Spot-check that template output is visually equivalent to the previous inline output."""

    def test_semgrep_structure_preserved(self):
        """Template output has same structural elements as old inline render."""
        plugin = SemgrepPlugin()
        result = _semgrep_result_with_findings()

        # Render via template (new path)
        tpl_out = plugin.render(result, template_dir=_TEMPLATES_DIR)

        # All key structural elements from old inline render must be present
        assert "<details" in tpl_out
        assert "<summary>" in tpl_out
        assert "🔍" in tpl_out
        assert "Semgrep" in tpl_out
        assert "</details>" in tpl_out
        # File references
        assert "app/db.py:42" in tpl_out
        # Rule name (last segment only)
        assert "sql" in tpl_out.lower()
        # Message content
        assert "SQL injection" in tpl_out

    def test_kube_linter_structure_preserved(self):
        plugin = KubeLinterPlugin()
        result = _kube_linter_result_with_findings()
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "<details" in out
        assert "☸️" in out
        assert "K8s" in out or "Helm" in out
        assert "no-read-only-root-fs" in out
        assert "Deployment/api-server" in out
        assert "💡" in out  # remediation icon

    def test_supply_chain_structure_preserved(self):
        plugin = SupplyChainPlugin()
        result = _supply_chain_result_with_findings()
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "📌" in out  # unpinned icon
        assert "🔒" in out  # lockfile icon
        assert "🐳" in out  # docker icon
        assert "lodash" in out
        assert "npm" in out

    def test_complexity_structure_preserved(self):
        plugin = ComplexityPlugin()
        result = _complexity_result_with_findings()
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "<details" in out
        assert "📊" in out
        assert "CCN" in out
        # Table headers
        assert "Function" in out
        assert "MI" in out or "Maintainability" in out

    def test_blast_radius_structure_preserved(self):
        plugin = BlastRadiusPlugin()
        result = _blast_radius_result_with_findings()
        out = plugin.render(result, template_dir=_TEMPLATES_DIR)
        assert "<details" in out
        assert "💥" in out
        assert "Blast Radius" in out
        assert "</details>" in out


# ── Templates package utility tests ──────────────────────────────────────────


class TestTemplatesPackageUtils:
    """Tests for the templates package utility functions.

    Written RED-first: these fail until get_templates_dir() and list_templates()
    are added to src/caliper/templates/__init__.py.
    """

    def test_get_templates_dir_returns_existing_path(self):
        from caliper.templates import get_templates_dir

        d = get_templates_dir()
        assert d.exists(), "templates dir must exist on disk"
        assert d.is_dir(), "templates dir must be a directory"

    def test_get_templates_dir_points_to_correct_location(self):
        from caliper.templates import get_templates_dir

        d = get_templates_dir()
        assert (d / "comment.md.j2").exists(), "comment.md.j2 must be inside templates dir"

    def test_list_templates_returns_list(self):
        from caliper.templates import list_templates

        templates = list_templates()
        assert isinstance(templates, list), "list_templates() must return a list"

    def test_list_templates_finds_jinja2_files(self):
        from caliper.templates import list_templates

        templates = list_templates()
        assert len(templates) > 0, "templates dir must contain at least one .j2 file"
        assert "comment.md.j2" in templates, "comment.md.j2 must be discoverable"

    def test_list_templates_is_sorted(self):
        from caliper.templates import list_templates

        templates = list_templates()
        assert templates == sorted(templates), "list_templates() output must be sorted"
