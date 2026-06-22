"""Tests for comment renderer.
# tested-by: tests/unit/test_renderer.py
"""

from __future__ import annotations

from caliper.core.plugin import PluginResult
from caliper.core.renderer import (  # noqa: PLC2701
    _VERSION,
    CATEGORY_PRIORITY,
    _build_sections,
    calculate_severity_score,
    render_comment,
)


def _vuln_result() -> PluginResult:
    return PluginResult(
        plugin_name="osv-scanner",
        category="dependency",
        findings=[
            {
                "id": "CVE-2023-0286",
                "severity": "high",
                "package": "cryptography",
                "version": "3.3.2",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0286",
                "summary": "Vulnerable OpenSSL",
            },
            {
                "id": "CVE-2024-1234",
                "severity": "medium",
                "package": "requests",
                "version": "2.25.1",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                "summary": "Something medium",
            },
        ],
        summary={"total": 2, "critical_high": 1},
    )


def _complexity_result() -> PluginResult:
    return PluginResult(
        plugin_name="complexity",
        findings=[
            {
                "function": "process_data",
                "file": "app.py",
                "nloc": 20,
                "cyclomatic_complexity": 12,
                "maintainability_index": "A (85.3)",
            },
            {
                "function": "simple",
                "file": "app.py",
                "nloc": 5,
                "cyclomatic_complexity": 1,
                "maintainability_index": "A (100.0)",
            },
        ],
        summary={
            "avg_cyclomatic_complexity": 6.5,
            "high_complexity_count": 1,
            "max_cyclomatic_complexity": 12,
            "total_nloc": 25,
        },
    )


def _empty_result() -> PluginResult:
    return PluginResult(plugin_name="cspell", summary={"status": "skipped"})


def _error_result() -> PluginResult:
    return PluginResult(plugin_name="kube-linter", error="not installed")


class TestRenderComment:
    def test_renders_header(self):
        md = render_comment(
            [],
            repo="org/repo",
            pr_num=42,
            title="feat: add thing",
        )
        assert "Caliper" in md
        assert "org/repo#42" in md
        assert "feat: add thing" in md

    def test_verdict_clear_when_no_findings(self):
        md = render_comment(
            [_empty_result()],
            repo="org/repo",
            pr_num=1,
            title="test",
        )
        assert "ALL CLEAR" in md

    def test_verdict_blocked_on_critical(self):
        md = render_comment(
            [_vuln_result()],
            repo="org/repo",
            pr_num=1,
            title="test",
        )
        assert "BLOCKED" in md

    def test_verdict_warnings_on_non_critical(self):
        result = PluginResult(
            plugin_name="semgrep",
            findings=[{"severity": "WARNING", "message": "x"}],
        )
        md = render_comment(
            [result],
            repo="org/repo",
            pr_num=1,
            title="test",
        )
        assert "PASS WITH WARNINGS" in md

    def test_summary_table_has_plugin_counts(self):
        md = render_comment(
            [_vuln_result(), _empty_result()],
            repo="org/repo",
            pr_num=1,
            title="test",
            file_count=5,
        )
        assert "| osv-scanner | 2 |" in md
        assert "| cspell | skipped |" in md
        assert "| Files scanned | 5 |" in md

    def test_error_plugin_shows_error(self):
        md = render_comment(
            [_error_result()],
            repo="org/repo",
            pr_num=1,
            title="test",
        )
        assert "not installed" in md

    def test_mi_grade_in_header(self):
        md = render_comment(
            [_complexity_result()],
            repo="org/repo",
            pr_num=1,
            title="test",
        )
        assert "Maintainability" in md
        assert "CCN avg" in md

    def test_plugin_render_used_when_provided(self):
        class FakePlugin:
            def render(self, result):
                return "CUSTOM RENDER OUTPUT"

        md = render_comment(
            [_vuln_result()],
            repo="org/repo",
            pr_num=1,
            title="test",
            plugin_renderers={"osv-scanner": FakePlugin()},
        )
        assert "CUSTOM RENDER OUTPUT" in md

    def test_footer_has_version(self):
        md = render_comment(
            [_vuln_result()],
            repo="org/repo",
            pr_num=1,
            title="test",
        )
        assert f"Caliper v{_VERSION}" in md

    def test_truncation_at_65k(self):
        class VerbosePlugin:
            def render(self, result):
                lines = []
                for f in result.findings:
                    lines.append(f"| `{f['word']}` | {f['detail']} |")
                return "\n".join(lines)

        big = PluginResult(
            plugin_name="verbose",
            findings=[
                {"word": f"w{i}", "detail": "x" * 500, "severity": "low"} for i in range(200)
            ],
        )
        md = render_comment(
            [big],
            repo="org/repo",
            pr_num=1,
            title="test",
            plugin_renderers={"verbose": VerbosePlugin()},
        )
        assert len(md) <= 65536
        assert "truncated" in md


class TestPerPackageRendering:
    """Monorepo: results with package_root set are grouped by package."""

    def _pkg_result(
        self,
        plugin_name: str,
        package_root: str,
        severity: str = "high",
    ) -> PluginResult:
        return PluginResult(
            plugin_name=plugin_name,
            package_root=package_root,
            category="dependency",
            findings=[{"severity": severity, "id": "CVE-T3-1", "message": "test finding"}],
            summary={},
        )

    def _clean_pkg_result(self, plugin_name: str, package_root: str) -> PluginResult:
        return PluginResult(
            plugin_name=plugin_name,
            package_root=package_root,
            findings=[],
            summary={},
        )

    def test_single_package_no_grouping(self):
        """Results with package_root=None render identically to current behavior."""
        result = PluginResult(
            plugin_name="semgrep",
            category="code",
            findings=[{"severity": "high", "id": "CVE-1", "message": "x"}],
            summary={},
        )
        md = render_comment([result], repo="org/repo", pr_num=1, title="test")
        assert "## apps/" not in md
        assert "## libs/" not in md
        assert "PASS WITH WARNINGS" in md

    def test_multi_package_section_headers(self):
        """Two packages get separate section headers."""
        results = [
            self._pkg_result("semgrep", "apps/web"),
            self._pkg_result("osv-scanner", "libs/core"),
        ]
        md = render_comment(results, repo="org/repo", pr_num=1, title="test")
        assert "## apps/web" in md
        assert "## libs/core" in md

    def test_multi_package_overall_verdict(self):
        """Overall verdict is worst of all packages (blocked > warnings > clear)."""
        results = [
            self._pkg_result("semgrep", "apps/web", severity="high"),  # blocked
            self._pkg_result("osv-scanner", "libs/core", severity="medium"),  # warnings
        ]
        md = render_comment(results, repo="org/repo", pr_num=1, title="test")
        assert "BLOCKED" in md

    def test_multi_package_per_package_score(self):
        """Each package section shows its own severity score."""
        results = [
            self._pkg_result("semgrep", "apps/web", severity="high"),  # score 95 (100-5)
            self._clean_pkg_result("osv-scanner", "libs/core"),  # score 100
        ]
        md = render_comment(results, repo="org/repo", pr_num=1, title="test")
        assert "apps/web" in md
        assert "libs/core" in md
        # apps/web has 1 high finding → per-package score = 95
        assert "95" in md

    def test_multi_package_clean_and_dirty(self):
        """One clean package + one with findings: overall = the dirty one's verdict."""
        results = [
            self._clean_pkg_result("semgrep", "apps/web"),
            self._pkg_result("osv-scanner", "libs/core", severity="high"),
        ]
        md = render_comment(results, repo="org/repo", pr_num=1, title="test")
        assert "BLOCKED" in md


class TestCalculateSeverityScore:
    def test_no_findings_score_is_100(self):
        results = [PluginResult(plugin_name="osv-scanner", findings=[])]
        assert calculate_severity_score(results) == 100.0

    def test_one_critical_finding_score_is_90(self):
        results = [
            PluginResult(
                plugin_name="osv-scanner",
                findings=[{"severity": "critical", "id": "CVE-X"}],
            )
        ]
        assert calculate_severity_score(results) == 90.0

    def test_one_critical_two_high_score_is_80(self):
        results = [
            PluginResult(
                plugin_name="osv-scanner",
                findings=[
                    {"severity": "critical", "id": "CVE-1"},
                    {"severity": "high", "id": "CVE-2"},
                    {"severity": "high", "id": "CVE-3"},
                ],
            )
        ]
        # 100 - 10 - 5 - 5 = 80
        assert calculate_severity_score(results) == 80.0

    def test_only_info_findings_score_is_100(self):
        results = [
            PluginResult(
                plugin_name="osv-scanner",
                findings=[
                    {"severity": "info", "id": "INFO-1"},
                    {"severity": "info", "id": "INFO-2"},
                ],
            )
        ]
        assert calculate_severity_score(results) == 100.0

    def test_massive_findings_score_floors_at_0(self):
        results = [
            PluginResult(
                plugin_name="osv-scanner",
                findings=[{"severity": "critical", "id": f"CVE-{i}"} for i in range(20)],
            )
        ]
        # 20 * 10 = 200 weighted sum; 100 - 200 = -100 → clamped to 0
        assert calculate_severity_score(results) == 0.0

    def test_missing_severity_key_treated_as_info_weight_zero(self):
        results = [
            PluginResult(
                plugin_name="semgrep",
                findings=[
                    {"message": "no severity key here"},
                    {"message": "also missing"},
                ],
            )
        ]
        assert calculate_severity_score(results) == 100.0

    def test_quality_plugins_excluded_from_security_score(self):
        results = [
            PluginResult(
                plugin_name="blast-radius",
                findings=[{"severity": "critical"} for _ in range(100)],
            ),
            PluginResult(
                plugin_name="complexity",
                findings=[{"severity": "high"} for _ in range(50)],
            ),
        ]
        assert calculate_severity_score(results) == 100.0

    def test_score_shown_in_comment_with_security_and_quality(self):
        results = [
            PluginResult(
                plugin_name="osv-scanner",
                findings=[{"severity": "critical", "id": "CVE-X"}],
            )
        ]
        md = render_comment(results, repo="org/repo", pr_num=1, title="test")
        assert "Security: 90/100" in md
        assert "Quality:" in md

    def test_score_shown_even_when_100(self):
        results = [PluginResult(plugin_name="osv-scanner", findings=[])]
        md = render_comment(results, repo="org/repo", pr_num=1, title="test")
        assert "Security: 100/100" in md


class TestSectionOrdering:
    """Sections must render security-first regardless of input order (#89)."""

    def test_security_sections_before_quality(self):
        results = [
            PluginResult(
                plugin_name="complexity",
                findings=[{"severity": "medium", "message": "high complexity"}],
                category="quality",
            ),
            PluginResult(
                plugin_name="gitleaks",
                findings=[{"severity": "critical", "message": "leaked secret"}],
                category="supply_chain",
            ),
        ]
        _, _, sections = _build_sections(results, None)
        assert len(sections) == 2
        assert "gitleaks" in sections[0]
        assert "complexity" in sections[1]

    def test_dependency_before_code(self):
        results = [
            PluginResult(
                plugin_name="semgrep",
                findings=[{"severity": "medium", "message": "code issue"}],
                category="code",
            ),
            PluginResult(
                plugin_name="osv-scanner",
                findings=[{"severity": "high", "message": "CVE found"}],
                category="dependency",
            ),
        ]
        _, _, sections = _build_sections(results, None)
        assert len(sections) == 2
        assert "osv-scanner" in sections[0]
        assert "semgrep" in sections[1]

    def test_category_priority_map_exists(self):
        assert "supply_chain" in CATEGORY_PRIORITY
        assert "dependency" in CATEGORY_PRIORITY
        assert "quality" in CATEGORY_PRIORITY
        assert CATEGORY_PRIORITY["supply_chain"] < CATEGORY_PRIORITY["quality"]

    def test_results_without_category_sort_last(self):
        results = [
            PluginResult(
                plugin_name="unknown",
                findings=[{"severity": "low", "message": "something"}],
            ),
            PluginResult(
                plugin_name="gitleaks",
                findings=[{"severity": "critical", "message": "secret"}],
                category="supply_chain",
            ),
        ]
        _, _, sections = _build_sections(results, None)
        assert len(sections) == 2
        assert "gitleaks" in sections[0]


class TestActionabilityInComment:
    def test_actionability_section_rendered_for_fixable_findings(self):
        result = PluginResult(
            plugin_name="trivy",
            findings=[
                {
                    "id": "CVE-2025-1234",
                    "severity": "critical",
                    "package": "libfoo",
                    "version": "1.0.0",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-1234",
                    "summary": "Test vuln",
                    "fixed_version": "2.0.0",
                },
            ],
        )
        md = render_comment([result], repo="org/repo", pr_num=1, title="test")
        assert "Actionability" in md
        assert "fixable" in md.lower()
        assert "2.0.0" in md

    def test_actionability_section_rendered_for_blocked_findings(self):
        result = PluginResult(
            plugin_name="trivy",
            findings=[
                {
                    "id": "CVE-2025-9999",
                    "severity": "critical",
                    "package": "libbar",
                    "version": "3.0.0",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-9999",
                    "summary": "Unfixable",
                },
            ],
        )
        md = render_comment([result], repo="org/repo", pr_num=1, title="test")
        assert "Actionability" in md
        assert "blocked" in md.lower()
        assert "none actionable" in md.lower()

    def test_no_actionability_section_when_no_findings(self):
        result = PluginResult(plugin_name="trivy", findings=[])
        md = render_comment([result], repo="org/repo", pr_num=1, title="test")
        assert "Actionability" not in md


# ---------------------------------------------------------------------------
# Renderer validation — non-callable render, render that raises
# ---------------------------------------------------------------------------


class TestRendererInputValidation:
    """_build_sections must be defensive against bad renderer objects."""

    def _result(self) -> PluginResult:
        return PluginResult(
            plugin_name="test_plugin",
            category="code",
            findings=[{"severity": "low", "message": "test finding"}],
            summary={},
        )

    def test_non_callable_render_attribute_falls_back_to_default(self):
        """If renderer.render is not callable, _build_sections must fall back to default."""

        class AttribRenderer:
            render = "not a function"

        _, _, sections = _build_sections([self._result()], {"test_plugin": AttribRenderer()})
        assert len(sections) == 1
        assert "test_plugin" in sections[0]

    def test_renderer_that_raises_falls_back_to_default(self):
        """If renderer.render() raises, _build_sections must fall back to default."""

        class BrokenRenderer:
            def render(self, r):
                raise RuntimeError("renderer exploded")

        _, _, sections = _build_sections([self._result()], {"test_plugin": BrokenRenderer()})
        assert len(sections) == 1
        assert "test_plugin" in sections[0]


class TestRenderCommentTruncation:
    """Tests for render_comment truncation at block boundaries."""

    def _big_result(self, count: int = 3000) -> PluginResult:
        """PluginResult with enough findings to trigger truncation."""
        return PluginResult(
            plugin_name="osv-scanner",
            category="dependency",
            findings=[
                {
                    "id": f"CVE-2024-{i:04d}",
                    "severity": "high",
                    "package": f"pkg{i}",
                    "version": "1.0.0",
                    "url": f"https://example.com/{i}",
                    "summary": f"Vulnerability number {i} with a long description to pad output",
                }
                for i in range(count)
            ],
            summary={"total": count, "critical_high": count},
        )

    def test_truncated_output_within_max_length(self) -> None:
        """render_comment output must never exceed _MAX_COMMENT_LENGTH."""
        from caliper.core.renderer import _MAX_COMMENT_LENGTH

        output = render_comment([self._big_result()], repo="org/repo", pr_num=1)

        assert len(output) <= _MAX_COMMENT_LENGTH + len(
            "\n\n*[comment truncated — full report in artifacts]*"
        )

    def test_truncated_output_ends_at_line_boundary(self) -> None:
        """Truncated output must not split a line mid-way.

        Before fix: raw character slice could cut in the middle of a Markdown
        table row or code block.
        After fix: truncation stops at the last newline before the limit.
        """
        output = render_comment([self._big_result()], repo="org/repo", pr_num=1)

        if "*[comment truncated — full report in artifacts]*" in output:
            before_marker = output.split("*[comment truncated — full report in artifacts]*")[0]
            # Must end at a line boundary (newline), not mid-word
            assert before_marker.endswith("\n") or before_marker.endswith(
                "\n\n"
            ), f"Expected line boundary before truncation marker, got: {repr(before_marker[-30:])}"

    def test_truncation_marker_at_end(self) -> None:
        """The truncation notice must be the final text in the output."""
        output = render_comment([self._big_result()], repo="org/repo", pr_num=1)

        if "*[comment truncated — full report in artifacts]*" in output:
            assert output.rstrip().endswith("*[comment truncated — full report in artifacts]*")
