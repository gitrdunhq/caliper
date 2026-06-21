"""Comment renderer — assembles plugin results into markdown.
# tested-by: tests/unit/test_renderer.py

Pure function: no I/O beyond reading template files.
"""

from __future__ import annotations

from pathlib import Path

import jinja2

from eedom.core.plugin import PluginResult
from eedom.core.version import get_version

_MAX_COMMENT_LENGTH = 65536

CATEGORY_PRIORITY: dict[str, int] = {
    "supply_chain": 0,
    "dependency": 1,
    "infra": 2,
    "code": 3,
    "quality": 4,
}
_DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_VERSION = get_version()

_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_SECURITY_PLUGINS: set[str] = {
    "gitleaks",
    "semgrep",
    "trivy",
    "osv-scanner",
    "clamav",
    "supply-chain",
    "opa",
    "scancode",
    "kube-linter",
    "mypy",
}

_QUALITY_PLUGINS: set[str] = {
    "blast-radius",
    "complexity",
    "cpd",
    "cspell",
    "ls-lint",
}


def _plugin_is_security(plugin_name: str) -> bool:
    normalized = plugin_name.lower().replace("_", "-")
    return normalized in _SECURITY_PLUGINS


def calculate_severity_score(results: list[PluginResult]) -> float:
    """Return a 0-100 health score based on security plugin findings only.

    Quality plugins (blast-radius, complexity, cpd, cspell, ls-lint) are
    excluded from the score — they are advisory, not merge-blocking.

    Formula: max(0, 100 - sum(weight(severity) for each security finding))
    Weights: critical=10, high=5, medium=2, low=1, info=0.
    """
    total_weight = 0
    for result in results:
        if not _plugin_is_security(result.plugin_name):
            continue
        for finding in result.findings:
            sev = str(finding.get("severity", "")).lower()
            total_weight += _SEVERITY_WEIGHTS.get(sev, 0)
    return max(0.0, min(100.0, 100.0 - total_weight))


def calculate_quality_score(results: list[PluginResult]) -> float:
    """Return a 0-100 quality score based on quality plugin findings only.

    Advisory — does not gate merges. Reported alongside the security score.
    """
    total_weight = 0
    for result in results:
        if _plugin_is_security(result.plugin_name):
            continue
        for finding in result.findings:
            sev = str(finding.get("severity", "")).lower()
            total_weight += _SEVERITY_WEIGHTS.get(sev, 0)
    return max(0.0, min(100.0, 100.0 - total_weight))


def _is_monorepo(results: list[PluginResult]) -> bool:
    """Return True when at least one result carries a package_root label."""
    return any(r.package_root is not None for r in results)


def _group_by_package(results: list[PluginResult]) -> dict[str, list[PluginResult]]:
    """Partition results by package_root, preserving insertion order."""
    packages: dict[str, list[PluginResult]] = {}
    for r in results:
        key = r.package_root or ""
        packages.setdefault(key, []).append(r)
    return packages


def _verdict_rank(verdict: str) -> int:
    return {"blocked": 3, "warnings": 2, "incomplete": 1, "clear": 0}.get(verdict, 0)


def _build_monorepo_sections(
    results: list[PluginResult],
    plugin_renderers: dict[str, object] | None,
) -> tuple[str, list[tuple[str, str]], list[str]]:
    """Build per-package sections for monorepo results.

    Returns the same (verdict, summary_rows, sections) triple as
    _build_sections so render_comment can use either path transparently.
    """
    packages = _group_by_package(results)
    overall_verdict = "clear"
    summary_rows: list[tuple[str, str]] = []
    sections: list[str] = []

    for pkg_root, pkg_results in packages.items():
        pkg_verdict, pkg_rows, pkg_finding_sections = _build_sections(pkg_results, plugin_renderers)
        pkg_score = calculate_severity_score(pkg_results)
        pkg_quality = calculate_quality_score(pkg_results)

        if _verdict_rank(pkg_verdict) > _verdict_rank(overall_verdict):
            overall_verdict = pkg_verdict

        header = pkg_root if pkg_root else "(root)"
        pkg_lines: list[str] = [
            f"## {header}",
            f"> Security: {int(pkg_score)}/100 · Quality: {int(pkg_quality)}/100",
            "",
            "| Plugin | Findings |",
            "|--------|----------|",
        ]
        for row in pkg_rows:
            pkg_lines.append(f"| {row[0]} | {row[1]} |")

        for fs in pkg_finding_sections:
            if fs:
                pkg_lines.append("")
                pkg_lines.append(fs)

        sections.append("\n".join(pkg_lines))
        summary_rows.append(
            (
                header,
                f"{pkg_verdict.upper()} (Sec: {int(pkg_score)} · Qual: {int(pkg_quality)})",
            )
        )

    return overall_verdict, summary_rows, sections


def render_comment(
    results: list[PluginResult],
    repo: str = "",
    pr_num: int = 0,
    title: str = "",
    file_count: int = 0,
    template_dir: Path | None = None,
    plugin_renderers: dict[str, object] | None = None,
) -> str:
    tpl_dir = template_dir or _DEFAULT_TEMPLATE_DIR
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(tpl_dir)),
        autoescape=False,  # nosemgrep: jinja2-autoescape-disabled — output is markdown, not HTML
        keep_trailing_newline=True,
    )
    template = env.get_template("comment.md.j2")

    if _is_monorepo(results):
        verdict, summary_rows, sections = _build_monorepo_sections(results, plugin_renderers)
    else:
        verdict, summary_rows, sections = _build_sections(results, plugin_renderers)

    severity_score = calculate_severity_score(results)
    quality_score = calculate_quality_score(results)
    mi_grade, mi_score, mi_icon, avg_ccn, hi_ccn, mi_c_count = _extract_mi(results)

    from eedom.core.actionability import classify_findings

    act_summary = classify_findings(results)

    footer_parts = []
    for r in results:
        if r.error:
            continue
        count = len(r.findings)
        if count:
            footer_parts.append(f"{count} {r.plugin_name}")
    footer_stats = " · ".join(footer_parts) if footer_parts else "clean"

    output = template.render(
        repo=repo,
        pr_num=pr_num,
        title=title,
        verdict=verdict,
        file_count=file_count,
        summary_rows=summary_rows,
        sections=sections,
        severity_score=severity_score,
        quality_score=quality_score,
        mi_grade=mi_grade,
        mi_score=mi_score,
        mi_icon=mi_icon,
        avg_ccn=avg_ccn,
        hi_ccn=hi_ccn,
        mi_c_count=mi_c_count,
        version=_VERSION,
        footer_stats=footer_stats,
        actionability=act_summary,
    )

    if len(output) > _MAX_COMMENT_LENGTH:
        truncated = output[: _MAX_COMMENT_LENGTH - 100]
        truncated += "\n\n*[comment truncated — full report in artifacts]*"
        return truncated

    return output


def _build_sections(
    results: list[PluginResult],
    plugin_renderers: dict[str, object] | None,
) -> tuple[str, list[tuple[str, str]], list[str]]:
    verdict = "clear"
    summary_rows: list[tuple[str, str]] = []
    sections: list[str] = []

    _max_priority = max(CATEGORY_PRIORITY.values()) + 1
    sorted_results = sorted(
        results,
        key=lambda r: CATEGORY_PRIORITY.get(r.category, _max_priority),
    )

    for r in sorted_results:
        count = len(r.findings)
        label = r.plugin_name

        if r.error:
            summary_rows.append((label, f"error: {r.error}"))
            if verdict == "clear":
                verdict = "incomplete"
            continue

        status = r.summary.get("status", "")
        if status == "skipped":
            summary_rows.append((label, "skipped"))
            continue

        summary_rows.append((label, str(count)))

        has_crit = any(f.get("severity") in ("critical", "high") for f in r.findings)
        is_security = r.category in {"dependency", "supply_chain", "infra"}
        if has_crit and is_security:
            verdict = "blocked"
        elif count and verdict != "blocked":
            verdict = "warnings"

        renderer = None
        if plugin_renderers:
            renderer = plugin_renderers.get(r.plugin_name)

        if renderer is not None and callable(getattr(renderer, "render", None)):
            try:
                md = renderer.render(r)
            except Exception:  # noqa: BLE001
                md = _default_render(r)
        else:
            md = _default_render(r)

        if md:
            sections.append(md)

    return verdict, summary_rows, sections


def _default_render(result: PluginResult) -> str:
    if not result.findings:
        return ""
    lines = [f"**{result.plugin_name}**: {len(result.findings)} findings"]
    return "\n".join(lines)


class MarkdownRenderer:
    """ReportRendererPort implementation that produces a markdown PR comment."""

    def render(self, report) -> str:  # report: ReviewReport
        return render_comment(report.plugin_results)


def _extract_mi(
    results: list[PluginResult],
) -> tuple[str, int, str, float, int, int]:
    for r in results:
        if r.plugin_name == "complexity" and r.findings:
            s = r.summary
            avg = s.get("avg_cyclomatic_complexity", 0)
            mi_scores = []
            for f in r.findings:
                mi_str = f.get("maintainability_index", "")
                if "(" in str(mi_str):
                    try:
                        val = float(str(mi_str).split("(")[1].rstrip(")"))
                        mi_scores.append(val)
                    except (ValueError, IndexError):
                        pass
            avg_mi = sum(mi_scores) / len(mi_scores) if mi_scores else 0
            grade = "A" if avg_mi >= 20 else ("B" if avg_mi >= 10 else "C")
            icon = {"A": "🟢", "B": "🟡", "C": "🔴"}.get(grade, "⚪")
            hi = s.get("high_complexity_count", 0)
            c_count = sum(1 for s in mi_scores if s < 10)
            return grade, int(avg_mi), icon, avg, hi, c_count
    return "", 0, "", 0.0, 0, 0


from eedom.core.registries import RENDERERS  # noqa: E402  (registration wiring)


@RENDERERS.register("markdown")
def build_markdown_renderer() -> MarkdownRenderer:
    return MarkdownRenderer()
