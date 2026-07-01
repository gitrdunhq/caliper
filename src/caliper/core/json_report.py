# tested-by: tests/unit/test_json_report.py
# tested-by: tests/unit/test_report_schema.py
"""Structured JSON output for machine consumption.

The emitted document round-trips through the published Pydantic models in
``caliper.core.report_schema`` (#389) so the output always matches the
JSON Schema artifact in ``docs/schema/``.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import orjson

from caliper.core.plugin import PluginResult
from caliper.core.report_schema import (
    REPORT_SCHEMA_VERSION,
    PluginReportModel,
    PluginStatus,
    ReportModel,
    ReportVerdict,
)
from caliper.core.review_summary import ReviewSummary, summarize_review

# Plugin summaries are meant to be small, renderer-friendly metadata (counts,
# flags, short strings) — not full documents. A plugin that inlines a large
# nested payload (e.g. syft embedding a full SBOM under "sbom") would bloat
# every JSON report and risk over-disclosing internal data unconditionally
# (#223 / #257). This is the one sanitization seam all plugin summaries pass
# through on the way into the report.
_SUMMARY_DENYLIST_KEYS = frozenset({"sbom", "sbom_data", "bom", "cyclonedx"})
_SUMMARY_MAX_VALUE_CHARS = 1000


def _sanitize_summary(summary: dict, *, include_sbom: bool = False) -> dict:
    """Strip large/SBOM-shaped payloads from a plugin summary before rendering.

    ``include_sbom`` is the opt-in escape hatch for a future CLI flag (e.g.
    ``--include-sbom``) — wiring that flag through ``cli/main.py`` is a
    natural follow-up; today it defaults to False so every report is safe
    by default.
    """
    if include_sbom:
        return summary

    sanitized: dict = {}
    for key, value in summary.items():
        if key.lower() in _SUMMARY_DENYLIST_KEYS:
            continue
        if isinstance(value, (dict, list)) and len(orjson.dumps(value)) >= _SUMMARY_MAX_VALUE_CHARS:
            continue
        sanitized[key] = value
    return sanitized


def _plugin_status(result: PluginResult) -> str:
    if result.error:
        return "error"
    if result.summary.get("status") == "skipped":
        return "skipped"
    return "ran"


def _finding_to_dict(finding: object) -> dict:
    """Normalize a finding to a plain dict with metadata nested (report shape)."""
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "model_dump"):  # frozen PluginFinding Contract
        return finding.model_dump()
    if dataclasses.is_dataclass(finding) and not isinstance(finding, type):
        return dataclasses.asdict(finding)
    return finding  # type: ignore[return-value]


def render_json(
    results: list[PluginResult],
    repo: str = "",
    commit: str = "",
    summary: ReviewSummary | None = None,
    include_sbom: bool = False,
) -> str:
    # Single source of truth: the canonical verdict/counts/scores. Callers pass the
    # diff-scoped summary; absent that, compute a repo-wide one so the JSON still
    # agrees with the other outputs.
    if summary is None:
        summary = summarize_review(results)

    total_findings = sum(len(r.findings) for r in results)

    plugins = []
    for r in results:
        plugins.append(
            PluginReportModel(
                name=r.plugin_name,
                category=r.category,
                status=PluginStatus(_plugin_status(r)),
                skip_reason=r.skip_reason or None,
                skip_remediation=r.skip_remediation or None,
                findings_count=len(r.findings),
                findings=[_finding_to_dict(f) for f in r.findings],
                summary=_sanitize_summary(r.summary, include_sbom=include_sbom),
                error=r.error or None,
            )
        )

    report = ReportModel(
        schema_version=REPORT_SCHEMA_VERSION,
        timestamp=datetime.now(UTC).isoformat(),
        repo=repo,
        commit=commit,
        verdict=ReportVerdict(summary.verdict.value),
        security_score=summary.security_score,
        quality_score=summary.quality_score,
        error_count=summary.error_count,
        warning_count=summary.warning_count,
        note_count=summary.note_count,
        crashed_count=summary.crashed_count,
        skipped_count=summary.skipped_count,
        blocking_count=summary.blocking_count,
        total_findings=total_findings,
        total_plugins=len(results),
        plugins=plugins,
    )

    return orjson.dumps(report.model_dump(mode="json"), option=orjson.OPT_INDENT_2).decode()


class JsonRenderer:
    """ReportRendererPort implementation that produces a structured JSON string."""

    def render(self, report) -> str:  # report: ReviewReport
        return render_json(report.plugin_results)


from caliper.core.registries import RENDERERS  # noqa: E402  (registration wiring)


@RENDERERS.register("json")
def build_json_renderer() -> JsonRenderer:
    return JsonRenderer()
