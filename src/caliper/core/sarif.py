# tested-by: tests/unit/test_sarif.py
"""SARIF v2.1.0 output format for GitHub Security tab integration.

Pure function: no I/O. Converts plugin results to a SARIF 2.1.0 document.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

from caliper.core.plugin import PluginResult
from caliper.core.review_summary import SEVERITY_TO_LEVEL, ReviewSummary, summarize_review
from caliper.core.version import get_version

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/"
    "schema/sarif-schema-2.1.0.json"
)

# Severity -> SARIF level uses the canonical map (review_summary), so SARIF, the
# JSON report, and the verdict all classify severities identically.
_SEVERITY_TO_LEVEL = SEVERITY_TO_LEVEL


def _rule_id(finding: dict, plugin_name: str) -> str:
    """Extract a stable rule identifier from a finding dict."""
    for key in ("rule_id", "advisory_id", "id", "check_id"):
        val = finding.get(key)
        if val:
            return str(val)
    return plugin_name


def _message_text(finding: dict) -> str:
    """Extract a human-readable description from a finding dict."""
    for key in ("message", "description", "summary"):
        val = finding.get(key)
        if val:
            return str(val)
    return ""


def _level(finding: dict) -> str:
    """Map severity field to a SARIF level string."""
    raw = str(finding.get("severity", "")).lower()
    return _SEVERITY_TO_LEVEL.get(raw, "note")


def _make_locations(finding: dict, repo_path: str | None) -> list[dict]:
    """Build SARIF locations list from file/line fields if present."""
    file_path = finding.get("file") or finding.get("path")
    if not file_path:
        return []

    uri = str(file_path)
    if repo_path:
        with contextlib.suppress(ValueError):
            uri = str(Path(file_path).relative_to(repo_path))

    start_line = finding.get("start_line") or finding.get("line") or 1
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": int(start_line)},
            }
        }
    ]


def _scribe(finding: dict) -> dict | None:
    """Return the detect-then-scribe packet (ADR-006) for *finding*, or None.

    Surfaced verbatim into the SARIF result's property bag so scribe reaches
    SARIF consumers at parity with the JSON report.
    """
    metadata = finding.get("metadata") or {}
    scribe = metadata.get("scribe")
    return scribe or None


def _plugin_to_run(
    result: PluginResult,
    repo_path: str | None,
    max_findings: int = 0,
) -> dict:
    """Convert one PluginResult to a SARIF run object."""
    findings = result.findings
    truncated = 0
    if max_findings > 0 and len(findings) > max_findings:
        truncated = len(findings) - max_findings
        findings = findings[:max_findings]

    sarif_results: list[dict] = []
    for finding in findings:
        sarif_result: dict = {
            "ruleId": _rule_id(finding, result.plugin_name),
            "level": _level(finding),
            "message": {"text": _message_text(finding)},
        }
        locations = _make_locations(finding, repo_path)
        if locations:
            sarif_result["locations"] = locations
        scribe = _scribe(finding)
        if scribe:
            sarif_result["properties"] = {"scribe": scribe}
        sarif_results.append(sarif_result)

    if result.error:
        sarif_results.append(
            {
                "ruleId": "caliper-plugin-error",
                "level": "error",
                "message": {"text": result.error},
            }
        )

    if truncated > 0:
        sarif_results.append(
            {
                "ruleId": "caliper-truncated",
                "level": "note",
                "message": {
                    "text": f"{truncated} additional findings truncated. "
                    f"Query the code graph directly for full results."
                },
            }
        )

    tool_name = (
        f"{result.plugin_name} [{result.package_root}]"
        if result.package_root
        else result.plugin_name
    )
    return {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": get_version(),
            }
        },
        "results": sarif_results,
    }


def to_sarif(
    results: list[PluginResult],
    repo_path: str | None = None,
    max_findings_per_run: int = 0,
    summary: ReviewSummary | None = None,
) -> dict:
    """Convert plugin results to a SARIF v2.1.0 document.

    Args:
        results: List of PluginResult objects from any registered plugin.
        repo_path: Optional absolute path to the repository root. When
            provided, absolute file URIs are made relative to this path.
        max_findings_per_run: Cap findings per plugin run. 0 means no limit.

    Returns:
        A dict that serialises to a valid SARIF 2.1.0 JSON document.
    """
    if summary is None:
        summary = summarize_review(results)
    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        # Canonical verdict/counts (single source of truth) as a top-level property
        # bag so SARIF consumers and the CI gate read the same conclusion as the
        # markdown badge and JSON report.
        "properties": {
            "caliper_verdict": summary.verdict.value,
            "error_count": summary.error_count,
            "warning_count": summary.warning_count,
            "note_count": summary.note_count,
            "crashed_count": summary.crashed_count,
            "skipped_count": summary.skipped_count,
            "blocking_count": summary.blocking_count,
            "security_score": summary.security_score,
            "quality_score": summary.quality_score,
        },
        "runs": [_plugin_to_run(r, repo_path, max_findings_per_run) for r in results],
    }
    return doc


class SarifRenderer:
    """ReportRendererPort implementation that produces a SARIF v2.1.0 JSON string."""

    def render(self, report) -> str:  # report: ReviewReport
        doc = to_sarif(report.plugin_results)
        return json.dumps(doc, indent=2)


from caliper.core.registries import RENDERERS  # noqa: E402  (registration wiring)


@RENDERERS.register("sarif")
def build_sarif_renderer() -> SarifRenderer:
    return SarifRenderer()
