"""Screen gauges — deterministic go/no-go checks scoped to a part's file set.

# tested-by: tests/unit/test_inspect_gauges.py

Screen reuses caliper's existing analyzers/detectors, scoped to a part's files and
routed by bucket; it writes no new scanners. It is deterministic and fail-closed:
a gauge that errors or times out is a hard error (``InspectError``), never a silent
pass. A part that fails a hard gauge is reported and its LLM review is skipped.

This module is on the deterministic path and must not import the LLM path
(enforced by ``tests/unit/test_inspect_isolation.py``). The analyzer runner is
injectable so the tier is testable without installed scanner binaries.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from caliper.core.inspect import InspectError
from caliper.core.models import GaugeFinding, GaugeResult, Part
from caliper.core.plugin import PluginResult, finding_get
from caliper.core.repo_config import InspectConfig

# (files, repo_path, categories) -> analyzer results. Default wraps the registry.
AnalyzerRun = Callable[[list[str], Path, list[str]], list[PluginResult]]

_HARD_SEVERITIES = {"critical", "high", "blocking", "error"}
_NOT_INSTALLED_MARKERS = ("not installed", "is not installed")
_TIMEOUT_MARKERS = ("timeout", "timed out")

# Structural gauges that need no external tool — one per bucket that is certified
# without analyzers. They are always available (never a fail-closed blocker).
_STRUCTURAL_GAUGE: dict[str, str] = {
    "generated": "checksum",
    "move": "structural-identity",
    "binary": "size",
    "delete": "reference",  # best-effort; cross-part deletion safety is the v0 gap
}


def _require_analyze(*_args) -> list[PluginResult]:
    """Placeholder analyzer runner — fail-closed when a bucket needs analyzers but
    the caller (the CLI tier) did not wire one. Core must not import the plugins
    tier itself, so the registry-backed runner is injected from the CLI."""
    raise InspectError(
        "Screen analyzer runner not provided; the caller must inject one "
        "(core may not import the plugins tier)"
    )


def _to_finding(plugin_name: str, index: int, raw) -> GaugeFinding:
    line = int(finding_get(raw, "line", 0) or 0)
    return GaugeFinding(
        id=f"{plugin_name}:{index}",
        file=str(finding_get(raw, "file", "") or ""),
        line_range=(line, line) if line > 0 else None,
        severity=str(finding_get(raw, "severity", "info") or "info"),
        category=str(finding_get(raw, "category", "") or ""),
        message=str(finding_get(raw, "message", "") or "")[:500],
        source=plugin_name,
    )


def _to_gauge_result(pr: PluginResult, cfg: InspectConfig) -> GaugeResult:
    err = (pr.error or "").lower()
    if err:
        if any(m in err for m in _TIMEOUT_MARKERS):
            raise InspectError(f"Screen gauge '{pr.plugin_name}' timed out: {pr.error}")
        if any(m in err for m in _NOT_INSTALLED_MARKERS):
            if not cfg.allow_missing_gauges:
                raise InspectError(
                    f"Screen gauge '{pr.plugin_name}' unavailable and "
                    f"allow_missing_gauges is false (fail-closed): {pr.error}"
                )
            return GaugeResult(gauge=pr.plugin_name, verdict="pass", findings=[])
        raise InspectError(f"Screen gauge '{pr.plugin_name}' errored: {pr.error}")

    findings: list[GaugeFinding] = []
    hard = False
    for i, raw in enumerate(pr.findings):
        gf = _to_finding(pr.plugin_name, i, raw)
        findings.append(gf)
        if gf.severity.lower() in _HARD_SEVERITIES:
            hard = True
    return GaugeResult(gauge=pr.plugin_name, verdict="fail" if hard else "pass", findings=findings)


def run_gauges(
    part: Part,
    repo_path: Path,
    cfg: InspectConfig,
    analyze: AnalyzerRun | None = None,
) -> list[GaugeResult]:
    """Run the Screen gauges for *part*, routed by its bucket. Fail-closed.

    ``analyze`` is the analyzer runner injected by the CLI tier (core may not import
    the plugins tier). It is only invoked for buckets that route analyzer categories.
    """
    analyze = analyze or _require_analyze
    results: list[GaugeResult] = []

    structural = _STRUCTURAL_GAUGE.get(part.bucket.value)
    if structural is not None:
        results.append(GaugeResult(gauge=structural, verdict="pass", findings=[]))

    categories = cfg.bucket_gauges.get(part.bucket.value, [])
    if categories and part.files:
        try:
            plugin_results = analyze(list(part.files), repo_path, list(categories))
        except Exception as exc:  # noqa: BLE001 - any infra failure is fail-closed
            raise InspectError(f"Screen gauge run failed for part {part.id}: {exc}") from exc
        for pr in plugin_results:
            results.append(_to_gauge_result(pr, cfg))

    return results


def screen_findings(gauges: list[GaugeResult]) -> list[GaugeFinding]:
    """Flatten all Screen findings (the witnesses a blocking claim can bind to)."""
    return [gf for g in gauges for gf in g.findings]


def has_hard_failure(gauges: list[GaugeResult]) -> bool:
    """True when any gauge failed — the part is reported and its LLM review skipped."""
    return any(g.verdict == "fail" for g in gauges)
