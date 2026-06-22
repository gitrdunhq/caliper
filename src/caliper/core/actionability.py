"""Actionability classification for scanner findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from caliper.core.plugin import Actionability, PluginResult

__all__ = ["Actionability", "ActionabilitySummary", "classify_findings"]

_CRITICAL_HIGH = {"critical", "high"}


@dataclass
class ActionabilitySummary:
    actionable: list[dict] = field(default_factory=list)
    blocked: list[dict] = field(default_factory=list)
    actionable_count: int = 0
    blocked_count: int = 0
    blocked_by_source: dict[str, list[dict]] = field(default_factory=dict)
    summary_text: str = ""


def _is_actionable(finding: dict) -> bool:
    fv = finding.get("fixed_version", "")
    return bool(fv and fv.strip())


def _build_summary_text(
    actionable: list[dict],
    blocked: list[dict],
) -> str:
    total = len(actionable) + len(blocked)
    if total == 0:
        return "No findings."

    crit_high_blocked = sum(1 for f in blocked if f.get("severity", "") in _CRITICAL_HIGH)
    crit_blocked = sum(1 for f in blocked if f.get("severity", "") == "critical")
    high_blocked = sum(1 for f in blocked if f.get("severity", "") == "high")

    if not actionable:
        # All blocked
        if crit_high_blocked > 0:
            parts = []
            if crit_blocked:
                parts.append(f"{crit_blocked} CRITICAL")
            if high_blocked:
                parts.append(f"{high_blocked} HIGH")
            severity_str = " + ".join(parts) if parts else f"{crit_high_blocked} CRITICAL/HIGH"
            return (
                f"{severity_str} findings — none actionable by you. "
                "All in upstream dependencies at latest release."
            )
        return f"{len(blocked)} findings — none actionable by you."

    if not blocked:
        # All actionable
        return f"All {len(actionable)} findings have available fixes."

    # Mixed
    return (
        f"{len(actionable)} findings have available fixes. {len(blocked)} are blocked on upstream."
    )


def classify_findings(results: list[PluginResult]) -> ActionabilitySummary:
    """Classify all findings across plugin results by actionability.

    Args:
        results: Plugin results from all scanners.

    Returns:
        ActionabilitySummary with actionable/blocked split, counts,
        per-source grouping, and human-readable summary text.
    """
    actionable: list[dict] = []
    blocked: list[dict] = []
    blocked_by_source: dict[str, list[dict]] = {}

    for result in results:
        for finding in result.findings:
            if _is_actionable(finding):
                actionable.append(finding)
            else:
                blocked.append(finding)
                blocked_by_source.setdefault(result.plugin_name, []).append(finding)

    return ActionabilitySummary(
        actionable=actionable,
        blocked=blocked,
        actionable_count=len(actionable),
        blocked_count=len(blocked),
        blocked_by_source=blocked_by_source,
        summary_text=_build_summary_text(actionable, blocked),
    )
