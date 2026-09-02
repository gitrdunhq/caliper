# tested-by: tests/unit/test_review_summary.py
"""The single source of truth for a review's verdict, counts, and scores (#output-SoT).

Every output caliper produces — the markdown PR comment badge, the JSON report, the
SARIF run properties, and the CI header/label — must agree on "what did this review
conclude". They used to disagree: the markdown badge, the JSON report, and a Python
snippet embedded in the GitHub workflow each computed a verdict independently, from
different inputs and rules. ``summarize_review`` is now the one place that decision is
made; all renderers and the workflow consume its result.

Verdict policy (diff-scoped gate):
  - A finding **blocks** only when it is error-level (critical/high), in a
    security-gating category (dependency / supply_chain / infra), AND attributable to
    the change under review — i.e. its file is in ``changed_files``. Pre-existing
    dependency CVEs on files the PR did not touch are advisory, not blocking.
  - ``changed_files=None`` means "no diff scope" (a full-repo scan, e.g. the release
    gate): every finding is attributable, so the gate is repo-wide.
  - Quality-category findings never block (advisory by design); they still count toward
    ``warning_count`` / the quality score.

Determinism: same results + same changed_files -> same summary (order-independent).
"""

from __future__ import annotations

from dataclasses import replace
from enum import StrEnum

from pydantic import Field

from caliper._base import Contract
from caliper.core.plugin import finding_get

# Severity ordering used for the semgrep min-severity floor — higher ranks first.
# Unknown/blank severities rank below "info" so they never accidentally clear a
# floor they can't be measured against.
_SEVERITY_RANK_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "warning": 3,
    "low": 2,
    "info": 1,
    "note": 1,
}


def _severity_floor_rank(severity: object) -> int:
    return _SEVERITY_RANK_ORDER.get(str(severity or "").lower(), 0)


def split_below_floor_semgrep_findings(
    results: list, semgrep_min_severity: str = "medium"
) -> tuple[list, list]:
    """Split semgrep findings below *semgrep_min_severity* out of *results*.

    Returns ``(filtered_results, below_floor_findings)``: *filtered_results* is
    *results* with every ``semgrep`` :class:`PluginResult`'s findings trimmed to
    only those meeting-or-exceeding the floor (all other plugins pass through
    unchanged); *below_floor_findings* is the flat list of excluded finding
    dicts — still returned by the plugin, just never counted toward
    verdict/score, and rendered separately (collapsed notes section).
    """
    floor_rank = _severity_floor_rank(semgrep_min_severity)
    filtered_results: list = []
    below_floor: list = []
    for r in results:
        plugin_name = str(getattr(r, "plugin_name", "") or "").lower()
        findings = getattr(r, "findings", [])
        if plugin_name != "semgrep" or not findings:
            filtered_results.append(r)
            continue
        keep = []
        for finding in findings:
            if _severity_floor_rank(finding_get(finding, "severity")) >= floor_rank:
                keep.append(finding)
            else:
                below_floor.append(finding)
        if len(keep) == len(findings):
            filtered_results.append(r)
        else:
            filtered_results.append(replace(r, findings=keep))
    return filtered_results, below_floor


# Canonical severity -> SARIF-style level map. The one mapping the whole system uses
# (SARIF imports this); unmapped severities fall back to "note" (least alarming).
SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "error": "error",
    "medium": "warning",
    "moderate": "warning",
    "warning": "warning",
    "low": "note",
    "info": "note",
    "note": "note",
}

# Categories whose findings gate a merge ("security blocks, quality advises").
SECURITY_CATEGORIES = frozenset({"dependency", "supply_chain", "infra"})


class ReviewVerdict(StrEnum):
    """The canonical verdict vocabulary (worst-first precedence)."""

    blocked = "blocked"
    incomplete = "incomplete"
    warnings = "warnings"
    clear = "clear"


class ReviewSummary(Contract):
    """The one computed conclusion of a review, consumed by every output."""

    verdict: ReviewVerdict
    error_count: int = 0
    warning_count: int = 0
    note_count: int = 0
    crashed_count: int = 0
    skipped_count: int = 0
    blocking_count: int = 0  # attributable, error-level, security findings (what blocks)
    security_score: float = 100.0
    quality_score: float = 100.0
    maintainability_grade: str = "A"
    verdict_text: str = ""
    incomplete_plugins: list[tuple[str, str]] = Field(default_factory=list)


def level_for(severity: object) -> str:
    """Return the SARIF-style level ("error"/"warning"/"note") for a severity."""
    return SEVERITY_TO_LEVEL.get(str(severity or "").lower(), "note")


def _norm(path: object) -> str:
    """Normalize a path for changed-file membership tests."""
    return str(path or "").lstrip("./")


def _status_of(result: object) -> str | None:
    """Return a plugin result's reported ``summary.status``, if any."""
    return (getattr(result, "summary", {}) or {}).get("status")


def summarize_review(
    results: list,
    *,
    changed_files: set[str] | None = None,
    semgrep_min_severity: str = "medium",
) -> ReviewSummary:
    """Compute the canonical :class:`ReviewSummary` for *results*.

    *changed_files* (repo-relative paths) scopes the blocking decision to the change
    under review; ``None`` disables scoping (full-repo gate). See module docstring.

    *semgrep_min_severity* is the configured severity floor (default "medium",
    see ``repo_config.RepoConfig.semgrep_min_severity``): a below-floor semgrep
    finding never moves security_score/quality_score, though it is still
    counted (as a note) and rendered separately (see
    ``renderer.render_comment``). Below-floor findings are never error-level
    (critical/high), so they never affect blocking_count/verdict either way.
    """
    from caliper.core.renderer import calculate_quality_score, calculate_severity_score

    scored_results, _below_floor = split_below_floor_semgrep_findings(results, semgrep_min_severity)

    changed = {_norm(f) for f in changed_files} if changed_files is not None else None

    errors = warnings = notes = crashed = skipped = blocking = 0
    for r in results:
        if getattr(r, "error", None):
            crashed += 1
            continue
        if _status_of(r) == "skipped":
            skipped += 1
        is_security = str(getattr(r, "category", "") or "") in SECURITY_CATEGORIES
        for finding in getattr(r, "findings", []):
            level = level_for(finding_get(finding, "severity"))
            if level == "error":
                errors += 1
            elif level == "warning":
                warnings += 1
            else:
                notes += 1
            if level == "error" and is_security:
                file = finding_get(finding, "file")
                attributable = changed is None or (bool(file) and _norm(file) in changed)
                if attributable:
                    blocking += 1

    if blocking > 0:
        verdict = ReviewVerdict.blocked
    elif crashed > 0:
        verdict = ReviewVerdict.incomplete
    elif errors > 0 or warnings > 0:
        # Advisory findings (incl. non-attributable security ones) — worth noting,
        # not blocking. Skipped plugins are informational only (skipped_count) and
        # never downgrade the verdict on their own.
        verdict = ReviewVerdict.warnings
    else:
        verdict = ReviewVerdict.clear

    return ReviewSummary(
        verdict=verdict,
        error_count=errors,
        warning_count=warnings,
        note_count=notes,
        crashed_count=crashed,
        skipped_count=skipped,
        blocking_count=blocking,
        security_score=calculate_severity_score(scored_results),
        quality_score=calculate_quality_score(scored_results),
    )


def maintainability_grade_for(quality_score: float) -> str:
    """Derive the maintainability grade from *quality_score* — the one shared
    function that decides the grade, so it can never disagree with the score
    (the grade used to be computed independently from per-finding
    ``maintainability_index`` strings, which could yield "A" even when the
    weighted quality_score had collapsed to 0).
    """
    if quality_score >= 80:
        return "A"
    if quality_score >= 50:
        return "B"
    return "C"


def _incomplete_reason(result: object) -> str | None:
    """Return why *result*'s plugin did not complete, or ``None`` if it did."""
    if getattr(result, "error", None):
        return "crashed"
    status = _status_of(result)
    if status in ("timeout", "not_installed"):
        return status
    return None


def _verdict_text_for(
    base_verdict: ReviewVerdict,
    *,
    policy_verdict: str | None,
    incomplete_plugins: list[tuple[str, str]],
) -> str:
    """Compose the human-readable verdict sentence.

    "incomplete" only appears when plugins actually failed to complete.
    "blocked" only appears when the *policy* verdict is an actual reject —
    never merely because findings exist (that's what error_count/warning_count
    are for; a scan can surface high-severity findings and still not be
    policy-rejected, e.g. dev-scope exemptions).
    """
    if incomplete_plugins:
        names = ", ".join(f"{name} ({reason})" for name, reason in incomplete_plugins)
        return f"Review incomplete: {len(incomplete_plugins)} plugin(s) did not complete ({names})"
    if policy_verdict == "reject":
        return "Review blocked by policy"
    return {
        ReviewVerdict.blocked: "Review has blocking findings",
        ReviewVerdict.incomplete: "Review incomplete",
        ReviewVerdict.warnings: "Review has warnings",
        ReviewVerdict.clear: "Review clear",
    }.get(base_verdict, str(base_verdict))


def build_review_summary(
    results: list,
    *,
    changed_files: set[str] | None = None,
    policy_verdict: str | None = None,
    semgrep_min_severity: str = "medium",
) -> ReviewSummary:
    """Compute the full :class:`ReviewSummary`, including the maintainability
    grade, human-readable verdict text, and incomplete-plugin accounting.

    Builds on :func:`summarize_review` (verdict/counts/scores) and adds the
    fields that used to be computed independently elsewhere and could drift:
    ``maintainability_grade`` (always derived from ``quality_score`` via
    :func:`maintainability_grade_for`), ``verdict_text`` (only says "blocked"
    for an actual policy reject), and ``incomplete_plugins`` (plugins that
    timed out, were not installed, or crashed).
    """
    base = summarize_review(
        results, changed_files=changed_files, semgrep_min_severity=semgrep_min_severity
    )

    incomplete_plugins: list[tuple[str, str]] = []
    for r in results:
        reason = _incomplete_reason(r)
        if reason is not None:
            incomplete_plugins.append((r.plugin_name, reason))

    grade = maintainability_grade_for(base.quality_score)
    verdict_text = _verdict_text_for(
        base.verdict,
        policy_verdict=policy_verdict,
        incomplete_plugins=incomplete_plugins,
    )

    return base.model_copy(
        update={
            "maintainability_grade": grade,
            "verdict_text": verdict_text,
            "incomplete_plugins": incomplete_plugins,
        }
    )
