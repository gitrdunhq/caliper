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

from enum import StrEnum

from caliper._base import Contract
from caliper.core.plugin import finding_get

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


def level_for(severity: object) -> str:
    """Return the SARIF-style level ("error"/"warning"/"note") for a severity."""
    return SEVERITY_TO_LEVEL.get(str(severity or "").lower(), "note")


def _norm(path: object) -> str:
    """Normalize a path for changed-file membership tests."""
    return str(path or "").lstrip("./")


def summarize_review(
    results: list,
    *,
    changed_files: set[str] | None = None,
) -> ReviewSummary:
    """Compute the canonical :class:`ReviewSummary` for *results*.

    *changed_files* (repo-relative paths) scopes the blocking decision to the change
    under review; ``None`` disables scoping (full-repo gate). See module docstring.
    """
    from caliper.core.renderer import calculate_quality_score, calculate_severity_score

    changed = {_norm(f) for f in changed_files} if changed_files is not None else None

    errors = warnings = notes = crashed = skipped = blocking = 0
    for r in results:
        if getattr(r, "error", None):
            crashed += 1
            continue
        if (getattr(r, "summary", {}) or {}).get("status") == "skipped":
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
        security_score=calculate_severity_score(results),
        quality_score=calculate_quality_score(results),
    )
