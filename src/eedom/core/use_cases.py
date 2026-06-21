# tested-by: tests/unit/test_use_cases.py
"""ReviewUseCase — thin orchestration layer over the plugin pipeline.

Three public symbols:
  - ReviewOptions — scan filter parameters
  - ReviewResult  — structured outcome of a repository review
  - review_repository(context, files, repo_path, options) -> ReviewResult
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from eedom.core.review_summary import ReviewSummary, summarize_review

if TYPE_CHECKING:
    from eedom.core.context import ApplicationContext


class ScanScope(StrEnum):
    REPO = "repo"
    DIFF = "diff"
    FOLDER = "folder"


@dataclasses.dataclass
class ReviewOptions:
    """Filtering parameters for a repository review run."""

    scanners: list[str] | None = None
    categories: list | None = None
    disabled: set[str] = dataclasses.field(default_factory=set)
    enabled: set[str] = dataclasses.field(default_factory=set)
    scope: ScanScope = ScanScope.REPO


@dataclasses.dataclass
class ReviewResult:
    """Structured outcome of a repository review run."""

    results: list
    verdict: str
    security_score: float
    quality_score: float
    summary: ReviewSummary | None = None


def _derive_verdict(results: list) -> str:
    """Repo-wide verdict string (thin shim over the canonical summarizer, SoT).

    Kept for back-compat; the canonical computation lives in
    ``eedom.core.review_summary.summarize_review``.
    """
    from eedom.core.review_summary import summarize_review

    return summarize_review(results).verdict.value


def _enrich_results(context: ApplicationContext, results: list, repo_path: Path) -> list:
    """Run the detect-then-enrich pass over every plugin's findings (ADR-006).

    A post-detection, verdict-independent pass: each finding is decorated with
    deterministic context (enclosing symbol, code-graph blast radius) in its
    ``metadata['enrichment']``. Fail-open and time-bounded — enrichment can never
    change a verdict or drop a finding, so this runs *after* detection and before
    scoring. A no-op when no enrichers are wired.
    """
    from eedom.core.accessors import get_enrichers
    from eedom.core.enrich import enrich_findings
    from eedom.core.enrichment import EnrichmentContext

    enrichers = get_enrichers(context)
    if not enrichers:
        return results
    ctx = EnrichmentContext(repo_path=str(repo_path))
    enriched: list = []
    for result in results:
        findings = getattr(result, "findings", None)
        if findings:
            new = enrich_findings(list(findings), enrichers, ctx)
            enriched.append(dataclasses.replace(result, findings=new))
        else:
            enriched.append(result)
    return enriched


def review_repository(
    context: ApplicationContext,
    files: list,
    repo_path: Path,
    options: ReviewOptions,
    repo_files: list | None = None,
    changed_files: set[str] | None = None,
) -> ReviewResult:
    """Run all matching plugins and return a structured ReviewResult.

    Delegates execution to ``context.analyzer_registry.run_all()``. The verdict,
    counts, and scores come from the single source of truth
    (``review_summary.summarize_review``) so every output agrees.

    When *repo_files* is provided (diff mode), code/quality plugins receive
    *files* (diff-scoped) while dependency/infra/supply_chain plugins receive
    *repo_files* (full repo). *changed_files* scopes the **blocking** decision to
    the change under review (``None`` = full-repo gate); see ``summarize_review``.
    """
    plugin_results = context.analyzer_registry.run_all(
        files,
        repo_path,
        names=options.scanners,
        categories=options.categories,
        disabled_names=options.disabled,
        enabled_names=options.enabled,
        repo_files=repo_files,
    )

    plugin_results = _enrich_results(context, plugin_results, repo_path)

    summary = summarize_review(plugin_results, changed_files=changed_files)

    return ReviewResult(
        results=plugin_results,
        verdict=summary.verdict.value,
        security_score=summary.security_score,
        quality_score=summary.quality_score,
        summary=summary,
    )
