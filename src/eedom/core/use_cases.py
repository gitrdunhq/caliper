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

from eedom.core.plugin import finding_get

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


def _derive_verdict(results: list) -> str:
    """Derive a verdict string from a list of PluginResult objects.

    Priority: blocked > warnings > incomplete > clear.
    """
    verdict = "clear"
    for r in results:
        if getattr(r, "error", None):
            if verdict == "clear":
                verdict = "incomplete"
            continue
        findings = getattr(r, "findings", [])
        category = getattr(r, "category", "")
        has_crit = any(finding_get(f, "severity") in ("critical", "high") for f in findings)
        is_security = category in {"dependency", "supply_chain", "infra"}
        if has_crit and is_security:
            verdict = "blocked"
        elif findings and verdict != "blocked":
            verdict = "warnings"
    return verdict


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
) -> ReviewResult:
    """Run all matching plugins and return a structured ReviewResult.

    Delegates execution to ``context.analyzer_registry.run_all()``.
    Scores and verdict are derived from the aggregated plugin results.

    When *repo_files* is provided (diff mode), code/quality plugins receive
    *files* (diff-scoped) while dependency/infra/supply_chain plugins receive
    *repo_files* (full repo).
    """
    from eedom.core.renderer import calculate_quality_score, calculate_severity_score

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

    verdict = _derive_verdict(plugin_results)
    security_score = calculate_severity_score(plugin_results)
    quality_score = calculate_quality_score(plugin_results)

    return ReviewResult(
        results=plugin_results,
        verdict=verdict,
        security_score=security_score,
        quality_score=quality_score,
    )
