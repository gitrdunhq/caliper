"""The detect-then-enrich pass (ADR-006).

A sequential post-aggregation pass: after detection, each finding is run through the
applicable enrichers, which attach deterministic context to ``metadata['enrichment']``.
Sequential (not in the plugin ThreadPool) so shared tool state — e.g. the CodeGraph —
is built once and read without locks. The pass is **fail-open** (an enricher raising
never drops a finding) and **time-bounded** (an ``enrichment_timeout`` budget), so the
verdict never depends on enrichment.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from eedom.core.enrichment import EnrichmentContext
    from eedom.core.plugin import PluginFinding
    from eedom.core.ports import EnricherPort

logger = structlog.get_logger(__name__)


def enrich_findings(
    findings: list[PluginFinding],
    enrichers: list[EnricherPort],
    ctx: EnrichmentContext,
) -> list[PluginFinding]:
    """Return *findings* with enrichment applied. Pure post-detection; verdict-independent."""
    if not findings or not enrichers:
        return findings
    deadline = time.monotonic() + ctx.enrichment_timeout
    enriched: list[PluginFinding] = []
    for finding in findings:
        current = finding
        for enricher in enrichers:
            if time.monotonic() > deadline:
                logger.warning("enrich.budget_exhausted", enricher=getattr(enricher, "name", "?"))
                break
            try:
                if enricher.applies_to(current):
                    current = enricher.enrich(current, ctx)
            except Exception:  # fail-open: enrichment must never drop a finding or break the gate
                logger.exception("enrich.failed", enricher=getattr(enricher, "name", "?"))
        enriched.append(current)
    return enriched
