"""The detect-then-scribe pass (ADR-006).

A sequential post-aggregation pass: after detection, each finding is run through the
applicable scribes, which attach deterministic context to ``metadata['scribe']``.
Sequential (not in the plugin ThreadPool) so shared tool state — e.g. the CodeGraph —
is built once and read without locks. The pass is **fail-open** (an scribe raising
never drops a finding) and **time-bounded** (an ``scribe_timeout`` budget), so the
verdict never depends on scribe.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from caliper.core.plugin import PluginFinding
    from caliper.core.ports import ScribePort
    from caliper.core.scribe import ScribeContext

logger = structlog.get_logger(__name__)


def scribe_findings(
    findings: list[PluginFinding],
    scribes: list[ScribePort],
    ctx: ScribeContext,
) -> list[PluginFinding]:
    """Return *findings* with scribe applied. Pure post-detection; verdict-independent."""
    if not findings or not scribes:
        return findings
    deadline = time.monotonic() + ctx.scribe_timeout
    scribeed: list[PluginFinding] = []
    for finding in findings:
        current = finding
        for scribe in scribes:
            if time.monotonic() > deadline:
                logger.warning("scribe.budget_exhausted", scribe=getattr(scribe, "name", "?"))
                break
            try:
                if scribe.applies_to(current):
                    current = scribe.scribe(current, ctx)
            except Exception:  # fail-open: scribe must never drop a finding or break the gate
                logger.exception("scribe.failed", scribe=getattr(scribe, "name", "?"))
        scribeed.append(current)
    return scribeed
