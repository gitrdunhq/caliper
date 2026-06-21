"""SemgrepEnricher — attaches nearby static-analysis rule matches (detect-then-enrich, ADR-006).
# tested-by: tests/unit/plugins/test_semgrep_enricher.py

Opt-in (off by default — each scanned file is a subprocess, ~100-200ms): when enabled it
runs opengrep over a finding's single file and attaches the rule matches *near* the finding
location as ``metadata['enrichment']['related']``, so a consumer sees "what else the static
analyzer flagged right here" without a second tool invocation. Results are cached per file
within a run, deterministic given the same rules+file, and fail-open: any error (tool missing,
timeout, parse failure) yields the finding unchanged. Reuses the canonical opengrep runner so
ruleset selection / exclusion semantics stay in one place.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from eedom.core.enrichment import merge_enrichment
from eedom.core.plugin import finding_get
from eedom.core.registries import ENRICHERS
from eedom.plugins._runners.semgrep_runner import (
    _EXT_TO_RULESETS,
    _NAME_TO_RULESETS,
    run_semgrep,
)

if TYPE_CHECKING:
    from eedom.core.enrichment import EnrichmentContext
    from eedom.core.plugin import PluginFinding

logger = structlog.get_logger(__name__)

_LINE_WINDOW = 25  # a match within this many lines of the finding counts as "related"
_MAX_RELATED = 10  # cap the attached matches so enrichment stays bounded
_DEFAULT_TIMEOUT = 15  # per-file opengrep budget (seconds)


def _supported(file: str) -> bool:
    return Path(file).suffix in _EXT_TO_RULESETS or Path(file).name in _NAME_TO_RULESETS


@ENRICHERS.register("semgrep")
class SemgrepEnricher:
    """Attach opengrep rule matches near a finding's location (opt-in, budgeted)."""

    name = "semgrep"

    def __init__(self, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._cache: dict[tuple[str, str], list[dict]] = {}  # (repo, file) -> results

    def applies_to(self, finding: PluginFinding) -> bool:
        file = finding_get(finding, "file")
        line = finding_get(finding, "line")
        return bool(file) and _supported(str(file)) and isinstance(line, int) and line > 0

    def _matches_for(self, repo_path: str, rel_file: str) -> list[dict]:
        """Run (once, cached) opengrep over a single file; fail-open to []."""
        key = (repo_path, rel_file)
        if key in self._cache:
            return self._cache[key]
        try:
            data = run_semgrep([rel_file], repo_path, timeout=self._timeout)
            results = data.get("results") or []
        except Exception:
            logger.exception("enrich.semgrep.run_failed", file=rel_file)
            results = []
        self._cache[key] = results
        return results

    def enrich(self, finding: PluginFinding, ctx: EnrichmentContext) -> PluginFinding:
        file = str(finding_get(finding, "file"))
        line = int(finding_get(finding, "line"))
        rel = file
        abs_path = Path(file)
        if abs_path.is_absolute():
            try:
                rel = str(abs_path.resolve().relative_to(Path(ctx.repo_path).resolve()))
            except ValueError:
                return finding
        related: list[dict] = []
        for r in self._matches_for(ctx.repo_path, rel):
            start = (r.get("start") or {}).get("line", 0)
            if abs(start - line) > _LINE_WINDOW:
                continue
            related.append(
                {
                    "check_id": r.get("check_id", ""),
                    "line": start,
                    "message": ((r.get("extra") or {}).get("message") or "").strip(),
                    "severity": (r.get("extra") or {}).get("severity", ""),
                }
            )
        related.sort(key=lambda m: (m["line"], m["check_id"]))
        if not related:
            return finding
        return merge_enrichment(finding, source=self.name, related=related[:_MAX_RELATED])
