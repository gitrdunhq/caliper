"""CodeGraphEnricher — attaches blast radius + enclosing symbol from the code graph (ADR-006).
# tested-by: tests/unit/plugins/test_code_graph_enricher.py

For a code finding (``.py``/``.ts``/``.js`` family), resolve the enclosing symbol via the
SQLite ``CodeGraph`` and walk its upstream callers (``blast_radius``) so a consumer sees
"who breaks if this changes" without re-deriving it. The graph is the same one the
``blast-radius`` plugin builds; this enricher builds it **once per run** and caches it on
the instance (the enrichment pass is sequential, so no locking is needed).

Deterministic, zero-LLM, fail-open: any error (missing graph, unindexed file) yields the
finding unchanged. The graph build is the one cost — already paid by the blast-radius
plugin — and the whole pass is time-bounded by ``EnrichmentContext.enrichment_timeout``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from eedom.core.enrichment import merge_enrichment
from eedom.core.plugin import finding_get
from eedom.core.registries import ENRICHERS
from eedom.plugins._runners.graph_builder import CodeGraph, resolve_graph_db_path

if TYPE_CHECKING:
    from eedom.core.enrichment import EnrichmentContext
    from eedom.core.plugin import PluginFinding

logger = structlog.get_logger(__name__)

_CODE_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx"}
_MAX_CALLERS = 25  # cap the attached blast radius so enrichment stays bounded


@ENRICHERS.register("code_graph")
class CodeGraphEnricher:
    """Attach enclosing symbol + upstream blast radius from the SQLite code graph."""

    name = "code_graph"

    def __init__(self) -> None:
        self._graph: CodeGraph | None = None
        self._graph_repo: str | None = None

    def applies_to(self, finding: PluginFinding) -> bool:
        file = finding_get(finding, "file")
        line = finding_get(finding, "line")
        return (
            bool(file)
            and Path(str(file)).suffix in _CODE_EXTS
            and isinstance(line, int)
            and line > 0
        )

    def _resolve_graph(self, repo_path: str) -> CodeGraph | None:
        """Build (once) or reuse the cached code graph for *repo_path* (fail-open)."""
        if self._graph is not None and self._graph_repo == repo_path:
            return self._graph
        try:
            db_path = str(resolve_graph_db_path(repo_path))
            graph = CodeGraph(db_path=db_path, repo_root=Path(repo_path))
            if graph.stats()["symbols"] == 0:
                graph.index_directory(Path(repo_path))
            self._graph = graph
            self._graph_repo = repo_path
        except Exception:
            logger.exception("enrich.code_graph.build_failed", repo=repo_path)
            return None
        return self._graph

    def enrich(self, finding: PluginFinding, ctx: EnrichmentContext) -> PluginFinding:
        graph = self._resolve_graph(ctx.repo_path)
        if graph is None:
            return finding
        file = str(finding_get(finding, "file"))
        line = int(finding_get(finding, "line"))
        rel = file
        abs_path = Path(file)
        if abs_path.is_absolute():
            try:
                rel = str(abs_path.resolve().relative_to(Path(ctx.repo_path).resolve()))
            except ValueError:
                return finding  # outside the repo — nothing the graph can say
        symbol = graph.symbol_at(rel, line)
        if not symbol or not symbol.get("name"):
            return finding
        callers = graph.blast_radius(symbol["name"])[:_MAX_CALLERS]
        return merge_enrichment(
            finding,
            source=self.name,
            enclosing_symbol=symbol["name"],
            enclosing_kind=symbol.get("kind", ""),
            blast_radius=callers,
            blast_radius_count=len(callers),
        )
