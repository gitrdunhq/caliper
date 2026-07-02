"""ReachabilityScribe — declared-vs-imported vulnerability reachability (ADR-009).
# tested-by: tests/unit/plugins/test_reachability_scribe.py

For a finding tied to a package (``finding.package`` non-empty — the shape every SCA
finding, e.g. osv-scanner, populates), resolve the distribution name to an import name
(``core/import_resolution.resolve_import_name``) and check whether the code graph has
an ``imports`` edge to it (``CodeGraph.imports_module``). Attaches
``metadata['scribe']['reachability'] = {reachable, evidence}``:

- ``reachable=False`` — the import name resolved but no import edge was found anywhere
  in the repo (declared, never imported).
- ``reachable=True`` — an import edge was found.
- ``reachable=None`` — the import name could not be resolved, or the graph is
  unavailable. Never treated as evidence of absence by policy.

Deterministic, zero-LLM, fail-open: any error yields the finding unchanged. Reuses the
same cached-per-run ``CodeGraph`` build pattern as ``CodeGraphScribe``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from caliper.core.import_resolution import resolve_import_name
from caliper.core.plugin import finding_get
from caliper.core.port_registries import SCRIBES
from caliper.core.scribe import merge_scribe
from caliper.plugins._runners.graph_builder import CodeGraph, resolve_graph_db_path

if TYPE_CHECKING:
    from caliper.core.plugin import PluginFinding
    from caliper.core.scribe import ScribeContext

logger = structlog.get_logger(__name__)


@SCRIBES.register("reachability")
class ReachabilityScribe:
    """Attach declared-vs-imported reachability for package-scoped findings."""

    name = "reachability"

    def __init__(self) -> None:
        self._graph: CodeGraph | None = None
        self._graph_repo: str | None = None

    def applies_to(self, finding: PluginFinding) -> bool:
        return bool(finding_get(finding, "package"))

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
            logger.exception("scribe.reachability.build_failed", repo=repo_path)
            return None
        return self._graph

    def scribe(self, finding: PluginFinding, ctx: ScribeContext) -> PluginFinding:
        package = str(finding_get(finding, "package") or "")
        if not package:
            return finding

        import_name = resolve_import_name(package)
        if import_name is None:
            return merge_scribe(
                finding,
                source=self.name,
                reachability={
                    "reachable": None,
                    "evidence": [f"could not resolve an import name for {package!r}"],
                },
            )

        graph = self._resolve_graph(ctx.repo_path)
        if graph is None:
            return merge_scribe(
                finding,
                source=self.name,
                reachability={"reachable": None, "evidence": ["code graph unavailable"]},
            )

        if graph.imports_module(import_name):
            return merge_scribe(
                finding,
                source=self.name,
                reachability={
                    "reachable": True,
                    "evidence": [f"{import_name!r} is imported in the repo"],
                },
            )
        return merge_scribe(
            finding,
            source=self.name,
            reachability={
                "reachable": False,
                "evidence": [f"{package!r} declared but {import_name!r} is never imported"],
            },
        )
