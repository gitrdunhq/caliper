"""GroundingScribe — cross-file symbol/contract context via GroundingProviderPort (#481).
# tested-by: tests/unit/plugins/test_grounding_scribe.py

The grounding providers (adapters/grounding.py — codegraph/ctags/gitnexus/null) already
exist and are gated behind ``grounding_enabled``, but their only consumer was the
standalone ``caliper ground`` export. This scribe gives them an on-thesis consumer:
attaching the same cross-file context to every finding that a human reviewer would pull
up manually — symbols the finding's file defines, and type-like symbols it references but
that are defined elsewhere (the "contracts" whose absence causes most false positives).

Deterministic, zero-LLM, fail-open: any provider error yields an empty (but present)
packet rather than dropping the finding. Memoized per file within one scribe instance (one
review run) so a file with many findings only calls the provider once.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from caliper.core.plugin import finding_get
from caliper.core.port_registries import SCRIBES
from caliper.core.scribe import merge_scribe

if TYPE_CHECKING:
    from caliper.core.plugin import PluginFinding
    from caliper.core.ports import GroundingProviderPort
    from caliper.core.scribe import ScribeContext

logger = structlog.get_logger(__name__)

_DEFAULT_MAX_SYMBOLS = 40


@SCRIBES.register("grounding")
class GroundingScribe:
    """Attach defined-symbols + referenced-contracts context from a GroundingProviderPort."""

    name = "grounding"

    def __init__(
        self,
        provider: GroundingProviderPort,
        *,
        max_symbols: int = _DEFAULT_MAX_SYMBOLS,
    ) -> None:
        self._provider = provider
        self._max_symbols = max_symbols
        self._memo: dict[str, dict] = {}

    def applies_to(self, finding: PluginFinding) -> bool:
        return bool(finding_get(finding, "file"))

    def _bundle(self, root: str, file: str) -> dict:
        if file in self._memo:
            return self._memo[file]
        try:
            defined = self._provider.fact_sheet(Path(root), [file])[: self._max_symbols]
            contracts = self._provider.type_context(Path(root), [file])[: self._max_symbols]
            bundle = {
                "defined": [
                    {"name": d.get("name"), "kind": d.get("kind"), "line": d.get("line")}
                    for d in defined
                ],
                "contracts": [
                    {"name": c.get("name"), "defined_in": c.get("file")} for c in contracts
                ],
                "provider": self._provider.name,
            }
        except Exception:
            logger.warning("scribe.grounding.provider_failed", file=file)
            bundle = {"defined": [], "contracts": [], "provider": self._provider.name}
        self._memo[file] = bundle
        return bundle

    def scribe(self, finding: PluginFinding, ctx: ScribeContext) -> PluginFinding:
        file = str(finding_get(finding, "file") or "")
        if not file:
            return finding
        bundle = self._bundle(ctx.repo_path, file)
        return merge_scribe(finding, source=self.name, grounding=bundle)
