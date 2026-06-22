"""EnclosingSymbolScribe — maps a finding location to its function/class (ADR-006).
# tested-by: tests/unit/detectors/test_enclosing_symbol_scribe.py

The cheapest scribe: for any finding that carries a ``file`` + ``line``, read the
source and attach the innermost enclosing symbol via the canonical
``core.scribe.enclosing_symbol`` resolver (one source of truth, shared with the
cpd runner). Pure stdlib, no subprocess, sub-millisecond — deterministic, zero-LLM,
and fail-open by construction (an unreadable file yields no scribe, never an error).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from caliper.core.plugin import finding_get
from caliper.core.registries import SCRIBES
from caliper.core.scribe import enclosing_symbol, merge_scribe

if TYPE_CHECKING:
    from caliper.core.plugin import PluginFinding
    from caliper.core.scribe import ScribeContext


@SCRIBES.register("enclosing_symbol")
class EnclosingSymbolScribe:
    """Attach the innermost function/class enclosing a finding's ``file``:``line``."""

    name = "enclosing_symbol"

    def applies_to(self, finding: PluginFinding) -> bool:
        """Applies to any finding anchored to a concrete file location."""
        file = finding_get(finding, "file")
        line = finding_get(finding, "line")
        return bool(file) and isinstance(line, int) and line > 0

    def scribe(self, finding: PluginFinding, ctx: ScribeContext) -> PluginFinding:
        file = finding_get(finding, "file")
        line = finding_get(finding, "line")
        abs_path = Path(file)
        if not abs_path.is_absolute():
            abs_path = Path(ctx.repo_path) / file
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return finding  # fail-open: no source, no scribe
        name, kind = enclosing_symbol(text, line, is_python=str(file).endswith(".py"))
        if not name:
            return finding
        return merge_scribe(
            finding,
            source=self.name,
            enclosing_symbol=name,
            enclosing_kind=kind,
        )
