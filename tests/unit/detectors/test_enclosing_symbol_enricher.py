"""EnclosingSymbolEnricher (detect-then-enrich, ADR-006).
# tested-by: tests/unit/detectors/test_enclosing_symbol_enricher.py

DPS-12 domains: Determinism (same file+finding -> same enrichment), Availability
(fail-open: unreadable source never drops the finding), Integrity (enrichment only
adds metadata; severity/message untouched).
"""

from __future__ import annotations

from eedom.core.enrichment import EnrichmentContext
from eedom.core.plugin import PluginFinding
from eedom.detectors.enrichers.enclosing_symbol import EnclosingSymbolEnricher

_SRC = (
    "def alpha():\n    x = 1\n    return x\n\nclass Beta:\n    def gamma(self):\n        return 2\n"
)


def _finding(**kw) -> PluginFinding:
    base = {"id": "x", "severity": "info", "message": "m", "file": "a.py", "line": 2}
    base.update(kw)
    return PluginFinding(**base)


def test_applies_only_to_located_findings() -> None:
    e = EnclosingSymbolEnricher()
    assert e.applies_to(_finding(file="a.py", line=2)) is True
    assert e.applies_to(_finding(file="", line=2)) is False
    assert e.applies_to(_finding(file="a.py", line=0)) is False


def test_attaches_innermost_symbol(tmp_path) -> None:
    (tmp_path / "a.py").write_text(_SRC)
    e = EnclosingSymbolEnricher()
    ctx = EnrichmentContext(repo_path=str(tmp_path))
    out = e.enrich(_finding(file="a.py", line=7), ctx)
    enr = out.metadata["enrichment"]
    assert enr["enclosing_symbol"] == "gamma"
    assert enr["enclosing_kind"] == "function"
    assert "enclosing_symbol" in enr["sources"]


def test_is_deterministic(tmp_path) -> None:
    (tmp_path / "a.py").write_text(_SRC)
    e = EnclosingSymbolEnricher()
    ctx = EnrichmentContext(repo_path=str(tmp_path))
    f = _finding(file="a.py", line=2)
    assert e.enrich(f, ctx).to_dict() == e.enrich(f, ctx).to_dict()  # Determinism


def test_missing_file_is_fail_open(tmp_path) -> None:
    e = EnclosingSymbolEnricher()
    ctx = EnrichmentContext(repo_path=str(tmp_path))
    f = _finding(file="nope.py", line=2)
    assert e.enrich(f, ctx) == f  # Availability: finding survives unchanged


def test_enriches_dict_findings(tmp_path) -> None:
    (tmp_path / "a.py").write_text(_SRC)
    e = EnclosingSymbolEnricher()
    ctx = EnrichmentContext(repo_path=str(tmp_path))
    out = e.enrich({"file": "a.py", "line": 2, "severity": "info"}, ctx)
    assert out["metadata"]["enrichment"]["enclosing_symbol"] == "alpha"
    assert out["severity"] == "info"  # Integrity: original fields preserved
