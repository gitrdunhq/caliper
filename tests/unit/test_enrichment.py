"""Detect-then-enrich core seam (ADR-006).
# tested-by: tests/unit/test_enrichment.py

DPS-12 domains exercised: Determinism (same input -> same enrichment), Availability
(fail-open: an enricher raising never drops a finding), Boundedness (the pass respects
the enrichment budget).
"""

from __future__ import annotations

from eedom.core.enrich import enrich_findings
from eedom.core.enrichment import Enrichment, EnrichmentContext, enclosing_symbol
from eedom.core.plugin import PluginFinding

_PY = (
    "def alpha():\n    x = 1\n    return x\n\nclass Beta:\n    def gamma(self):\n        return 2\n"
)


def test_enclosing_symbol_python_is_innermost_and_authoritative() -> None:
    assert enclosing_symbol(_PY, 2, is_python=True) == ("alpha", "function")
    assert enclosing_symbol(_PY, 7, is_python=True) == ("gamma", "function")
    assert enclosing_symbol(_PY, 5, is_python=True) == ("Beta", "class")
    assert enclosing_symbol(_PY, 99, is_python=True) == ("", "")  # module-level, not "scan upward"


def test_enclosing_symbol_generic_languages() -> None:
    assert enclosing_symbol("func helper() {\n  return 1\n}\n", 2, is_python=False) == (
        "helper",
        "function",
    )
    assert enclosing_symbol("class Foo:\n  pass\n", 2, is_python=False) == ("Foo", "class")


def test_enrichment_model_defaults_serialize() -> None:
    e = Enrichment(enclosing_symbol="scan", enclosing_kind="function", sources=("x",))
    dumped = e.model_dump()
    assert dumped["enclosing_symbol"] == "scan" and dumped["sources"] == ("x",)


def _finding(**kw) -> PluginFinding:
    base = {"id": "x", "severity": "info", "message": "m", "file": "a.py", "line": 1}
    base.update(kw)
    return PluginFinding(**base)


class _Tagger:
    name = "tagger"

    def applies_to(self, finding: PluginFinding) -> bool:
        return True

    def enrich(self, finding: PluginFinding, ctx: EnrichmentContext) -> PluginFinding:
        md = dict(finding.metadata)
        md["enrichment"] = {"sources": ["tagger"]}
        return finding.model_copy(update={"metadata": md})


class _Boom:
    name = "boom"

    def applies_to(self, finding: PluginFinding) -> bool:
        return True

    def enrich(self, finding: PluginFinding, ctx: EnrichmentContext) -> PluginFinding:
        raise RuntimeError("enricher exploded")


def test_enrich_applies_and_is_deterministic() -> None:
    ctx = EnrichmentContext(repo_path=".")
    f = _finding()
    out1 = enrich_findings([f], [_Tagger()], ctx)
    out2 = enrich_findings([f], [_Tagger()], ctx)
    assert out1[0].metadata["enrichment"]["sources"] == ["tagger"]
    assert out1[0].to_dict() == out2[0].to_dict()  # Determinism


def test_enrich_is_fail_open() -> None:
    ctx = EnrichmentContext(repo_path=".")
    f = _finding()
    out = enrich_findings([f], [_Boom()], ctx)
    assert out[0] == f  # Availability: finding survives an exploding enricher, unchanged


def test_enrich_respects_budget() -> None:
    ctx = EnrichmentContext(repo_path=".", enrichment_timeout=-1.0)  # deadline already passed
    out = enrich_findings([_finding()], [_Tagger()], ctx)
    assert "enrichment" not in out[0].metadata  # Boundedness: nothing runs past budget
