"""Detect-then-scribe core seam (ADR-006).
# tested-by: tests/unit/test_scribe.py

DPS-12 domains exercised: Determinism (same input -> same scribe), Availability
(fail-open: a scribe raising never drops a finding), Boundedness (the pass respects
the scribe budget).
"""

from __future__ import annotations

from caliper.core.plugin import PluginFinding
from caliper.core.scribe import ScribeContext, ScribeNote, enclosing_symbol
from caliper.core.scribe_pass import scribe_findings

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


def test_scribe_model_defaults_serialize() -> None:
    e = ScribeNote(enclosing_symbol="scan", enclosing_kind="function", sources=("x",))
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

    def scribe(self, finding: PluginFinding, ctx: ScribeContext) -> PluginFinding:
        md = dict(finding.metadata)
        md["scribe"] = {"sources": ["tagger"]}
        return finding.model_copy(update={"metadata": md})


class _Boom:
    name = "boom"

    def applies_to(self, finding: PluginFinding) -> bool:
        return True

    def scribe(self, finding: PluginFinding, ctx: ScribeContext) -> PluginFinding:
        raise RuntimeError("scribe exploded")


def test_scribe_applies_and_is_deterministic() -> None:
    ctx = ScribeContext(repo_path=".")
    f = _finding()
    out1 = scribe_findings([f], [_Tagger()], ctx)
    out2 = scribe_findings([f], [_Tagger()], ctx)
    assert out1[0].metadata["scribe"]["sources"] == ["tagger"]
    assert out1[0].to_dict() == out2[0].to_dict()  # Determinism


def test_scribe_is_fail_open() -> None:
    ctx = ScribeContext(repo_path=".")
    f = _finding()
    out = scribe_findings([f], [_Boom()], ctx)
    assert out[0] == f  # Availability: finding survives an exploding scribe, unchanged


def test_scribe_respects_budget() -> None:
    ctx = ScribeContext(repo_path=".", scribe_timeout=-1.0)  # deadline already passed
    out = scribe_findings([_finding()], [_Tagger()], ctx)
    assert "scribe" not in out[0].metadata  # Boundedness: nothing runs past budget
