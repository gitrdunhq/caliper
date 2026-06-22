"""EnclosingSymbolScribe (detect-then-scribe, ADR-006).
# tested-by: tests/unit/detectors/test_enclosing_symbol_scribe.py

DPS-12 domains: Determinism (same file+finding -> same scribe), Availability
(fail-open: unreadable source never drops the finding), Integrity (scribe only
adds metadata; severity/message untouched).
"""

from __future__ import annotations

from caliper.core.plugin import PluginFinding
from caliper.core.scribe import ScribeContext
from caliper.detectors.scribes.enclosing_symbol import EnclosingSymbolScribe

_SRC = (
    "def alpha():\n    x = 1\n    return x\n\nclass Beta:\n    def gamma(self):\n        return 2\n"
)


def _finding(**kw) -> PluginFinding:
    base = {"id": "x", "severity": "info", "message": "m", "file": "a.py", "line": 2}
    base.update(kw)
    return PluginFinding(**base)


def test_applies_only_to_located_findings() -> None:
    e = EnclosingSymbolScribe()
    assert e.applies_to(_finding(file="a.py", line=2)) is True
    assert e.applies_to(_finding(file="", line=2)) is False
    assert e.applies_to(_finding(file="a.py", line=0)) is False


def test_attaches_innermost_symbol(tmp_path) -> None:
    (tmp_path / "a.py").write_text(_SRC)
    e = EnclosingSymbolScribe()
    ctx = ScribeContext(repo_path=str(tmp_path))
    out = e.scribe(_finding(file="a.py", line=7), ctx)
    enr = out.metadata["scribe"]
    assert enr["enclosing_symbol"] == "gamma"
    assert enr["enclosing_kind"] == "function"
    assert "enclosing_symbol" in enr["sources"]


def test_is_deterministic(tmp_path) -> None:
    (tmp_path / "a.py").write_text(_SRC)
    e = EnclosingSymbolScribe()
    ctx = ScribeContext(repo_path=str(tmp_path))
    f = _finding(file="a.py", line=2)
    assert e.scribe(f, ctx).to_dict() == e.scribe(f, ctx).to_dict()  # Determinism


def test_missing_file_is_fail_open(tmp_path) -> None:
    e = EnclosingSymbolScribe()
    ctx = ScribeContext(repo_path=str(tmp_path))
    f = _finding(file="nope.py", line=2)
    assert e.scribe(f, ctx) == f  # Availability: finding survives unchanged


def test_scribees_dict_findings(tmp_path) -> None:
    (tmp_path / "a.py").write_text(_SRC)
    e = EnclosingSymbolScribe()
    ctx = ScribeContext(repo_path=str(tmp_path))
    out = e.scribe({"file": "a.py", "line": 2, "severity": "info"}, ctx)
    assert out["metadata"]["scribe"]["enclosing_symbol"] == "alpha"
    assert out["severity"] == "info"  # Integrity: original fields preserved
