"""CodeGraphScribe (detect-then-scribe, ADR-006).
# tested-by: tests/unit/plugins/test_code_graph_scribe.py

DPS-12 domains: Determinism (same repo+finding -> same scribe), Availability
(fail-open: an unbuildable/empty graph never drops the finding), Boundedness (the
attached blast radius is capped).
"""

from __future__ import annotations

from caliper.core.plugin import PluginFinding
from caliper.core.scribe import ScribeContext
from caliper.plugins.scribes.code_graph import CodeGraphScribe

_SRC = "def helper():\n    return 1\n\n\ndef caller():\n    return helper()\n"


def _finding(**kw) -> PluginFinding:
    base = {"id": "x", "severity": "info", "message": "m", "file": "a.py", "line": 2}
    base.update(kw)
    return PluginFinding(**base)


def _repo(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text(_SRC)
    monkeypatch.setenv("CALIPER_GRAPH_DB", str(tmp_path / "graph.db"))
    return ScribeContext(repo_path=str(tmp_path))


def test_applies_only_to_code_findings() -> None:
    e = CodeGraphScribe()
    assert e.applies_to(_finding(file="a.py", line=2)) is True
    assert e.applies_to(_finding(file="README.md", line=2)) is False
    assert e.applies_to(_finding(file="a.py", line=0)) is False


def test_attaches_symbol_and_blast_radius(tmp_path, monkeypatch) -> None:
    ctx = _repo(tmp_path, monkeypatch)
    out = CodeGraphScribe().scribe(_finding(file="a.py", line=2), ctx)
    enr = out.metadata["scribe"]
    assert enr["enclosing_symbol"] == "helper"
    assert "blast_radius" in enr and "blast_radius_count" in enr
    assert any(c.get("name") == "caller" for c in enr["blast_radius"])  # upstream caller found
    assert "code_graph" in enr["sources"]


def test_is_deterministic(tmp_path, monkeypatch) -> None:
    ctx = _repo(tmp_path, monkeypatch)
    e = CodeGraphScribe()
    f = _finding(file="a.py", line=2)
    assert e.scribe(f, ctx).to_dict() == e.scribe(f, ctx).to_dict()  # Determinism (cached graph)


def test_unindexable_repo_is_fail_open(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CALIPER_GRAPH_DB", str(tmp_path / "graph.db"))
    ctx = ScribeContext(repo_path=str(tmp_path))  # empty repo, no symbols
    f = _finding(file="a.py", line=2)
    assert CodeGraphScribe().scribe(f, ctx) == f  # Availability: survives unchanged
