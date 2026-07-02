"""ReachabilityScribe (detect-then-scribe, ADR-006/ADR-009).
# tested-by: tests/unit/plugins/test_reachability_scribe.py

DPS-12 domains: Determinism (same repo+finding -> same scribe), Availability
(fail-open: an unresolvable package or unbuildable graph never drops the finding),
SAFETY (an unresolved import name or missing graph is `reachable=None`, never
misreported as `False` -- absence of evidence is not evidence of absence).
"""

from __future__ import annotations

from caliper.core.plugin import PluginFinding
from caliper.core.scribe import ScribeContext
from caliper.plugins.scribes.reachability import ReachabilityScribe


def _finding(**kw) -> PluginFinding:
    base = {"id": "x", "severity": "high", "message": "m", "package": "PyYAML", "version": "5.4"}
    base.update(kw)
    return PluginFinding(**base)


def _repo(tmp_path, monkeypatch, source: str = "import yaml\n\ndef f():\n    return yaml\n"):
    (tmp_path / "a.py").write_text(source)
    monkeypatch.setenv("CALIPER_GRAPH_DB", str(tmp_path / "graph.db"))
    return ScribeContext(repo_path=str(tmp_path))


def test_applies_only_to_package_scoped_findings() -> None:
    e = ReachabilityScribe()
    assert e.applies_to(_finding(package="PyYAML")) is True
    assert e.applies_to(_finding(package="")) is False


def test_reachable_when_import_found(tmp_path, monkeypatch) -> None:
    ctx = _repo(tmp_path, monkeypatch)
    out = ReachabilityScribe().scribe(_finding(), ctx)
    enr = out.metadata["scribe"]["reachability"]
    assert enr["reachable"] is True
    assert "reachability" in out.metadata["scribe"]


def test_unreachable_when_declared_but_never_imported(tmp_path, monkeypatch) -> None:
    ctx = _repo(tmp_path, monkeypatch, source="def f():\n    return 1\n")
    out = ReachabilityScribe().scribe(_finding(), ctx)
    enr = out.metadata["scribe"]["reachability"]
    assert enr["reachable"] is False


def test_unresolvable_import_name_yields_none_never_false(tmp_path, monkeypatch) -> None:
    """SAFETY: a package name that can't be mapped to an import name must never
    be reported as reachable=False -- that would be a false 'unreachable' claim."""
    ctx = _repo(tmp_path, monkeypatch)
    out = ReachabilityScribe().scribe(_finding(package="123-not-an-identifier"), ctx)
    enr = out.metadata["scribe"]["reachability"]
    assert enr["reachable"] is None


def test_finding_without_package_is_untouched() -> None:
    f = _finding(package="")
    assert ReachabilityScribe().scribe(f, ScribeContext(repo_path=".")) == f


def test_is_deterministic(tmp_path, monkeypatch) -> None:
    ctx = _repo(tmp_path, monkeypatch)
    e = ReachabilityScribe()
    f = _finding()
    assert e.scribe(f, ctx).to_dict() == e.scribe(f, ctx).to_dict()


def test_unindexable_repo_is_fail_open(tmp_path, monkeypatch) -> None:
    """Availability: a graph build failure never drops the finding, and reports
    reachable=None rather than a false negative."""
    monkeypatch.setenv("CALIPER_GRAPH_DB", "/nonexistent/dir/does-not-exist/graph.db")
    ctx = ScribeContext(repo_path=str(tmp_path))
    out = ReachabilityScribe().scribe(_finding(), ctx)
    enr = out.metadata["scribe"]["reachability"]
    assert enr["reachable"] is None
