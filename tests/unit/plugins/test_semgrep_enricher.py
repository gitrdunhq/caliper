"""SemgrepEnricher (detect-then-enrich, ADR-006).
# tested-by: tests/unit/plugins/test_semgrep_enricher.py

DPS-12 domains: Determinism (same matches -> same enrichment), Availability
(fail-open: a crashing/absent tool never drops the finding), Boundedness (related
matches are line-windowed and capped), Isolation (per-file results cached once).
"""

from __future__ import annotations

import eedom.plugins.enrichers.semgrep as mod
from eedom.core.enrichment import EnrichmentContext
from eedom.core.plugin import PluginFinding
from eedom.plugins.enrichers.semgrep import SemgrepEnricher


def _finding(**kw) -> PluginFinding:
    base = {"id": "x", "severity": "info", "message": "m", "file": "a.py", "line": 20}
    base.update(kw)
    return PluginFinding(**base)


def _match(line: int, check_id: str = "rule", sev: str = "WARNING") -> dict:
    return {
        "check_id": check_id,
        "start": {"line": line},
        "extra": {"message": f"msg {line}", "severity": sev},
    }


def test_applies_only_to_supported_located_files() -> None:
    e = SemgrepEnricher()
    assert e.applies_to(_finding(file="a.py", line=20)) is True
    assert e.applies_to(_finding(file="notes.md", line=20)) is False
    assert e.applies_to(_finding(file="a.py", line=0)) is False


def test_attaches_nearby_matches_and_windows_out_far_ones(monkeypatch) -> None:
    monkeypatch.setattr(mod, "run_semgrep", lambda *a, **k: {"results": [_match(22), _match(200)]})
    out = SemgrepEnricher().enrich(_finding(line=20), EnrichmentContext(repo_path="."))
    related = out.metadata["enrichment"]["related"]
    assert [m["line"] for m in related] == [22]  # 200 is outside the ±25 window
    assert "semgrep" in out.metadata["enrichment"]["sources"]


def test_no_nearby_matches_leaves_finding_unchanged(monkeypatch) -> None:
    monkeypatch.setattr(mod, "run_semgrep", lambda *a, **k: {"results": [_match(999)]})
    f = _finding(line=20)
    assert SemgrepEnricher().enrich(f, EnrichmentContext(repo_path=".")) == f


def test_tool_crash_is_fail_open(monkeypatch) -> None:
    def boom(*a, **k):
        raise RuntimeError("opengrep exploded")

    monkeypatch.setattr(mod, "run_semgrep", boom)
    f = _finding(line=20)
    assert SemgrepEnricher().enrich(f, EnrichmentContext(repo_path=".")) == f  # Availability


def test_caps_related_matches(monkeypatch) -> None:
    many = {"results": [_match(20 + i, check_id=f"r{i}") for i in range(20)]}
    monkeypatch.setattr(mod, "run_semgrep", lambda *a, **k: many)
    out = SemgrepEnricher().enrich(_finding(line=20), EnrichmentContext(repo_path="."))
    assert len(out.metadata["enrichment"]["related"]) == mod._MAX_RELATED  # Boundedness


def test_results_cached_per_file(monkeypatch) -> None:
    calls = {"n": 0}

    def counting(*a, **k):
        calls["n"] += 1
        return {"results": [_match(20)]}

    monkeypatch.setattr(mod, "run_semgrep", counting)
    e = SemgrepEnricher()
    ctx = EnrichmentContext(repo_path=".")
    e.enrich(_finding(line=20), ctx)
    e.enrich(_finding(line=21), ctx)
    assert calls["n"] == 1  # Isolation: one subprocess per file, reused across findings
