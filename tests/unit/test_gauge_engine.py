"""Tests for the gauge execution engine — ``core.gauge_engine``.

# tested-by: tests/unit/test_gauge_engine.py

The engine executes a promoted/candidate gauge over a file set (semgrep kind only;
ast/manual need a human-written detector). All IO is via an injected semgrep callable,
so these run with no opengrep binary and no network.
"""

from __future__ import annotations

from caliper.core.gauge_engine import make_backtest_runner, run_gauge
from caliper.core.models import CandidateGauge

_DRAFT = (
    "rules:\n  - id: my-rule\n    pattern: dangerous($X)\n    message: bad\n    severity: WARNING"
)


def _cand(kind: str = "semgrep", draft: str = _DRAFT) -> CandidateGauge:
    return CandidateGauge(
        cluster_key="g-1", kind=kind, draft=draft, model_version="m", prompt_version="v0"
    )


def _fake_semgrep(results: list[dict]):
    def run(files, repo, *, timeout: int = 60, extra_config_dirs=None, exclude_rules=None) -> dict:
        return {"results": results, "errors": []}

    return run


def test_run_gauge_semgrep_maps_findings() -> None:
    results = [
        {
            "check_id": "policies.semgrep.my-rule",
            "path": "a.py",
            "start": {"line": 3},
            "end": {"line": 3},
            "extra": {"message": "bad", "severity": "WARNING"},
        }
    ]
    run = run_gauge(_cand(), ["a.py"], "/repo", semgrep_run=_fake_semgrep(results))
    assert run.executable is True
    assert len(run.findings) == 1
    f = run.findings[0]
    assert f.file == "a.py" and f.line_range == (3, 3) and f.source == "gauge:g-1"


def test_run_gauge_filters_to_this_rule_only() -> None:
    """The runner also applies the repo's standard rulesets; only this gauge's hits count."""
    results = [
        {"check_id": "p/default.other-rule", "path": "a.py", "start": {"line": 1}, "extra": {}}
    ]
    run = run_gauge(_cand(), ["a.py"], "/repo", semgrep_run=_fake_semgrep(results))
    assert run.findings == []


def test_run_gauge_non_semgrep_is_not_executable() -> None:
    run = run_gauge(
        _cand(kind="manual", draft="implement X"), ["a.py"], "/repo", semgrep_run=_fake_semgrep([])
    )
    assert run.executable is False and run.findings == []


def test_run_gauge_no_files() -> None:
    run = run_gauge(_cand(), [], "/repo", semgrep_run=_fake_semgrep([{"check_id": "x"}]))
    assert run.findings == []


def test_make_backtest_runner_counts_hits() -> None:
    results = [{"check_id": "x.my-rule", "path": "s.py", "start": {"line": 1}, "extra": {}}]
    runner = make_backtest_runner("/repo", lambda sid: [f"{sid}.py"], _fake_semgrep(results))
    out = runner(_cand(), ["s1", "s2"])
    assert out.hits == {"s1", "s2"}


def test_make_backtest_runner_non_executable_flags_nothing() -> None:
    runner = make_backtest_runner("/repo", lambda sid: [f"{sid}.py"], _fake_semgrep([]))
    out = runner(_cand(kind="manual", draft="x"), ["s1"])
    assert out.hits == set()
