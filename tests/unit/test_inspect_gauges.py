"""Tests for Screen gauges — ``core.inspect_gauges`` (injected analyzer runner).

# tested-by: tests/unit/test_inspect_gauges.py

Property domains (DPS-12):
  Availability LIVENESS structural gauges always run; analyzers routed by bucket
  Integrity    SAFETY   fail-closed: a gauge error/timeout is a hard error
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.inspect import InspectError
from caliper.core.inspect_gauges import has_hard_failure, run_gauges, screen_findings
from caliper.core.models import ChangeType, Kerf, Part
from caliper.core.plugin import PluginResult
from caliper.core.repo_config import InspectConfig


def _part(bucket: ChangeType, files=("a.py",)) -> Part:
    return Part(
        id=f"part-{bucket}",
        files=list(files),
        bucket=bucket,
        size=10,
        opened_by=Kerf(fired_rule="bucket-end"),
    )


def test_structural_gauge_for_generated_no_analyzers() -> None:
    gauges = run_gauges(
        _part(ChangeType.generated), Path("/repo"), InspectConfig(), analyze=lambda *a: []
    )
    assert [g.gauge for g in gauges] == ["checksum"]
    assert gauges[0].verdict == "pass"


def test_move_gets_structural_identity_gauge() -> None:
    gauges = run_gauges(
        _part(ChangeType.move), Path("/repo"), InspectConfig(), analyze=lambda *a: []
    )
    assert gauges[0].gauge == "structural-identity"


def test_logic_runs_analyzers_and_records_findings_with_ids() -> None:
    def fake_analyze(files, repo, cats):
        return [
            PluginResult(
                plugin_name="detectors",
                findings=[{"file": "a.py", "line": 4, "severity": "medium", "message": "x"}],
            )
        ]

    gauges = run_gauges(
        _part(ChangeType.logic), Path("/repo"), InspectConfig(), analyze=fake_analyze
    )
    findings = screen_findings(gauges)
    assert any(
        f.id == "detectors:0" and f.file == "a.py" and f.line_range == (4, 4) for f in findings
    )
    assert not has_hard_failure(gauges)  # medium is not a hard severity


def test_hard_finding_marks_gauge_failed() -> None:
    def fake_analyze(files, repo, cats):
        return [
            PluginResult(
                plugin_name="gitleaks", findings=[{"severity": "critical", "message": "secret"}]
            )
        ]

    gauges = run_gauges(
        _part(ChangeType.logic), Path("/repo"), InspectConfig(), analyze=fake_analyze
    )
    assert has_hard_failure(gauges)


def test_fail_closed_on_gauge_error() -> None:
    def fake_analyze(files, repo, cats):
        return [PluginResult(plugin_name="semgrep", error="opengrep crashed: boom")]

    with pytest.raises(InspectError):
        run_gauges(_part(ChangeType.logic), Path("/repo"), InspectConfig(), analyze=fake_analyze)


def test_fail_closed_on_timeout() -> None:
    def fake_analyze(files, repo, cats):
        return [PluginResult(plugin_name="trivy", error="trivy timeout after 60s")]

    with pytest.raises(InspectError):
        run_gauges(_part(ChangeType.logic), Path("/repo"), InspectConfig(), analyze=fake_analyze)


def test_missing_gauge_hard_fails_by_default_but_relaxable() -> None:
    def fake_analyze(files, repo, cats):
        return [PluginResult(plugin_name="clamav", error="clamav is not installed")]

    with pytest.raises(InspectError):
        run_gauges(_part(ChangeType.logic), Path("/repo"), InspectConfig(), analyze=fake_analyze)

    relaxed = InspectConfig(allow_missing_gauges=True)
    gauges = run_gauges(_part(ChangeType.logic), Path("/repo"), relaxed, analyze=fake_analyze)
    assert gauges[-1].verdict == "pass"  # skipped, not a blocker
