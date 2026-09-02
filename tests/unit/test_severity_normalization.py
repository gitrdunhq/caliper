"""One severity vocabulary in every output: critical/high/medium/low/info.
# tested-by: tests/unit/test_severity_normalization.py

semgrep findings reached the JSON report as ERROR/WARNING/INFO while every
other plugin used the FindingSeverity enum. The registry's normalizer now
maps every plugin's severity onto that enum, and semgrep emits canonical
values at its own boundary, so no consumer needs a per-plugin special case.
"""

from __future__ import annotations

import json
from pathlib import Path

from caliper.core.json_report import render_json
from caliper.core.plugin import PluginResult, normalize_finding
from caliper.core.plugin_registry import _normalize_findings
from caliper.core.port_registries import RULE_RUNNERS
from caliper.plugins.semgrep import SemgrepPlugin

_CANONICAL = {"critical", "high", "medium", "low", "info"}


class TestNormalizeFinding:
    def test_semgrep_vocabulary_maps_onto_the_enum(self) -> None:
        assert normalize_finding({"severity": "ERROR"}).severity == "high"
        assert normalize_finding({"severity": "WARNING"}).severity == "medium"
        assert normalize_finding({"severity": "INFO"}).severity == "info"

    def test_case_and_alias_variants_collapse(self) -> None:
        assert normalize_finding({"severity": "HIGH"}).severity == "high"
        assert normalize_finding({"severity": "Moderate"}).severity == "medium"
        assert normalize_finding({"severity": "note"}).severity == "info"

    def test_unknown_and_missing_fall_to_info(self) -> None:
        assert normalize_finding({"severity": "bogus"}).severity == "info"
        assert normalize_finding({}).severity == "info"

    def test_registry_output_is_always_canonical(self) -> None:
        raw = [{"severity": s} for s in ("ERROR", "WARNING", "INFO", "critical", "LOW", "?")]
        assert {f.severity for f in _normalize_findings(raw)} <= _CANONICAL


class TestJsonReport:
    def test_raw_dict_findings_are_canonical_in_the_report(self) -> None:
        result = PluginResult(
            plugin_name="semgrep",
            findings=[{"rule_id": "r", "severity": "ERROR", "message": "m", "file": "a.py"}],
        )
        data = json.loads(render_json([result]))
        sev = {f["severity"] for p in data["plugins"] for f in p["findings"]}
        assert sev == {"high"}


class _Runner:
    def __init__(self, data: dict) -> None:
        self._data = data

    def run(self, *a, **k) -> dict:
        return self._data


class TestSemgrepPluginBoundary:
    def _run(self, monkeypatch, tmp_path: Path, sevs: list[str]) -> PluginResult:
        target = tmp_path / "a.py"
        data = {
            "results": [
                {
                    "check_id": f"rule.{i}",
                    "path": str(target),
                    "start": {"line": i},
                    "end": {"line": i},
                    "extra": {"severity": s, "message": "m"},
                }
                for i, s in enumerate(sevs, 1)
            ]
        }
        monkeypatch.setattr(RULE_RUNNERS, "create", lambda name: _Runner(data))
        return SemgrepPlugin().run([str(target)], tmp_path)

    def test_emits_canonical_severities(self, monkeypatch, tmp_path: Path) -> None:
        result = self._run(monkeypatch, tmp_path, ["INFO", "ERROR", "WARNING"])
        assert [f["severity"] for f in result.findings] == ["high", "medium", "info"]

    def test_missing_severity_defaults_to_medium(self, monkeypatch, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        data = {
            "results": [
                {
                    "check_id": "r",
                    "path": str(target),
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"message": "m"},
                }
            ]
        }
        monkeypatch.setattr(RULE_RUNNERS, "create", lambda name: _Runner(data))
        assert SemgrepPlugin().run([str(target)], tmp_path).findings[0]["severity"] == "medium"

    def test_inline_render_uses_canonical_icons(self, monkeypatch, tmp_path: Path) -> None:
        result = self._run(monkeypatch, tmp_path, ["ERROR", "WARNING", "INFO"])
        out = SemgrepPlugin().render(result)
        assert "🔴" in out and "🟡" in out and "ℹ️" in out and "?" not in out.split("</summary>")[1]
