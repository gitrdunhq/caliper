"""Tests for ComplexityPlugin render output capping.
# tested-by: tests/unit/test_complexity_plugin.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.config import CaliperSettings
from caliper.core.plugin import PluginResult
from caliper.plugins import complexity as complexity_mod
from caliper.plugins.complexity import ComplexityPlugin


def _make_finding(name: str, ccn: int = 3, nloc: int = 10) -> dict:
    return {
        "function": name,
        "file": "src/mod.py",
        "cyclomatic_complexity": ccn,
        "maintainability_index": 85.0,
        "nloc": nloc,
    }


class TestComplexityRenderCapping:
    """Complexity render output must cap rows to prevent report truncation."""

    def test_render_caps_at_25_rows(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(40)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 400,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        rows = [line for line in output.split("\n") if line.startswith("| `func_")]
        assert len(rows) == 25

    def test_render_shows_remaining_count(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(40)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 400,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        assert "15 more" in output

    def test_render_no_truncation_under_cap(self) -> None:
        findings = [_make_finding(f"func_{i}") for i in range(10)]
        result = PluginResult(
            plugin_name="complexity",
            findings=findings,
            summary={
                "avg_cyclomatic_complexity": 3,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 100,
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        rows = [line for line in output.split("\n") if line.startswith("| `func_")]
        assert len(rows) == 10
        assert "more" not in output


class TestComplexityRenderTypeCoercion:
    """_render_inline must handle string-typed numeric fields without raising."""

    def test_string_summary_values_do_not_raise(self) -> None:
        """Summary metrics as strings (e.g. from JSON) must coerce without TypeError."""
        result = PluginResult(
            plugin_name="complexity",
            findings=[_make_finding("func_a", ccn=3)],
            summary={
                "avg_cyclomatic_complexity": "10.5",
                "max_cyclomatic_complexity": "15",
                "total_nloc": "200",
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        assert "<details>" in output
        assert "Complexity" in output

    def test_string_ccn_above_10_appears_in_high_section(self) -> None:
        """A finding with cyclomatic_complexity='12' (string) must land in the high section."""
        result = PluginResult(
            plugin_name="complexity",
            findings=[
                {
                    "function": "hot_func",
                    "file": "src/mod.py",
                    "cyclomatic_complexity": "12",
                    "maintainability_index": "65.5",
                    "nloc": "50",
                }
            ],
            summary={
                "avg_cyclomatic_complexity": "12",
                "max_cyclomatic_complexity": "12",
                "total_nloc": "50",
            },
        )
        plugin = ComplexityPlugin()
        # Before fix: TypeError because "12" > 10 is invalid in Python 3
        output = plugin._render_inline(result)
        assert "High complexity" in output, "CCN=12 string should be in high-complexity section"

    def test_invalid_string_ccn_does_not_crash(self) -> None:
        """Completely non-numeric cyclomatic_complexity values must not crash _render_inline."""
        result = PluginResult(
            plugin_name="complexity",
            findings=[
                {
                    "function": "bad_func",
                    "file": "test.py",
                    "cyclomatic_complexity": "not_a_number",
                    "maintainability_index": "also_bad",
                    "nloc": "50",
                }
            ],
            summary={
                "avg_cyclomatic_complexity": "abc",
                "max_cyclomatic_complexity": "def",
                "total_nloc": "xyz",
            },
        )
        plugin = ComplexityPlugin()
        output = plugin._render_inline(result)
        assert output  # must produce some output rather than crashing


class TestComplexityPluginTimeout:
    """ComplexityPlugin must honor CaliperSettings.scanner_timeout (#432a)."""

    def test_run_passes_scanner_timeout_from_settings(self, monkeypatch, tmp_path: Path) -> None:
        captured: dict = {}

        def fake_run(files, repo_path, timeout=60):
            captured["timeout"] = timeout
            return {"functions": [], "summary": {}}

        monkeypatch.setattr(complexity_mod, "_run", fake_run)

        plugin = ComplexityPlugin(settings=CaliperSettings(scanner_timeout=5))
        plugin.run(["a.py"], tmp_path)

        assert captured["timeout"] == 5

    def test_run_defaults_to_60_without_settings(self, monkeypatch, tmp_path: Path) -> None:
        captured: dict = {}

        def fake_run(files, repo_path, timeout=60):
            captured["timeout"] = timeout
            return {"functions": [], "summary": {}}

        monkeypatch.setattr(complexity_mod, "_run", fake_run)

        plugin = ComplexityPlugin()
        plugin.run(["a.py"], tmp_path)

        assert captured["timeout"] == 60


class TestComplexityThreshold:
    """Only functions above the CCN threshold are findings; the rest is summary metadata.

    Before: one finding per function (6,113 on caliper's own repo), all at note
    level, flooding the PR comment, the JSON report, and the SARIF upload.
    """

    @staticmethod
    def _functions(ccns: list[int]) -> list[dict]:
        return [_make_finding(f"f{i}", ccn=c) for i, c in enumerate(ccns)]

    def _run_with(self, monkeypatch, tmp_path: Path, ccns: list[int], plugin=None):
        def fake_run(files, repo_path, timeout=60):
            return {
                "functions": self._functions(ccns),
                "summary": {"avg_cyclomatic_complexity": 4, "max_cyclomatic_complexity": max(ccns)},
            }

        monkeypatch.setattr(complexity_mod, "_run", fake_run)
        return (plugin or ComplexityPlugin()).run(["a.py"], tmp_path)

    def test_simple_functions_produce_no_findings(self, monkeypatch, tmp_path: Path) -> None:
        result = self._run_with(monkeypatch, tmp_path, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        assert result.findings == []
        assert result.summary["functions_scanned"] == 10
        assert result.summary["ccn_threshold"] == 10
        assert result.summary["max_cyclomatic_complexity"] == 10

    def test_only_functions_above_threshold_are_findings(self, monkeypatch, tmp_path: Path) -> None:
        result = self._run_with(monkeypatch, tmp_path, [3, 11, 25, 10])
        assert sorted(f["cyclomatic_complexity"] for f in result.findings) == [11, 25]
        assert result.summary["functions_scanned"] == 4

    def test_threshold_from_repo_config(self, monkeypatch, tmp_path: Path) -> None:
        """`thresholds.complexity.ccn` in .caliper.yaml overrides the default of 10."""
        (tmp_path / ".caliper.yaml").write_text("thresholds:\n  complexity:\n    ccn: 5\n")
        result = self._run_with(monkeypatch, tmp_path, [3, 6, 11])
        assert sorted(f["cyclomatic_complexity"] for f in result.findings) == [6, 11]
        assert result.summary["ccn_threshold"] == 5

    def test_unparseable_ccn_is_not_a_finding(self, monkeypatch, tmp_path: Path) -> None:
        def fake_run(files, repo_path, timeout=60):
            f = _make_finding("weird", ccn=3)
            f["cyclomatic_complexity"] = "not_a_number"
            return {"functions": [f], "summary": {}}

        monkeypatch.setattr(complexity_mod, "_run", fake_run)
        result = ComplexityPlugin().run(["a.py"], tmp_path)
        assert result.findings == []
        assert result.summary["functions_scanned"] == 1


class TestComplexityFindingMessage:
    """A complexity finding must describe itself.

    core.sarif._message_text reads "message"/"description"/"summary" off the
    finding dict. A complexity finding carried none of them, so every
    complexity result serialised with `"message": {"text": ""}` — and
    `caliper review --pr N`, which posts SARIF results as inline comments,
    would post them blank. The CCN that makes the finding worth reading only
    ever appeared in the markdown table.
    """

    def _findings_for(self, monkeypatch, tmp_path: Path, functions: list[dict]):
        def fake_run(files, repo_path, timeout=60):
            return {"functions": functions, "summary": {}}

        monkeypatch.setattr(complexity_mod, "_run", fake_run)
        return ComplexityPlugin().run(["a.py"], tmp_path)

    def test_finding_carries_a_non_empty_message(self, monkeypatch, tmp_path: Path) -> None:
        result = self._findings_for(monkeypatch, tmp_path, [_make_finding("parse_report", ccn=39)])
        assert result.findings[0]["message"].strip()

    def test_message_names_the_function_and_its_complexity(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        result = self._findings_for(monkeypatch, tmp_path, [_make_finding("parse_report", ccn=39)])
        message = result.findings[0]["message"]
        assert "parse_report" in message
        assert "39" in message

    def test_message_states_the_threshold_it_exceeded(self, monkeypatch, tmp_path: Path) -> None:
        """A reviewer seeing one inline comment has no other way to know what
        bar the function cleared."""
        result = self._findings_for(monkeypatch, tmp_path, [_make_finding("execute", ccn=35)])
        assert "10" in result.findings[0]["message"]

    def test_sarif_message_text_is_not_empty(self, monkeypatch, tmp_path: Path) -> None:
        from caliper.core.sarif import to_sarif

        result = self._findings_for(monkeypatch, tmp_path, [_make_finding("execute", ccn=35)])
        doc = to_sarif([result])
        run = next(r for r in doc["runs"] if r["tool"]["driver"]["name"] == "complexity")
        assert run["results"][0]["message"]["text"].strip()

    def test_sarif_anchors_to_the_function_start_line(self, monkeypatch, tmp_path: Path) -> None:
        from caliper.core.sarif import to_sarif

        finding = _make_finding("execute", ccn=35)
        finding["start_line"] = 541
        result = self._findings_for(monkeypatch, tmp_path, [finding])
        doc = to_sarif([result])
        run = next(r for r in doc["runs"] if r["tool"]["driver"]["name"] == "complexity")
        region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 541

    def test_message_is_added_without_disturbing_the_existing_fields(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        """The markdown renderer reads function/file/cyclomatic_complexity/nloc
        straight off the finding — adding a message must not displace them."""
        result = self._findings_for(monkeypatch, tmp_path, [_make_finding("execute", ccn=35)])
        finding = result.findings[0]
        assert finding["function"] == "execute"
        assert finding["file"] == "src/mod.py"
        assert finding["cyclomatic_complexity"] == 35
        assert finding["nloc"] == 10

    def test_below_threshold_functions_still_produce_no_findings(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        result = self._findings_for(monkeypatch, tmp_path, [_make_finding("tiny", ccn=2)])
        assert result.findings == []
