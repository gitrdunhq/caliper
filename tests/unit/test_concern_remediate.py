"""Tests for caliper.core.concern_remediate — Haiku-powered finding remediation."""

from __future__ import annotations

from pathlib import Path

import respx


def _anthropic_response(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


SAMPLE_HAIKU_PATCH = """\
--- TEST ---
file: tests/unit/test_graph_builder.py

```python
def test_sql_injection_in_run_checks(self, tmp_path):
    graph = CodeGraph(str(tmp_path / "test.db"))
    graph.index_file(str(tmp_path / "safe.py"), "def f(): pass")
    findings = graph.run_checks(["' OR 1=1 --"])
    assert len(findings) == 0
```

--- FIX ---
file: src/caliper/plugins/_runners/graph_builder.py
line: 144

```python
placeholders = ",".join("?" for _ in changed_files)
```
"""


class TestRemediator:
    @respx.mock
    def test_remediate_single_finding(self, tmp_path: Path) -> None:
        """Haiku returns a test + fix for one finding."""
        from caliper.core.concern_remediate import Remediator

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(200, json=_anthropic_response(SAMPLE_HAIKU_PATCH))
        )

        remediator = Remediator(api_key="sk-test")
        result = remediator.remediate_finding(
            finding={
                "severity": "CRITICAL",
                "concern": "plugins",
                "title": "SQL Injection via file paths in run_checks()",
                "file": "src/caliper/plugins/_runners/graph_builder.py",
                "line": 144,
                "fix_suggestion": "Use parameterized queries instead of string interpolation",
            },
            source_code="placeholders = ','.join(f\"'{f}'\" for f in changed_files)\n",
        )

        assert result != ""
        assert "TEST" in result or "test" in result
        assert "FIX" in result or "fix" in result
        remediator.close()

    @respx.mock
    def test_remediate_uses_fix_suggestion_from_real_plugin_finding(self, tmp_path: Path) -> None:
        """fix_suggestion reaches Haiku's prompt from a real PluginFinding.to_dict(),
        not just a hand-authored test fixture dict (#276)."""
        from caliper.core.concern_remediate import Remediator
        from caliper.core.plugin import PluginFinding

        route = respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(200, json=_anthropic_response(SAMPLE_HAIKU_PATCH))
        )

        # This is the shape scanner plugins (e.g. semgrep) actually emit —
        # fix_suggestion populated from rule metadata, not a test literal.
        plugin_finding = PluginFinding(
            id="rule.sql-injection",
            severity="CRITICAL",
            message="SQL Injection via file paths in run_checks()",
            file="src/caliper/plugins/_runners/graph_builder.py",
            line=144,
            fix_suggestion="Use parameterized queries instead of string interpolation",
        )

        remediator = Remediator(api_key="sk-test")
        result = remediator.remediate_finding(
            finding=plugin_finding.to_dict(),
            source_code="placeholders = ','.join(f\"'{f}'\" for f in changed_files)\n",
        )

        assert result != ""
        sent_body = route.calls.last.request.content.decode()
        assert "Use parameterized queries instead of string interpolation" in sent_body
        remediator.close()

    @respx.mock
    def test_timeout_returns_empty(self) -> None:
        """Timeout returns empty, does not raise."""
        import httpx as _httpx

        from caliper.core.concern_remediate import Remediator

        respx.post("https://api.anthropic.com/v1/messages").mock(
            side_effect=_httpx.TimeoutException("timed out")
        )

        remediator = Remediator(api_key="sk-test")
        result = remediator.remediate_finding(
            finding={"severity": "HIGH", "title": "test", "file": "x.py"},
            source_code="x = 1\n",
        )
        assert result == ""
        remediator.close()


class TestRunRemediation:
    @respx.mock
    def test_canary_then_parallel(self, tmp_path: Path) -> None:
        """Canary finding runs first; rest fan out in parallel."""
        from caliper.core.concern_remediate import RemediationReport, run_remediation

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(200, json=_anthropic_response(SAMPLE_HAIKU_PATCH))
        )

        (tmp_path / "src" / "caliper" / "plugins").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "plugins" / "a.py").write_text("a = 1\n")
        (tmp_path / "src" / "caliper" / "data").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "data" / "b.py").write_text("b = 2\n")

        findings = [
            {
                "severity": "CRITICAL",
                "title": "SQL injection",
                "file": "src/caliper/plugins/a.py",
                "line": 1,
                "fix_suggestion": "parameterize",
            },
            {
                "severity": "HIGH",
                "title": "Path traversal",
                "file": "src/caliper/data/b.py",
                "line": 1,
                "fix_suggestion": "resolve paths",
            },
        ]

        report = run_remediation(
            findings=findings,
            repo_path=tmp_path,
            api_key="sk-test",
        )

        assert isinstance(report, RemediationReport)
        assert report.total_findings == 2
        assert len(report.patches) == 2
        assert all(p.response != "" for p in report.patches)

    @respx.mock
    def test_canary_failure_aborts(self, tmp_path: Path) -> None:
        """If canary fails, remaining findings are skipped."""
        from caliper.core.concern_remediate import run_remediation

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(500, json={"error": "down"})
        )

        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core" / "a.py").write_text("a = 1\n")

        findings = [
            {"severity": "CRITICAL", "title": "Finding 1", "file": "src/caliper/core/a.py"},
            {"severity": "HIGH", "title": "Finding 2", "file": "src/caliper/core/a.py"},
        ]

        report = run_remediation(findings=findings, repo_path=tmp_path, api_key="sk-test")

        assert report.total_findings == 2
        assert any("canary" in e.lower() for e in report.errors)
        assert any(p.error != "" for p in report.patches)
