"""Tests for caliper.core.concern_review — concern-by-concern holistic audit.

Tests cover:
  - cluster_files: grouping, token splitting, tier classification, test exclusion
  - attach_findings: wiring dom's findings to clusters
  - build_packet: JSON packet shape for LLM agents
  - HolisticReviewer: Anthropic Messages API calls
  - run_audit: canary + parallel orchestration
  - render_audit_markdown: report rendering
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import respx


@dataclass
class FakePluginFinding:
    id: str = "F-001"
    severity: str = "high"
    message: str = "Test finding"
    file: str = ""
    line: int = 0
    url: str = ""
    category: str = ""
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    rule_id: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }

    def get(self, key: str, default=None):
        return getattr(self, key, default)


@dataclass
class FakePluginResult:
    plugin_name: str = "semgrep"
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str = ""
    category: str = "code"


def _anthropic_response(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


class TestClusterFiles:
    def test_groups_by_top_level_module(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "cli").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core" / "pipeline.py").write_text("def run(): pass\n")
        (tmp_path / "src" / "caliper" / "core" / "models.py").write_text("class Finding: pass\n")
        (tmp_path / "src" / "caliper" / "cli" / "main.py").write_text("import click\n")

        from caliper.core.concern_review import cluster_files

        files = [
            str(tmp_path / "src" / "caliper" / "core" / "pipeline.py"),
            str(tmp_path / "src" / "caliper" / "core" / "models.py"),
            str(tmp_path / "src" / "caliper" / "cli" / "main.py"),
        ]
        clusters = cluster_files(tmp_path, files)
        names = {c.name for c in clusters}
        assert "src/caliper/core" in names
        assert "src/caliper/cli" in names
        assert len(clusters) == 2

    def test_assigns_correct_tier(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "cli").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core" / "x.py").write_text("x = 1\n")
        (tmp_path / "src" / "caliper" / "cli" / "y.py").write_text("y = 2\n")

        from caliper.core.concern_review import cluster_files

        files = [
            str(tmp_path / "src" / "caliper" / "core" / "x.py"),
            str(tmp_path / "src" / "caliper" / "cli" / "y.py"),
        ]
        clusters = cluster_files(tmp_path, files)
        tier_map = {c.name: c.tier for c in clusters}
        assert tier_map["src/caliper/core"] == "logic"
        assert tier_map["src/caliper/cli"] == "presentation"

    def test_splits_large_clusters(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        big_content = "def func(): pass\n" * 50
        (tmp_path / "src" / "caliper" / "core" / "a.py").write_text(big_content)
        (tmp_path / "src" / "caliper" / "core" / "b.py").write_text(big_content)

        from caliper.core.concern_review import cluster_files

        files = [
            str(tmp_path / "src" / "caliper" / "core" / "a.py"),
            str(tmp_path / "src" / "caliper" / "core" / "b.py"),
        ]
        clusters = cluster_files(tmp_path, files, max_tokens_per_cluster=50)
        assert len(clusters) >= 2
        assert all("src/caliper/core" in c.name for c in clusters)

    def test_empty_file_list(self, tmp_path: Path) -> None:
        from caliper.core.concern_review import cluster_files

        clusters = cluster_files(tmp_path, [])
        assert clusters == []

    def test_test_files_excluded(self, tmp_path: Path) -> None:
        """Only src/ files are clustered — tests, configs, etc. are excluded."""
        (tmp_path / "tests" / "unit").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "tests" / "unit" / "test_a.py").write_text("def test_a(): pass\n")
        (tmp_path / "src" / "caliper" / "core" / "x.py").write_text("x = 1\n")

        from caliper.core.concern_review import cluster_files

        files = [
            str(tmp_path / "tests" / "unit" / "test_a.py"),
            str(tmp_path / "src" / "caliper" / "core" / "x.py"),
        ]
        clusters = cluster_files(tmp_path, files)
        assert len(clusters) == 1
        assert clusters[0].name == "src/caliper/core"

    def test_source_snippets_populated(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        content = "def hello(): return 42\n"
        (tmp_path / "src" / "caliper" / "core" / "x.py").write_text(content)

        from caliper.core.concern_review import cluster_files

        files = [str(tmp_path / "src" / "caliper" / "core" / "x.py")]
        clusters = cluster_files(tmp_path, files)
        assert len(clusters) == 1
        assert content in clusters[0].source_snippets.values()


class TestAttachFindings:
    def test_findings_attached_to_correct_cluster(self, tmp_path: Path) -> None:
        from caliper.core.concern_review import ConcernCluster, attach_findings

        cluster_core = ConcernCluster(
            name="src/caliper/core",
            tier="logic",
            files=[str(tmp_path / "src" / "caliper" / "core" / "pipeline.py")],
        )
        cluster_cli = ConcernCluster(
            name="src/caliper/cli",
            tier="presentation",
            files=[str(tmp_path / "src" / "caliper" / "cli" / "main.py")],
        )
        finding = FakePluginFinding(
            id="F-001",
            severity="high",
            message="SQL injection risk",
            file="src/caliper/core/pipeline.py",
        )
        result = FakePluginResult(plugin_name="semgrep", findings=[finding])
        attach_findings([cluster_core, cluster_cli], [result], tmp_path)
        assert len(cluster_core.findings) == 1
        assert cluster_core.findings[0]["severity"] == "high"
        assert len(cluster_cli.findings) == 0

    def test_no_findings_when_no_match(self, tmp_path: Path) -> None:
        from caliper.core.concern_review import ConcernCluster, attach_findings

        cluster = ConcernCluster(
            name="src/caliper/core",
            tier="logic",
            files=[str(tmp_path / "src" / "caliper" / "core" / "pipeline.py")],
        )
        finding = FakePluginFinding(file="src/caliper/data/scanner.py")
        result = FakePluginResult(findings=[finding])
        attach_findings([cluster], [result], tmp_path)
        assert len(cluster.findings) == 0


class TestBuildPacket:
    def test_packet_has_required_fields(self, tmp_path: Path) -> None:
        from caliper.core.concern_review import ConcernCluster, build_packet

        cluster = ConcernCluster(
            name="src/caliper/core",
            tier="logic",
            files=[str(tmp_path / "src" / "caliper" / "core" / "x.py")],
            total_tokens=500,
            findings=[{"severity": "high", "message": "test"}],
            source_snippets={str(tmp_path / "src" / "caliper" / "core" / "x.py"): "x = 1\n"},
        )
        packet = build_packet(cluster, tmp_path)
        assert packet["concern"] == "src/caliper/core"
        assert packet["tier"] == "logic"
        assert packet["file_count"] == 1
        assert packet["total_tokens"] == 500
        assert len(packet["findings"]) == 1
        assert "src/caliper/core/x.py" in packet["source"]

    def test_source_paths_are_relative(self, tmp_path: Path) -> None:
        from caliper.core.concern_review import ConcernCluster, build_packet

        abs_path = str(tmp_path / "src" / "caliper" / "core" / "x.py")
        cluster = ConcernCluster(
            name="src/caliper/core",
            tier="logic",
            files=[abs_path],
            source_snippets={abs_path: "code\n"},
        )
        packet = build_packet(cluster, tmp_path)
        for key in packet["source"]:
            assert not key.startswith("/"), f"Source key should be relative: {key}"


class TestHolisticReviewer:
    @respx.mock
    def test_successful_review(self) -> None:
        from caliper.core.concern_review import HolisticReviewer

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(
                200, json=_anthropic_response("TRUST VERDICT: CONDITIONAL")
            )
        )
        reviewer = HolisticReviewer(api_key="sk-test")
        result = reviewer.review_concern(
            {
                "concern": "src/caliper/core",
                "tier": "logic",
                "file_count": 2,
                "total_tokens": 500,
                "findings": [],
                "source": {"core/x.py": "x = 1\n"},
            }
        )
        assert "CONDITIONAL" in result
        reviewer.close()

    @respx.mock
    def test_timeout_returns_empty(self) -> None:
        import httpx as _httpx

        from caliper.core.concern_review import HolisticReviewer

        respx.post("https://api.anthropic.com/v1/messages").mock(
            side_effect=_httpx.TimeoutException("timed out")
        )
        reviewer = HolisticReviewer(api_key="sk-test")
        result = reviewer.review_concern(
            {
                "concern": "test",
                "tier": "logic",
                "file_count": 1,
                "total_tokens": 100,
                "findings": [],
                "source": {},
            }
        )
        assert result == ""
        reviewer.close()

    @respx.mock
    def test_api_error_returns_empty(self) -> None:
        from caliper.core.concern_review import HolisticReviewer

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(500, json={"error": "server error"})
        )
        reviewer = HolisticReviewer(api_key="sk-test")
        result = reviewer.review_concern(
            {
                "concern": "test",
                "tier": "logic",
                "file_count": 1,
                "total_tokens": 100,
                "findings": [],
                "source": {},
            }
        )
        assert result == ""
        reviewer.close()

    @respx.mock
    def test_malformed_response_returns_empty(self) -> None:
        from caliper.core.concern_review import HolisticReviewer

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(200, json={"unexpected": "shape"})
        )
        reviewer = HolisticReviewer(api_key="sk-test")
        result = reviewer.review_concern(
            {
                "concern": "test",
                "tier": "logic",
                "file_count": 1,
                "total_tokens": 100,
                "findings": [],
                "source": {},
            }
        )
        assert result == ""
        reviewer.close()

    @respx.mock
    def test_findings_included_in_request(self) -> None:
        from caliper.core.concern_review import HolisticReviewer

        route = respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(
                200, json=_anthropic_response("TRUST VERDICT: CONDITIONAL")
            )
        )
        reviewer = HolisticReviewer(api_key="sk-test")
        reviewer.review_concern(
            {
                "concern": "src/caliper/core",
                "tier": "logic",
                "file_count": 1,
                "total_tokens": 200,
                "findings": [
                    {
                        "severity": "high",
                        "message": "SQL injection",
                        "plugin": "semgrep",
                        "file": "x.py",
                    }
                ],
                "source": {"core/x.py": "x = 1\n"},
            }
        )
        body = route.calls[0].request.content.decode()
        assert "SQL injection" in body
        assert "semgrep" in body
        reviewer.close()


class TestRunAudit:
    @respx.mock
    def test_end_to_end_audit(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core" / "pipeline.py").write_text("def run(): pass\n")

        from caliper.core.concern_review import run_audit

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(
                200, json=_anthropic_response("## Security\nNo issues.\n\nTRUST VERDICT: TRUSTED")
            )
        )
        finding = FakePluginFinding(
            file="src/caliper/core/pipeline.py", severity="medium", message="unused import"
        )
        result = FakePluginResult(findings=[finding])

        report = run_audit(
            repo_path=tmp_path,
            results=[result],
            files=[str(tmp_path / "src" / "caliper" / "core" / "pipeline.py")],
            api_key="sk-test",
        )
        assert report.concern_count == 1
        assert len(report.verdicts) == 1
        assert "TRUSTED" in report.verdicts[0].review_text
        assert report.verdicts[0].dom_finding_count == 1

    @respx.mock
    def test_canary_failure_aborts_audit(self, tmp_path: Path) -> None:
        """If canary fails, remaining clusters are skipped."""
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "cli").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core" / "a.py").write_text("a = 1\n")
        (tmp_path / "src" / "caliper" / "cli" / "b.py").write_text("b = 2\n")

        from caliper.core.concern_review import run_audit

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(500, json={"error": "down"})
        )
        report = run_audit(
            repo_path=tmp_path,
            results=[],
            files=[
                str(tmp_path / "src" / "caliper" / "core" / "a.py"),
                str(tmp_path / "src" / "caliper" / "cli" / "b.py"),
            ],
            api_key="sk-test",
        )
        assert report.concern_count == 2
        assert any("canary" in e.lower() for e in report.errors)
        assert any("Skipped" in v.error for v in report.verdicts)

    @respx.mock
    def test_canary_success_then_parallel(self, tmp_path: Path) -> None:
        """Canary succeeds, rest fan out in parallel — all concerns reviewed."""
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "cli").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "data").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core" / "a.py").write_text("a = 1\n")
        (tmp_path / "src" / "caliper" / "cli" / "b.py").write_text("b = 2\n")
        (tmp_path / "src" / "caliper" / "data" / "c.py").write_text("c = 3\n")

        from caliper.core.concern_review import run_audit

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(200, json=_anthropic_response("TRUST VERDICT: TRUSTED"))
        )
        report = run_audit(
            repo_path=tmp_path,
            results=[],
            files=[
                str(tmp_path / "src" / "caliper" / "core" / "a.py"),
                str(tmp_path / "src" / "caliper" / "cli" / "b.py"),
                str(tmp_path / "src" / "caliper" / "data" / "c.py"),
            ],
            api_key="sk-test",
        )
        assert report.concern_count == 3
        assert len(report.verdicts) == 3
        assert all("TRUSTED" in v.review_text for v in report.verdicts)

    @respx.mock
    def test_audit_with_empty_response(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "caliper" / "core").mkdir(parents=True)
        (tmp_path / "src" / "caliper" / "core" / "x.py").write_text("x = 1\n")

        from caliper.core.concern_review import run_audit

        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=respx.MockResponse(200, json=_anthropic_response(""))
        )
        report = run_audit(
            repo_path=tmp_path,
            results=[],
            files=[str(tmp_path / "src" / "caliper" / "core" / "x.py")],
            api_key="sk-test",
        )
        assert report.concern_count == 1
        assert report.verdicts[0].error != ""


class TestRenderAuditMarkdown:
    def test_renders_header_and_verdicts(self) -> None:
        from caliper.core.concern_review import AuditReport, ConcernVerdict, render_audit_markdown

        report = AuditReport(
            repo_path="/repo",
            concern_count=2,
            total_files=5,
            verdicts=[
                ConcernVerdict(
                    concern="src/caliper/core",
                    tier="logic",
                    file_count=3,
                    dom_finding_count=2,
                    review_text="All clear.\n\nTRUST VERDICT: TRUSTED",
                ),
                ConcernVerdict(
                    concern="src/caliper/cli",
                    tier="presentation",
                    file_count=2,
                    dom_finding_count=0,
                    review_text="Input validation gap.\n\nTRUST VERDICT: CONDITIONAL",
                ),
            ],
        )
        md = render_audit_markdown(report)
        assert "# Codebase Trust Audit" in md
        assert "TRUSTED" in md
        assert "CONDITIONAL" in md
        assert "src/caliper/core" in md
        assert "3 files" in md

    def test_renders_errors(self) -> None:
        from caliper.core.concern_review import AuditReport, ConcernVerdict, render_audit_markdown

        report = AuditReport(
            repo_path="/repo",
            concern_count=1,
            total_files=1,
            verdicts=[
                ConcernVerdict(
                    concern="src/caliper/data",
                    tier="data",
                    file_count=1,
                    dom_finding_count=0,
                    review_text="",
                    error="LLM returned empty response",
                )
            ],
            errors=["Empty response for concern: src/caliper/data"],
        )
        md = render_audit_markdown(report)
        assert "Error" in md
        assert "LLM returned empty response" in md


# ---------------------------------------------------------------------------
# Regression P08-3 — post_with_retry must catch ValueError (json.JSONDecodeError)
# ---------------------------------------------------------------------------


class TestPostWithRetryValueErrorRegression:
    """Regression for P08-3: post_with_retry's response-parsing except clause
    previously omitted ValueError, so resp.json() raising JSONDecodeError
    (a subclass of ValueError) on a malformed 200 body would propagate."""

    def test_malformed_json_200_anthropic_returns_empty_string(self):
        """A 200 response with malformed JSON body must return '' not raise ValueError
        (regression for P08-3: ValueError was not in the except clause)."""
        import httpx

        from caliper.core.concern_prompt import post_with_retry

        # Build a mock client that returns a 200 with non-JSON text
        class _BadJsonTransport(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="<html>not json</html>")

        client = httpx.Client(transport=_BadJsonTransport())
        try:
            result = post_with_retry(
                client=client,
                url="http://fake.invalid/v1/messages",
                payload={"model": "x", "messages": []},
                headers={"x-api-key": "test"},
                is_anthropic=True,
                timeout=5,
                max_retries=1,
            )
        except (ValueError, Exception) as exc:
            import pytest

            pytest.fail(
                f"post_with_retry must not propagate ValueError from resp.json() — "
                f"got {type(exc).__name__}: {exc}"
            )

        assert result == "", f"Malformed JSON 200 body must produce empty string, got {result!r}"

    def test_malformed_json_200_openai_returns_empty_string(self):
        """Same regression test for the OpenAI path (is_anthropic=False)."""
        import httpx

        from caliper.core.concern_prompt import post_with_retry

        class _BadJsonTransport(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="definitely not json {{{")

        client = httpx.Client(transport=_BadJsonTransport())
        result = post_with_retry(
            client=client,
            url="http://fake.invalid/v1/chat/completions",
            payload={},
            headers={},
            is_anthropic=False,
            timeout=5,
            max_retries=1,
        )
        assert result == ""
