"""Tests for the ``caliper baseline update`` CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner

from caliper.cli.main import cli
from caliper.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)

_RUNNER_ENV = {"CALIPER_ALLOW_GLOBAL": "1"}


def _fake_context_with_scanner(findings: list[Finding]):
    from caliper.composition.bootstrap import ApplicationContext, bootstrap_test

    base = bootstrap_test()
    scanner = MagicMock(name="FakeScanner")
    scanner.name = "fake-scanner"
    scanner.scan.return_value = ScanResult(
        tool_name="fake-scanner",
        status=ScanResultStatus.success,
        findings=findings,
        duration_seconds=0.1,
    )
    return ApplicationContext(
        analyzer_registry=base.analyzer_registry,
        policy_engine=base.policy_engine,
        tool_runner=base.tool_runner,
        decision_store=base.decision_store,
        evidence_store=base.evidence_store,
        package_index=base.package_index,
        audit_sink=base.audit_sink,
        publisher=base.publisher,
        scanners=[scanner],
        evidence_writer=base.evidence_writer,
        package_metadata=base.package_metadata,
        decision_repository=base.decision_repository,
        audit_log_appender=base.audit_log_appender,
    )


class TestBaselineUpdateCommand:
    def test_no_findings_writes_empty_baseline(self, tmp_path: Path) -> None:
        fake_ctx = _fake_context_with_scanner([])

        with patch("caliper.composition.bootstrap.bootstrap", return_value=fake_ctx):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["baseline", "update", "--repo-path", str(tmp_path), "--reason", "tech debt"],
                env=_RUNNER_ENV,
            )

        assert result.exit_code == 0, result.output
        assert "0 new entries added" in result.output

    def test_new_finding_added_with_reason(self, tmp_path: Path) -> None:
        finding = Finding(
            severity=FindingSeverity.high,
            category=FindingCategory.vulnerability,
            description="test vuln",
            source_tool="fake-scanner",
            package_name="django",
            version="3.2.0",
            advisory_id="GHSA-xxxx",
        )
        fake_ctx = _fake_context_with_scanner([finding])

        with patch("caliper.composition.bootstrap.bootstrap", return_value=fake_ctx):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                [
                    "baseline",
                    "update",
                    "--repo-path",
                    str(tmp_path),
                    "--reason",
                    "tracked in JIRA-1",
                ],
                env=_RUNNER_ENV,
            )

        assert result.exit_code == 0, result.output
        assert "1 new entries added" in result.output

        baseline_file = tmp_path / ".caliper-baseline.yaml"
        assert baseline_file.exists()
        data = yaml.safe_load(baseline_file.read_text())
        assert len(data["entries"]) == 1
        assert data["entries"][0]["reason"] == "tracked in JIRA-1"

    def test_rerun_does_not_duplicate_entries(self, tmp_path: Path) -> None:
        finding = Finding(
            severity=FindingSeverity.high,
            category=FindingCategory.vulnerability,
            description="test vuln",
            source_tool="fake-scanner",
            package_name="django",
            version="3.2.0",
            advisory_id="GHSA-xxxx",
        )
        fake_ctx = _fake_context_with_scanner([finding])

        with patch("caliper.composition.bootstrap.bootstrap", return_value=fake_ctx):
            runner = CliRunner()
            runner.invoke(
                cli,
                ["baseline", "update", "--repo-path", str(tmp_path), "--reason", "r"],
                env=_RUNNER_ENV,
            )
            result = runner.invoke(
                cli,
                ["baseline", "update", "--repo-path", str(tmp_path), "--reason", "r"],
                env=_RUNNER_ENV,
            )

        assert result.exit_code == 0, result.output
        assert "0 new entries added" in result.output

        baseline_file = tmp_path / ".caliper-baseline.yaml"
        data = yaml.safe_load(baseline_file.read_text())
        assert len(data["entries"]) == 1
