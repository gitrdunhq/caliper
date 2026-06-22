"""Tests for the scanner orchestrator."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

from caliper.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)
from caliper.core.orchestrator import ScanOrchestrator
from caliper.data.scanners.base import Scanner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scanner(name: str, result: ScanResult, delay: float = 0.0) -> Scanner:
    """Create a mock scanner that returns a fixed result after an optional delay."""
    scanner = MagicMock(spec=Scanner)
    scanner.name = name

    def _scan(target_path: Path) -> ScanResult:
        if delay > 0:
            time.sleep(delay)
        return result

    scanner.scan.side_effect = _scan
    return scanner


def _success_result(name: str, findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        tool_name=name,
        status=ScanResultStatus.success,
        findings=findings or [],
        duration_seconds=1.0,
    )


def _timeout_result(name: str) -> ScanResult:
    return ScanResult(
        tool_name=name,
        status=ScanResultStatus.timeout,
        findings=[],
        duration_seconds=60.0,
        message=f"{name} timeout after 60s",
    )


def _finding(pkg: str = "requests", version: str = "2.25.0") -> Finding:
    return Finding(
        severity=FindingSeverity.high,
        category=FindingCategory.vulnerability,
        description="test vuln",
        source_tool="test",
        package_name=pkg,
        version=version,
        advisory_id="CVE-2023-0001",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOrchestratorAllSucceed:
    """Tests for the happy path where all scanners succeed."""

    def test_returns_all_results(self) -> None:
        scanners = [
            _make_scanner("syft", _success_result("syft")),
            _make_scanner("osv-scanner", _success_result("osv-scanner")),
            _make_scanner("trivy", _success_result("trivy")),
        ]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=180)

        results = orch.run(Path("/project"))

        assert len(results) == 3
        assert all(r.status == ScanResultStatus.success for r in results)

    def test_preserves_scanner_order(self) -> None:
        scanners = [
            _make_scanner("syft", _success_result("syft")),
            _make_scanner("osv-scanner", _success_result("osv-scanner")),
        ]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=180)

        results = orch.run(Path("/project"))

        assert results[0].tool_name == "syft"
        assert results[1].tool_name == "osv-scanner"

    def test_findings_from_scanners_included(self) -> None:
        vuln = _finding()
        scanners = [
            _make_scanner("trivy", _success_result("trivy", findings=[vuln])),
        ]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=180)

        results = orch.run(Path("/project"))

        assert len(results[0].findings) == 1
        assert results[0].findings[0].advisory_id == "CVE-2023-0001"


class TestOrchestratorOneTimeout:
    """Tests for when one scanner times out but others continue."""

    def test_timeout_scanner_result_captured(self) -> None:
        scanners = [
            _make_scanner("syft", _success_result("syft")),
            _make_scanner("osv-scanner", _timeout_result("osv-scanner")),
            _make_scanner("trivy", _success_result("trivy")),
        ]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=180)

        results = orch.run(Path("/project"))

        assert len(results) == 3
        assert results[0].status == ScanResultStatus.success
        assert results[1].status == ScanResultStatus.timeout
        assert results[2].status == ScanResultStatus.success


class TestOrchestratorCombinedTimeout:
    """Tests for combined timeout behavior."""

    def test_remaining_scanners_skipped(self) -> None:
        """Slow scanners are skipped when combined timeout is tight."""
        scanners = [
            _make_scanner("syft", _success_result("syft"), delay=0.0),
            _make_scanner("osv-scanner", _success_result("osv-scanner"), delay=2.0),
            _make_scanner("trivy", _success_result("trivy"), delay=2.0),
        ]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=1)

        results = orch.run(Path("/project"))

        assert len(results) == 3
        skipped = [r for r in results if r.status == ScanResultStatus.skipped]
        assert len(skipped) >= 1
        for s in skipped:
            assert "combined timeout" in (s.message or "").lower()

    def test_skipped_results_have_correct_tool_name(self) -> None:
        """Skipped scanners carry the correct tool_name."""
        scanners = [
            _make_scanner("syft", _success_result("syft"), delay=0.0),
            _make_scanner("osv-scanner", _success_result("osv-scanner"), delay=2.0),
            _make_scanner("trivy", _success_result("trivy"), delay=2.0),
        ]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=1)

        results = orch.run(Path("/project"))

        skipped = [r for r in results if r.status == ScanResultStatus.skipped]
        skipped_names = {r.tool_name for r in skipped}
        assert skipped_names & {"osv-scanner", "trivy"}


class TestOrchestratorEmptyList:
    """Tests for empty scanner list."""

    def test_empty_scanners_returns_empty_results(self) -> None:
        orch = ScanOrchestrator(scanners=[], combined_timeout=180)

        results = orch.run(Path("/project"))

        assert results == []


class TestOrchestratorNeverRaises:
    """Tests that the orchestrator never raises exceptions."""

    def test_scanner_raising_exception_captured(self) -> None:
        """If a scanner's scan() somehow raises, orchestrator handles it."""
        scanner = MagicMock(spec=Scanner)
        scanner.name = "broken"
        scanner.scan.side_effect = RuntimeError("unexpected boom")

        orch = ScanOrchestrator(scanners=[scanner], combined_timeout=180)

        results = orch.run(Path("/project"))

        assert len(results) == 1
        assert results[0].status == ScanResultStatus.failed
        assert "unexpected boom" in (results[0].message or "")


class TestOrchestratorFutureCancellation:
    """Tests that remaining futures are cancelled after combined timeout."""

    def test_skipped_result_message_mentions_combined_timeout(self) -> None:
        """Scanners not completing within combined timeout are skipped with clear reason."""
        scanners = [
            _make_scanner("fast", _success_result("fast"), delay=0.0),
            _make_scanner("slow", _success_result("slow"), delay=5.0),
        ]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=1)

        results = orch.run(Path("/project"))

        slow_result = results[1]
        assert slow_result.status == ScanResultStatus.skipped
        assert "combined timeout" in (slow_result.message or "").lower()

    def test_all_scanners_get_result_after_combined_timeout(self) -> None:
        """Every scanner in the input list produces exactly one result, even on timeout."""
        n = 5
        scanners = [_make_scanner(f"s{i}", _success_result(f"s{i}"), delay=5.0) for i in range(n)]
        orch = ScanOrchestrator(scanners=scanners, combined_timeout=1)

        results = orch.run(Path("/project"))

        assert len(results) == n  # Exactly one result per scanner — no extras, no gaps
