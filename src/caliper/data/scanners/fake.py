"""Deterministic in-memory scanner for tests.
# tested-by: tests/unit/test_scanner_port.py

`FakeScanner` satisfies ``ScannerPort`` without spawning subprocesses or
touching the network/filesystem, so unit tests and ``bootstrap_test`` wiring
can resolve a scanner via ``SCANNERS.create("fake")``.  Its ``scan`` is
fail-open and deterministic: the same configured findings are returned for
any target path, and it never raises.
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.models import Finding, ScanResult, ScanResultStatus
from caliper.data.scanners import SCANNERS
from caliper.data.scanners.base import ScannerPort


class FakeScanner:
    """A scanner that returns a fixed, configurable result for any target."""

    def __init__(self, name: str = "fake", findings: list[Finding] | None = None) -> None:
        self._name = name
        self._findings = list(findings or [])

    @property
    def name(self) -> str:
        return self._name

    def scan(self, target_path: Path) -> ScanResult:
        return ScanResult(
            tool_name=self._name,
            status=ScanResultStatus.success,
            findings=list(self._findings),
            duration_seconds=0.0,
            message=f"{len(self._findings)} findings (fake)",
        )


@SCANNERS.register("fake")
def build_fake_scanner(
    *,
    name: str = "fake",
    findings: list[Finding] | None = None,
) -> ScannerPort:
    """Construct a deterministic FakeScanner. Does no I/O."""
    return FakeScanner(name=name, findings=findings)
