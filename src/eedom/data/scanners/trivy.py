"""Trivy vulnerability scanner.
# tested-by: tests/unit/test_trivy_scanner.py

Invokes trivy in filesystem mode to detect known vulnerabilities
and maps results into Finding objects.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import structlog

from eedom.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)
from eedom.data.scanners import SCANNERS
from eedom.data.scanners.base import ScannerPort, run_subprocess_with_timeout

logger = structlog.get_logger()

_TIMEOUT = 60

_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.critical,
    "HIGH": FindingSeverity.high,
    "MEDIUM": FindingSeverity.medium,
    "LOW": FindingSeverity.low,
    "UNKNOWN": FindingSeverity.info,
}


class TrivyScanner:
    """Detects known vulnerabilities using Trivy filesystem scan."""

    def __init__(self, timeout: int = _TIMEOUT) -> None:
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "trivy"

    def scan(self, target_path: Path) -> ScanResult:
        start = time.monotonic()
        log = logger.bind(scanner=self.name, target=str(target_path))

        # Skip large/irrelevant directories to prevent Errno 5 I/O errors when
        # scanning repos with heavy node_modules or build output via the container
        # overlay filesystem (see issue #352). --respect-gitignore avoids scanning
        # vendored and generated files declared in .gitignore.
        cmd = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--skip-dirs",
            "node_modules,dist,.git",
            "--respect-gitignore",
            str(target_path),
        ]
        returncode, stdout, stderr = run_subprocess_with_timeout(cmd=cmd, timeout=self._timeout)
        elapsed = time.monotonic() - start

        # Timeout
        if returncode is None and stderr == "timeout exceeded":
            log.warning("scanner.timeout")
            return ScanResult.timeout(self.name, self._timeout)

        # Binary not found
        if returncode is None:
            log.warning("scanner.not_installed", error=stderr)
            return ScanResult.not_installed(self.name)

        # Non-zero exit
        if returncode != 0:
            log.warning("scanner.failed", returncode=returncode, stderr=stderr)
            return ScanResult.failed(self.name, stderr or f"trivy exited with code {returncode}")

        # Parse JSON
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("scanner.parse_error", error=str(exc))
            return ScanResult.failed(self.name, f"failed to parse trivy output: {exc}")

        findings = _extract_findings(data)
        log.info("scanner.complete", findings=len(findings), elapsed=elapsed)

        return ScanResult(
            tool_name=self.name,
            status=ScanResultStatus.success,
            findings=findings,
            duration_seconds=elapsed,
            message=f"{len(findings)} vulnerabilities found",
        )


def _extract_findings(data: dict) -> list[Finding]:
    """Walk the Trivy JSON results and build Finding objects."""
    findings: list[Finding] = []

    for result_block in data.get("Results", []):
        vulns = result_block.get("Vulnerabilities")
        if not vulns:
            continue

        for vuln in vulns:
            advisory_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "unknown")
            version = vuln.get("InstalledVersion", "unknown")
            severity_str = vuln.get("Severity", "UNKNOWN")
            title = vuln.get("Title", "")
            description = vuln.get("Description", "")
            primary_url = vuln.get("PrimaryURL")

            severity = _SEVERITY_MAP.get(severity_str.upper(), FindingSeverity.info)

            findings.append(
                Finding(
                    severity=severity,
                    category=FindingCategory.vulnerability,
                    description=title or description,
                    source_tool="trivy",
                    package_name=pkg_name,
                    version=version,
                    advisory_id=advisory_id,
                    advisory_url=primary_url,
                )
            )

    return findings


@SCANNERS.register("trivy")
def build_trivy_scanner(*, timeout: int = _TIMEOUT) -> ScannerPort:
    """Construct a TrivyScanner. The 60s default timeout is enforced inside scan()."""
    return TrivyScanner(timeout=timeout)
