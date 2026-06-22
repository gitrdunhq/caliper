"""OSV-Scanner vulnerability scanner.
# tested-by: tests/unit/test_osv_scanner.py

Invokes osv-scanner to detect known vulnerabilities against lockfiles
or SBOM inputs and maps results into Finding objects.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import structlog

from caliper.core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanResult,
    ScanResultStatus,
)
from caliper.data.scanners import SCANNERS
from caliper.data.scanners.base import ScannerPort, run_subprocess_with_timeout

logger = structlog.get_logger()

_TIMEOUT = 60

_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.critical,
    "HIGH": FindingSeverity.high,
    "MODERATE": FindingSeverity.medium,
    "MEDIUM": FindingSeverity.medium,
    "LOW": FindingSeverity.low,
}


class OsvScanner:
    """Detects known vulnerabilities using osv-scanner."""

    def __init__(
        self,
        sbom_path: Path | None = None,
        exclude_paths: list[str] | None = None,
    ) -> None:
        self._sbom_path = sbom_path
        self._exclude_paths: list[str] = exclude_paths or []

    @property
    def name(self) -> str:
        return "osv-scanner"

    def scan(self, target_path: Path) -> ScanResult:
        start = time.monotonic()
        log = logger.bind(scanner=self.name, target=str(target_path))

        if self._sbom_path is not None:
            cmd = ["osv-scanner", "--format", "json", "--sbom", str(self._sbom_path)]
        else:
            exclude_flags = [f"--experimental-exclude={p}" for p in self._exclude_paths]
            cmd = ["osv-scanner", "--format", "json", *exclude_flags, "-r", str(target_path)]

        returncode, stdout, stderr = run_subprocess_with_timeout(cmd=cmd, timeout=_TIMEOUT)
        elapsed = time.monotonic() - start

        # Timeout
        if returncode is None and stderr == "timeout exceeded":
            log.warning("scanner.timeout")
            return ScanResult.timeout(self.name, _TIMEOUT)

        # Binary not found
        if returncode is None:
            log.warning("scanner.not_installed", error=stderr)
            return ScanResult.not_installed(self.name)

        # osv-scanner exits 1 when vulnerabilities are found — that is not an error.
        # Exit codes >= 2 are actual errors.
        if returncode not in (0, 1):
            log.warning("scanner.failed", returncode=returncode, stderr=stderr)
            return ScanResult.failed(
                self.name, stderr or f"osv-scanner exited with code {returncode}"
            )

        # Parse JSON
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("scanner.parse_error", error=str(exc))
            return ScanResult.failed(self.name, f"failed to parse osv-scanner output: {exc}")

        findings = _extract_findings(data)
        log.info("scanner.complete", findings=len(findings), elapsed=elapsed)

        return ScanResult(
            tool_name=self.name,
            status=ScanResultStatus.success,
            findings=findings,
            duration_seconds=elapsed,
            message=f"{len(findings)} vulnerabilities found",
        )


@SCANNERS.register("osv")
def build_osv_scanner(
    *,
    sbom_path: Path | None = None,
    exclude_paths: list[str] | None = None,
) -> ScannerPort:
    """Construct an OsvScanner.

    The per-call 60s timeout stays inside ``OsvScanner.scan`` — the factory
    does no I/O.  ``exclude_paths`` (sourced from ``config/scan-exclusions.toml``
    via ``osv_exclude_paths``) is threaded straight through.
    """
    return OsvScanner(sbom_path=sbom_path, exclude_paths=exclude_paths)


def _extract_findings(data: dict) -> list[Finding]:
    """Walk the OSV-Scanner results structure and build Finding objects."""
    findings: list[Finding] = []

    for result_block in data.get("results", []):
        for pkg_block in result_block.get("packages", []):
            pkg_info = pkg_block.get("package", {})
            pkg_name = pkg_info.get("name", "unknown")
            pkg_version = pkg_info.get("version", "unknown")

            for vuln in pkg_block.get("vulnerabilities", []):
                advisory_id = vuln.get("id", "")
                summary = vuln.get("summary", "")
                severity = _map_severity(vuln)
                aliases = vuln.get("aliases", [])
                advisory_url = _best_url(aliases)

                findings.append(
                    Finding(
                        severity=severity,
                        category=FindingCategory.vulnerability,
                        description=summary,
                        source_tool="osv-scanner",
                        package_name=pkg_name,
                        version=pkg_version,
                        advisory_id=advisory_id,
                        advisory_url=advisory_url,
                    )
                )

    return findings


def _cvss_score_to_severity(score: float) -> FindingSeverity:
    """Map a CVSS numeric base score (0–10) to FindingSeverity.

    Thresholds follow the NVD / CVSS v3 rating scale:
        Critical  >= 9.0
        High      >= 7.0
        Medium    >= 4.0
        Low        < 4.0
    """
    if score >= 9.0:
        return FindingSeverity.critical
    if score >= 7.0:
        return FindingSeverity.high
    if score >= 4.0:
        return FindingSeverity.medium
    return FindingSeverity.low


def _map_severity(vuln: dict) -> FindingSeverity:
    """Map OSV severity to FindingSeverity.

    Priority:
    1. database_specific.severity (string label — most reliable)
    2. severity[] entries — try numeric score parse, then CVSS vector heuristic
    3. Fall back to info if no usable data found
    """
    # Try database_specific.severity first (more reliable)
    db_severity = (vuln.get("database_specific") or {}).get("severity", "")
    if db_severity:
        mapped = _SEVERITY_MAP.get(db_severity.upper())
        if mapped is not None:
            return mapped

    # Fall back to CVSS severity list
    for sev_entry in vuln.get("severity", []):
        score_str = sev_entry.get("score", "")
        if not score_str:
            continue

        # Try direct numeric score (e.g. "7.5")
        try:
            return _cvss_score_to_severity(float(score_str))
        except ValueError:
            logger.debug("cvss.parse_error", score_str=score_str)

        # CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        # Approximate base score from impact metrics — no external library needed.
        # Each :H (High) component contributes ~2.5; network reachability adds 2.0.
        if "CVSS:3" in score_str or "CVSS:2" in score_str:
            high_count = score_str.count(":H")
            network_reachable = "AV:N" in score_str
            approx_score = min((high_count * 2.5) + (2.0 if network_reachable else 0.0), 10.0)
            return _cvss_score_to_severity(approx_score)

    return FindingSeverity.info


def _best_url(aliases: list[str]) -> str | None:
    """Pick the best advisory URL from OSV aliases."""
    for alias in aliases:
        if alias.startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{alias}"
    return None
