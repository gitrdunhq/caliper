"""Syft SBOM scanner.
# tested-by: tests/unit/test_syft_scanner.py

Generates a CycloneDX SBOM for a target directory and writes the raw
JSON to the evidence directory. SBOM generation produces no findings —
the output is consumed by downstream vulnerability scanners.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import structlog

from eedom.core.models import ScanResult, ScanResultStatus
from eedom.data.scanners import SCANNERS
from eedom.data.scanners.base import ScannerPort, run_subprocess_with_timeout

logger = structlog.get_logger()

_TIMEOUT = 60


class SyftScanner:
    """Generates a CycloneDX SBOM using Syft."""

    def __init__(self, evidence_dir: Path, timeout: int = _TIMEOUT) -> None:
        self._evidence_dir = evidence_dir
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "syft"

    def scan(self, target_path: Path) -> ScanResult:
        start = time.monotonic()
        log = logger.bind(scanner=self.name, target=str(target_path))

        cmd = ["syft", f"dir:{target_path}", "-o", "cyclonedx-json"]
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
            return ScanResult.failed(self.name, stderr or f"syft exited with code {returncode}")

        # Parse CycloneDX JSON
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("scanner.parse_error", error=str(exc))
            return ScanResult.failed(self.name, f"failed to parse syft output: {exc}")

        components = data.get("components", [])
        component_count = len(components)

        # Write evidence
        raw_output_path: str | None = None
        try:
            self._evidence_dir.mkdir(parents=True, exist_ok=True)
            evidence_file = (self._evidence_dir / "syft-sbom.json").resolve()
            if not evidence_file.is_relative_to(self._evidence_dir.resolve()):
                raise OSError("evidence path escapes evidence directory")
            evidence_file.write_text(stdout, encoding="utf-8")
            raw_output_path = str(evidence_file)
        except OSError as exc:
            log.warning("scanner.evidence_write_failed", error=str(exc))

        log.info("scanner.complete", components=component_count, elapsed=elapsed)
        return ScanResult(
            tool_name=self.name,
            status=ScanResultStatus.success,
            findings=[],
            raw_output_path=raw_output_path,
            message=f"SBOM generated: {component_count} components detected",
            duration_seconds=elapsed,
        )


@SCANNERS.register("syft")
def build_syft_scanner(
    *,
    evidence_dir: Path | None = None,
    timeout: int = _TIMEOUT,
) -> ScannerPort:
    """Construct a SyftScanner.

    ``evidence_dir`` defaults to the current directory; it is only touched
    during ``scan`` (never at construction), so the factory does no I/O.
    """
    return SyftScanner(evidence_dir=evidence_dir or Path("."), timeout=timeout)
