"""Scanner port and subprocess utilities.
# tested-by: tests/unit/test_scanner_base.py

Provides the ``ScannerPort`` structural contract and safe subprocess
execution with explicit timeouts. All subprocess failures are captured as
return values — nothing in this module raises on scanner errors.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable

import structlog

from eedom.core.models import ScanResult

logger = structlog.get_logger()


def run_subprocess_with_timeout(
    cmd: list[str],
    timeout: int,
    cwd: Path | None = None,
) -> tuple[int | None, str, str]:
    """Run a subprocess with an explicit timeout.

    Returns:
        (returncode, stdout, stderr) — returncode is None on timeout or OSError.
        Never raises.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.warning("subprocess.timeout", cmd=cmd[0], timeout=timeout)
        return None, "", "timeout exceeded"
    except OSError as exc:
        logger.warning("subprocess.oserror", cmd=cmd[0], error=str(exc))
        return None, "", str(exc)


def _make_timeout_result(scanner_name: str, timeout: int) -> ScanResult:
    """Thin wrapper — delegates to ScanResult.timeout()."""
    return ScanResult.timeout(scanner_name, timeout)


def _make_failed_result(scanner_name: str, message: str) -> ScanResult:
    """Thin wrapper — delegates to ScanResult.failed()."""
    return ScanResult.failed(scanner_name, message)


def _make_not_installed_result(scanner_name: str) -> ScanResult:
    """Thin wrapper — delegates to ScanResult.not_installed()."""
    return ScanResult.not_installed(scanner_name)


@runtime_checkable
class ScannerPort(Protocol):
    """Structural contract for all dependency scanners.

    An implementation exposes a human-readable ``name`` and a ``scan`` method
    that returns a ``ScanResult`` and never raises — failures are represented
    via ``ScanResult.status`` (fail-open).  Adapters self-register against the
    ``SCANNERS`` registry; no inheritance is required.
    """

    @property
    def name(self) -> str:
        """Human-readable scanner identifier (e.g. 'syft', 'trivy')."""
        ...

    def scan(self, target_path: Path) -> ScanResult:
        """Execute the scan against *target_path* and return a result."""
        ...


# Backward-compatible alias. Existing type hints (``core.orchestrator``) and
# the detector subclass (``detectors.scanner.DeterministicScanner``) still
# reference ``Scanner``; it now names the structural port.
Scanner = ScannerPort
