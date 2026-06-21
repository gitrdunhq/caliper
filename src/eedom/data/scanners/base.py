"""Scanner port and subprocess utilities.
# tested-by: tests/unit/test_scanner_base.py

Provides the ``ScannerPort`` structural contract and safe subprocess
execution with explicit timeouts. All subprocess failures are captured as
return values — nothing in this module raises on scanner errors.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import structlog

from eedom.core.models import ScanResult

# ScannerPort is owned by core (the port lives with the other hexagonal
# contracts); re-exported here so adapters and the orchestrator keep importing
# it from the scanners package. ``Scanner`` is the backward-compat alias.
from eedom.core.ports import ScannerPort

Scanner = ScannerPort

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
