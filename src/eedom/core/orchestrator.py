"""Scanner orchestrator.
# tested-by: tests/unit/test_orchestrator.py

Runs all scanners in parallel using a ThreadPoolExecutor with individual and
combined timeout enforcement. All failures are captured in ScanResult objects —
the orchestrator never raises.
"""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError, as_completed
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from eedom.core.models import ScanResult

if TYPE_CHECKING:
    from eedom.core.ports import ScannerPort

logger = structlog.get_logger()


class ScanOrchestrator:
    """Runs a list of scanners in parallel with combined timeout enforcement."""

    def __init__(self, scanners: list[ScannerPort], combined_timeout: int) -> None:
        self._scanners = scanners
        self._combined_timeout = combined_timeout

    def run(self, target_path: Path) -> list[ScanResult]:
        """Execute all scanners in parallel and return their results.

        - Each scanner's own timeout is handled internally by the scanner.
        - A combined wall-clock timeout across all scanners is enforced here:
          once exceeded, any scanner that has not yet completed is marked skipped.
        - Results are returned in the same order as the input scanner list.
        - Never raises.
        """
        if not self._scanners:
            return []

        wall_start = time.monotonic()
        log = logger.bind(target=str(target_path), scanner_count=len(self._scanners))

        results_by_index: dict[int, ScanResult] = {}

        executor = ThreadPoolExecutor(max_workers=len(self._scanners))
        future_to_idx: dict[Future[ScanResult], int] = {
            executor.submit(scanner.scan, target_path): i
            for i, scanner in enumerate(self._scanners)
        }

        remaining = max(0.0, self._combined_timeout - (time.monotonic() - wall_start))

        try:
            for future in as_completed(future_to_idx, timeout=remaining):
                idx = future_to_idx[future]
                scanner = self._scanners[idx]
                try:
                    result = future.result()
                except Exception as exc:
                    log.error(
                        "orchestrator.scanner_exception",
                        scanner=scanner.name,
                        error=str(exc),
                    )
                    result = ScanResult.failed(scanner.name, str(exc))
                log.info(
                    "orchestrator.scanner_complete",
                    scanner=scanner.name,
                    status=result.status,
                )
                results_by_index[idx] = result
        except TimeoutError:
            log.warning(
                "orchestrator.combined_timeout",
                elapsed=time.monotonic() - wall_start,
            )
            executor.shutdown(wait=False, cancel_futures=True)
        else:
            executor.shutdown(wait=True)

        # Any scanner that did not complete within the combined timeout → skipped
        for i, scanner in enumerate(self._scanners):
            if i not in results_by_index:
                log.warning("orchestrator.scanner_skipped", scanner=scanner.name)
                results_by_index[i] = ScanResult.skipped(
                    scanner.name, "combined timeout exceeded — scanner skipped"
                )

        # Return results in original scanner order
        ordered = [results_by_index[i] for i in range(len(self._scanners))]
        total_elapsed = time.monotonic() - wall_start
        log.info("orchestrator.complete", total_elapsed=total_elapsed, results=len(ordered))
        return ordered
