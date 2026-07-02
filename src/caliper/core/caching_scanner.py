"""Read-through cache wrapper around a ScannerPort (ADR-010).
# tested-by: tests/unit/test_caching_scanner.py

Pure composition of two ports — no I/O of its own, so it belongs in ``core`` alongside
the ports it composes. The pipeline wraps each scanner with this before handing the list
to ``ScanOrchestrator``, so the orchestrator's parallel/timeout logic is untouched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from caliper.core.models import ScanResultStatus

if TYPE_CHECKING:
    from pathlib import Path

    from caliper.core.models import ScanResult
    from caliper.core.ports import ScanCachePort, ScannerPort


class CachingScanner:
    """Wraps a ScannerPort with a read-through ScanCachePort.

    A cache hit for ``cache_key`` skips the wrapped scanner entirely. Only a
    ``success`` result is ever written back — SAFETY: a failed/timeout/skipped result
    is never cached, so a transient failure can never poison a future run with a false
    "clean" result.
    """

    def __init__(self, scanner: ScannerPort, cache: ScanCachePort, cache_key: str) -> None:
        self._scanner = scanner
        self._cache = cache
        self._cache_key = cache_key

    @property
    def name(self) -> str:
        return self._scanner.name

    def scan(self, target_path: Path) -> ScanResult:
        cached = self._cache.get(self._cache_key)
        if cached is not None:
            return cached

        result = self._scanner.scan(target_path)
        if result.status == ScanResultStatus.success:
            self._cache.put(self._cache_key, result)
        return result
