"""Tests for CachingScanner — the read-through cache wrapper (ADR-010).

# tested-by: tests/unit/test_caching_scanner.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.caching_scanner import CachingScanner
from caliper.core.models import ScanResult, ScanResultStatus


class _FakeCache:
    def __init__(self) -> None:
        self.store: dict[str, ScanResult] = {}
        self.put_calls = 0

    def get(self, key: str) -> ScanResult | None:
        return self.store.get(key)

    def put(self, key: str, result: ScanResult) -> None:
        self.put_calls += 1
        self.store[key] = result


class _FakeScanner:
    def __init__(self, result: ScanResult) -> None:
        self._result = result
        self.name = "fake"
        self.calls = 0

    def scan(self, target_path: Path) -> ScanResult:
        self.calls += 1
        return self._result


def _result(status: ScanResultStatus) -> ScanResult:
    return ScanResult(
        tool_name="fake",
        status=status,
        findings=[],
        duration_seconds=0.1,
    )


class TestProperties:
    def test_cache_hit_skips_wrapped_scanner(self, tmp_path) -> None:
        cache = _FakeCache()
        cached_result = _result(ScanResultStatus.success)
        cache.store["k"] = cached_result
        scanner = _FakeScanner(_result(ScanResultStatus.failed))

        wrapped = CachingScanner(scanner, cache, "k")
        result = wrapped.scan(tmp_path)

        assert result == cached_result
        assert scanner.calls == 0

    def test_cache_miss_delegates_and_writes_success(self, tmp_path) -> None:
        cache = _FakeCache()
        result_obj = _result(ScanResultStatus.success)
        scanner = _FakeScanner(result_obj)

        wrapped = CachingScanner(scanner, cache, "k")
        result = wrapped.scan(tmp_path)

        assert result == result_obj
        assert scanner.calls == 1
        assert cache.store["k"] == result_obj

    @pytest.mark.parametrize(
        "status",
        [ScanResultStatus.failed, ScanResultStatus.timeout, ScanResultStatus.skipped],
    )
    def test_non_success_result_is_never_cached(self, tmp_path, status) -> None:
        """SAFETY: a failed/timeout/skipped scan can never poison a future run."""
        cache = _FakeCache()
        scanner = _FakeScanner(_result(status))

        wrapped = CachingScanner(scanner, cache, "k")
        wrapped.scan(tmp_path)

        assert cache.put_calls == 0
        assert cache.get("k") is None

    def test_name_delegates_to_wrapped_scanner(self, tmp_path) -> None:
        cache = _FakeCache()
        scanner = _FakeScanner(_result(ScanResultStatus.success))
        wrapped = CachingScanner(scanner, cache, "k")
        assert wrapped.name == scanner.name
