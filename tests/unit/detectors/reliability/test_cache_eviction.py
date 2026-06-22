"""Tests for Cache Eviction detector.
# tested-by: tests/unit/detectors/reliability/test_cache_eviction.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.reliability.cache_eviction import CacheEvictionDetector


class TestCacheEvictionDetector:
    """Tests for CacheEvictionDetector (CAL-006)."""

    @pytest.fixture
    def detector(self):
        return CacheEvictionDetector()

    def test_detects_bare_cache_decorator(self, detector):
        """Detects @cache without maxsize."""
        code = """
from functools import cache

@cache
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-006"
        assert "without maxsize" in findings[0].message

    def test_detects_lru_cache_without_maxsize(self, detector):
        """Detects @lru_cache() without maxsize argument."""
        code = """
from functools import lru_cache

@lru_cache()
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_lru_cache_with_maxsize(self, detector):
        """No finding when maxsize is specified."""
        code = """
from functools import lru_cache

@lru_cache(maxsize=128)
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_multiple_unbounded_caches(self, detector):
        """Detects multiple unbounded cache decorators."""
        code = """
from functools import cache, lru_cache

@cache
def get_users():
    return fetch_users()

@lru_cache()
def get_items():
    return fetch_items()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 2


class TestCacheEvictionRegressions:
    """Regression tests for P13-10 fix: lru_cache(maxsize=None) treated as UNBOUNDED (#432).

    Before the fix, maxsize=None was accepted as a bounded cache because the
    check only tested for the *presence* of the maxsize keyword, not its value.
    Python documents maxsize=None as equivalent to @cache (unbounded growth).
    """

    @pytest.fixture
    def detector(self):
        return CacheEvictionDetector()

    def test_lru_cache_maxsize_none_is_flagged(self, detector):
        """P13-10: @lru_cache(maxsize=None) must be flagged as UNBOUNDED.

        None is Python's documented way of making lru_cache grow without
        limit — identical to @cache.  This was a false negative before the fix.
        """
        code = """
from functools import lru_cache

@lru_cache(maxsize=None)
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 1, "@lru_cache(maxsize=None) must be flagged as an unbounded cache"
        assert findings[0].detector_id == "CAL-006"

    def test_lru_cache_maxsize_128_not_flagged(self, detector):
        """P13-10: @lru_cache(maxsize=128) must NOT be flagged (no regression)."""
        code = """
from functools import lru_cache

@lru_cache(maxsize=128)
def get_data(key):
    return expensive_lookup(key)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert (
            len(findings) == 0
        ), "@lru_cache(maxsize=128) must NOT be flagged — it has a bounded eviction policy"

    def test_lru_cache_maxsize_zero_not_flagged(self, detector):
        """@lru_cache(maxsize=0) effectively disables caching — not unbounded, not flagged."""
        code = """
from functools import lru_cache

@lru_cache(maxsize=0)
def no_cache(key):
    return compute(key)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        # maxsize=0 disables caching entirely (no memory growth) so not an OOM risk
        assert (
            len(findings) == 0
        ), "@lru_cache(maxsize=0) does not accumulate entries — should not be flagged"
