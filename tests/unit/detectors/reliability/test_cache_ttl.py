"""Tests for Cache TTL detector.
# tested-by: tests/unit/detectors/reliability/test_cache_ttl.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.reliability.cache_ttl import CacheTTLDetector


class TestCacheTTLDetector:
    """Tests for CacheTTLDetector (CAL-009)."""

    @pytest.fixture
    def detector(self):
        return CacheTTLDetector()

    def test_detects_cache_lookup_without_ttl_check(self, detector):
        """Detects cache.get() without TTL/freshness check."""
        code = """
import redis

r = redis.Redis()

def get_user(user_id):
    cached = r.get(f"user:{user_id}")
    if cached:
        return json.loads(cached)
    user = fetch_from_db(user_id)
    r.setex(f"user:{user_id}", 3600, json.dumps(user))
    return user
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-009"

    def test_detects_dict_cache_without_freshness(self, detector):
        """Detects dict cache lookup without freshness check."""
        code = """
_cache = {}

def get_data(key):
    if key in _cache:
        return _cache[key]
    value = expensive_compute(key)
    _cache[key] = value
    return value
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_cache_with_ttl_check(self, detector):
        """No finding when TTL is checked."""
        code = """
import redis
import time

r = redis.Redis()

def get_user(user_id):
    cached = r.get(f"user:{user_id}")
    ttl = r.ttl(f"user:{user_id}")
    if cached and ttl > 0:
        return json.loads(cached)
    user = fetch_from_db(user_id)
    r.setex(f"user:{user_id}", 3600, json.dumps(user))
    return user
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_no_cache_usage(self, detector):
        """No finding when no cache is used."""
        code = """
def get_user(user_id):
    return fetch_from_db(user_id)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0
