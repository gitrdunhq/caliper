"""Tests for scan cache key construction (ADR-010).

# tested-by: tests/unit/test_scan_cache_key.py
"""

from __future__ import annotations

from caliper.core.config import CaliperSettings
from caliper.core.scan_cache_key import compute_cache_key, settings_digest


class TestProperties:
    """Determinism properties for the pure key-construction functions."""

    def test_compute_cache_key_is_deterministic(self) -> None:
        a = compute_cache_key("sha1", "osv", "1.2.3", "digest")
        b = compute_cache_key("sha1", "osv", "1.2.3", "digest")
        assert a == b

    def test_compute_cache_key_changes_with_any_component(self) -> None:
        base = compute_cache_key("sha1", "osv", "1.2.3", "digest")
        assert compute_cache_key("sha2", "osv", "1.2.3", "digest") != base
        assert compute_cache_key("sha1", "trivy", "1.2.3", "digest") != base
        assert compute_cache_key("sha1", "osv", "9.9.9", "digest") != base
        assert compute_cache_key("sha1", "osv", "1.2.3", "other-digest") != base

    def test_compute_cache_key_does_not_confuse_adjacent_parts(self) -> None:
        # Without a delimiter, ("ab", "c") and ("a", "bc") would collide.
        a = compute_cache_key("ab", "c", "v", "d")
        b = compute_cache_key("a", "bc", "v", "d")
        assert a != b

    def test_settings_digest_is_deterministic(self) -> None:
        config = CaliperSettings()
        assert settings_digest(config) == settings_digest(config)

    def test_settings_digest_changes_with_scan_relevant_field(self) -> None:
        base = settings_digest(CaliperSettings())
        changed = settings_digest(CaliperSettings(scanner_timeout=999))
        assert changed != base

    def test_settings_digest_ignores_scan_irrelevant_field(self) -> None:
        # publisher/LLM-ish settings must never invalidate the scan cache.
        base = settings_digest(CaliperSettings())
        changed = settings_digest(CaliperSettings(opa_timeout=999))
        assert changed == base
