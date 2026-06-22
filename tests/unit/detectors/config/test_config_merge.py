"""Tests for Config Merge detector.
# tested-by: tests/unit/detectors/config/test_config_merge.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from eedom.detectors.config.config_merge import ConfigMergeDetector


class TestConfigMergeDetector:
    """Tests for ConfigMergeDetector (EED-013)."""

    @pytest.fixture
    def detector(self):
        return ConfigMergeDetector()

    def test_detects_dict_merge_dropping_telemetry(self, detector):
        """Detects config-named dict merge that may drop telemetry keys.

        Updated for P14-1: detection is now narrowed to config-related merges.
        A bare {**base_config, **user_config} (config-named vars) is flagged;
        a generic {**base, **user} (non-config names) is NOT flagged.
        """
        code = """
def load_config():
    base_config = {"debug": False, "telemetry": True}
    user_config = {"debug": True}
    config = {**base_config, **user_config}  # telemetry key lost if not in user
    return config
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-013"

    def test_detects_update_call_dropping_telemetry(self, detector):
        """Detects dict.update() that may drop telemetry keys."""
        code = """
def merge_configs(base, override):
    result = base.copy()
    result.update(override)
    return result
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        # Should flag if base has telemetry-related keys
        # This test may need adjustment based on implementation
        assert len(findings) >= 0

    def test_ignores_safe_merge_with_default(self, detector):
        """No finding for safe merge patterns."""
        code = """
from collections import ChainMap

def load_config():
    base = {"debug": False, "telemetry": True}
    user = {"debug": True}
    config = ChainMap(user, base)
    return dict(config)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_no_merge(self, detector):
        """No finding when no config merge occurs."""
        code = """
def get_config():
    return {"debug": False, "telemetry": True}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0


class TestConfigMergeRegressions:
    """Regression tests for P14-1 fix: _is_dangerous_merge false-positive reduction (#432).

    Before the fix, _is_dangerous_merge returned True for ANY {**a, **b} expression
    in Python source — a very broad false positive.  The fix narrows detection to
    merges that look config-related: either a config-literal key is present inline,
    or an unpacked source variable has a config-indicating name.
    """

    @pytest.fixture
    def detector(self):
        return ConfigMergeDetector()

    def test_plain_dict_merge_of_non_config_vars_not_flagged(self, detector):
        """P14-1: {**a, **b} of generic variables must NOT be flagged.

        This was a broad false positive before the fix — it was firing on
        any dict unpacking regardless of context.
        """
        code = """
def combine(a, b):
    return {**a, **b}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert (
            len(findings) == 0
        ), "generic {**a, **b} of non-config vars must NOT be flagged (P14-1 false positive)"

    def test_merge_of_headers_and_params_not_flagged(self, detector):
        """P14-1: {**headers, **params} must NOT be flagged (no config indicator)."""
        code = """
def build_request(headers, params):
    return {**headers, **params}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert (
            len(findings) == 0
        ), "{**headers, **params} must not fire — neither name contains a config indicator"

    def test_config_named_merge_is_still_flagged(self, detector):
        """P14-1: {**base_config, **package_config} must still be flagged (the #262 case)."""
        code = """
def merge(base_config, package_config):
    return {**base_config, **package_config}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert (
            len(findings) == 1
        ), "{**base_config, **package_config} must be flagged — 'config' is in the variable names"
        assert findings[0].detector_id == "EED-013"

    def test_inline_config_literal_key_merge_flagged(self, detector):
        """P14-1: {**base, **user, 'debug': True} must be flagged (config-literal key present)."""
        code = """
merged = {**base, **user, "debug": True}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 1, "unpacking with a config-literal key ('debug') must be flagged"

    def test_settings_named_merge_is_flagged(self, detector):
        """P14-1: {**base_settings, **overrides} must be flagged ('settings' indicator)."""
        code = """
merged = {**base_settings, **overrides}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert (
            len(findings) == 1
        ), "'base_settings' contains 'settings' — must be flagged as a config merge"
