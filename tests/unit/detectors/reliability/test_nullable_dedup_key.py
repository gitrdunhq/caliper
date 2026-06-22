"""Tests for NullableDedupKeyDetector.
# tested-by: tests/unit/detectors/reliability/test_nullable_dedup_key.py
"""

from __future__ import annotations

import pytest

from caliper.detectors.reliability.nullable_dedup_key import NullableDedupKeyDetector


class TestNullableDedupKeyDetector:
    """Tests for NullableDedupKeyDetector (CAL-019)."""

    @pytest.fixture
    def detector(self):
        return NullableDedupKeyDetector()

    def test_flags_unguarded_advisory_id_in_tuple_key(self, detector, tmp_path):
        """Detects unguarded advisory_id used directly in a tuple dedup key."""
        code = "key = (f.advisory_id, f.category, f.package_name)\n"
        target = tmp_path / "normalizer.py"
        target.write_text(code)

        findings = detector.detect(target)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-019"

    def test_clean_with_or_empty_string_guard(self, detector, tmp_path):
        """No finding when advisory_id is guarded with 'or \"\"'."""
        code = 'key = (f.advisory_id or "", f.category, f.package_name)\n'
        target = tmp_path / "normalizer.py"
        target.write_text(code)

        findings = detector.detect(target)

        assert len(findings) == 0

    def test_clean_without_advisory_id(self, detector, tmp_path):
        """No finding when tuple key does not include advisory_id."""
        code = "key = (f.category, f.package_name, f.version)\n"
        target = tmp_path / "normalizer.py"
        target.write_text(code)

        findings = detector.detect(target)

        assert len(findings) == 0

    def test_clean_with_preceding_if_guard(self, detector, tmp_path):
        """No finding when advisory_id is guarded by a preceding if statement."""
        code = "if f.advisory_id:\n    key = (f.advisory_id, f.category, f.package_name)\n"
        target = tmp_path / "normalizer.py"
        target.write_text(code)

        findings = detector.detect(target)

        assert len(findings) == 0
