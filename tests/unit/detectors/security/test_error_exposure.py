"""Tests for Error Exposure detector.
# tested-by: tests/unit/detectors/security/test_error_exposure.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.security.error_exposure import ErrorExposureDetector


class TestErrorExposureDetector:
    """Tests for ErrorExposureDetector (CAL-002)."""

    @pytest.fixture
    def detector(self):
        return ErrorExposureDetector()

    def test_detects_exc_in_fstring(self, detector):
        """Detects exception variable in f-string."""
        code = """
try:
    risky_op()
except Exception as exc:
    return f"Error: {exc}"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-002"
        assert "exc" in findings[0].message

    def test_detects_exc_in_str_format(self, detector):
        """Detects exception variable in % formatting."""
        code = """
try:
    risky_op()
except ValueError as exc:
    return "Error: %s" % exc
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_detects_exc_in_dot_format(self, detector):
        """Detects exception variable in .format()."""
        code = """
try:
    risky_op()
except Exception as exc:
    return "Error: {}".format(exc)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_no_exception_variable(self, detector):
        """No finding when exception has no variable."""
        code = """
try:
    risky_op()
except Exception:
    return "An error occurred"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_safe_exc_usage(self, detector):
        """No finding when exc is logged but not exposed."""
        code = """
try:
    risky_op()
except Exception as exc:
    logger.error("Internal error: %s", exc)
    return "An error occurred"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_multiple_handlers(self, detector):
        """Detects violations in multiple exception handlers."""
        code = """
try:
    risky_op()
except ValueError as exc:
    return f"Value error: {exc}"
except TypeError as exc:
    return f"Type error: {exc}"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 2
