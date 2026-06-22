"""Tests for Path Construction detector.
# tested-by: tests/unit/detectors/reliability/test_path_construction.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.reliability.path_construction import PathConstructionDetector


class TestPathConstructionDetector:
    """Tests for PathConstructionDetector (CAL-008)."""

    @pytest.fixture
    def detector(self):
        return PathConstructionDetector()

    def test_detects_string_concatenation_for_path(self, detector):
        """Detects path built with string concatenation."""
        code = """
def read_file(filename):
    path = "/data/" + filename
    return open(path).read()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-008"

    def test_detects_fstring_for_path(self, detector):
        """Detects path built with f-string."""
        code = """
def read_file(filename):
    path = f"/data/{filename}"
    return open(path).read()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_detects_percent_formatting_for_path(self, detector):
        """Detects path built with % formatting."""
        code = """
def read_file(filename):
    path = "/data/%s" % filename
    return open(path).read()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_pathlib_usage(self, detector):
        """No finding when using pathlib."""
        code = """
from pathlib import Path

def read_file(filename):
    path = Path("/data") / filename
    return path.read_text()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_os_path_join(self, detector):
        """No finding when using os.path.join."""
        code = """
import os

def read_file(filename):
    path = os.path.join("/data", filename)
    return open(path).read()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_multiple_violations(self, detector):
        """Detects multiple path construction violations."""
        code = """
def read_file(filename):
    path1 = "/data/" + filename
    path2 = f"/tmp/{filename}"
    return open(path1).read(), open(path2).read()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 2
