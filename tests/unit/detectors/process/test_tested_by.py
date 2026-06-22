"""Tests for Tested-By Annotation detector.
# tested-by: tests/unit/detectors/process/test_tested_by.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.process.tested_by import TestedByAnnotationDetector


class TestTestedByAnnotationDetector:
    """Tests for TestedByAnnotationDetector (CAL-014)."""

    @pytest.fixture
    def detector(self):
        return TestedByAnnotationDetector()

    def test_detects_missing_annotation(self, detector):
        """Detects file without tested-by annotation."""
        code = """def foo():
    pass
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-014"
        assert "missing" in findings[0].message.lower()

    def test_ignores_file_with_annotation(self, detector):
        """No finding when tested-by annotation present."""
        code = """# tested-by: tests/unit/test_foo.py
def foo():
    pass
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            # Create the test file
            test_file = Path(f.name).parent / "tests" / "unit" / "test_foo.py"
            test_file.parent.mkdir(parents=True, exist_ok=True)
            test_file.write_text("# test file\n")

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_nonexistent_test_file(self, detector, tmp_path):
        """Detects when tested-by points to non-existent file."""
        code = """# tested-by: tests/unit/nonexistent.py
def foo():
    pass
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        findings = detector.detect(test_file)

        assert len(findings) == 1
        assert "non-existent" in findings[0].message.lower()
