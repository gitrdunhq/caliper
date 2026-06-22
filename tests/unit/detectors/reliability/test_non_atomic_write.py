"""Tests for NonAtomicWriteDetector (CAL-021).
# tested-by: tests/unit/detectors/reliability/test_non_atomic_write.py
"""

from __future__ import annotations

import pytest

from caliper.detectors.reliability.non_atomic_write import NonAtomicWriteDetector


class TestNonAtomicWriteDetector:
    """Tests for NonAtomicWriteDetector (CAL-021)."""

    @pytest.fixture
    def detector(self):
        return NonAtomicWriteDetector()

    # ------------------------------------------------------------------
    # Detector metadata
    # ------------------------------------------------------------------

    def test_detector_id(self, detector):
        assert detector.detector_id == "CAL-021"

    def test_category_is_reliability(self, detector):
        from caliper.detectors.categories import DetectorCategory

        assert detector.category == DetectorCategory.reliability

    def test_target_files_python_only(self, detector):
        assert detector.target_files == ("*.py",)

    # ------------------------------------------------------------------
    # Buggy: direct .write_bytes() with no atomic rename nearby → 1 finding
    # ------------------------------------------------------------------

    def test_detects_write_bytes_without_atomic_rename(self, detector, tmp_path):
        """Direct write_bytes() with no rename/replace nearby is flagged."""
        code = """\
def save(target, data):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return str(target)
"""
        f = tmp_path / "persistence.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-021"
        assert findings[0].line_number >= 1

    def test_detects_write_text_without_atomic_rename(self, detector, tmp_path):
        """Direct write_text() with no rename/replace nearby is flagged."""
        code = """\
def dump(path, content):
    path.write_text(content, encoding="utf-8")
"""
        f = tmp_path / "dump.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-021"

    def test_finding_message_mentions_atomic_rename(self, detector, tmp_path):
        """Finding message explains the crash-safety issue."""
        code = "target.write_bytes(data)\n"
        f = tmp_path / "bad.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 1
        msg = findings[0].message
        assert "atomic" in msg.lower() or "replace" in msg.lower() or "rename" in msg.lower()

    def test_finding_issue_reference(self, detector, tmp_path):
        """Finding carries the issue reference #232."""
        code = "path.write_bytes(b'data')\n"
        f = tmp_path / "ref.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].issue_reference is not None
        assert "232" in findings[0].issue_reference

    # ------------------------------------------------------------------
    # Clean: atomic pattern with .replace() nearby → 0 findings
    # ------------------------------------------------------------------

    def test_clean_write_bytes_followed_by_replace(self, detector, tmp_path):
        """write_bytes() to a temp path + .replace() is the atomic pattern — no finding."""
        code = """\
import tempfile
from pathlib import Path

def atomic_write(target: Path, data: bytes) -> None:
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(target)
"""
        f = tmp_path / "atomic.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_clean_write_bytes_preceded_by_os_rename(self, detector, tmp_path):
        """write_bytes() near os.rename() is considered atomic — no finding."""
        code = """\
import os
from pathlib import Path

def store(target: Path, data: bytes) -> None:
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.rename(str(tmp), str(target))
"""
        f = tmp_path / "store.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_clean_write_bytes_with_path_rename(self, detector, tmp_path):
        """write_bytes() near Path.rename() is considered atomic — no finding."""
        code = """\
from pathlib import Path

def put(target: Path, data: bytes) -> None:
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.rename(target)
"""
        f = tmp_path / "put.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_clean_write_bytes_with_shutil_move(self, detector, tmp_path):
        """write_bytes() near shutil.move() is considered atomic — no finding."""
        code = """\
import shutil
from pathlib import Path

def move_write(target: Path, data: bytes) -> None:
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(data)
    shutil.move(str(tmp), str(target))
"""
        f = tmp_path / "move_write.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 0

    # ------------------------------------------------------------------
    # Clean: no write_bytes / write_text calls at all → 0 findings
    # ------------------------------------------------------------------

    def test_clean_no_file_writes(self, detector, tmp_path):
        """File with no .write_bytes() or .write_text() → 0 findings."""
        code = """\
def compute(x, y):
    return x + y
"""
        f = tmp_path / "math.py"
        f.write_text(code)

        findings = detector.detect(f)

        assert len(findings) == 0

    # ------------------------------------------------------------------
    # Wrong file type → 0 findings
    # ------------------------------------------------------------------

    def test_yaml_file_not_applicable(self, detector, tmp_path):
        """YAML files are not targeted — detector returns 0 findings."""
        content = "key: value\n"
        f = tmp_path / "config.yaml"
        f.write_text(content)

        findings = detector.detect_safe(f)

        assert len(findings) == 0

    # ------------------------------------------------------------------
    # Robustness: detect() must never raise
    # ------------------------------------------------------------------

    def test_empty_file_returns_no_findings(self, detector, tmp_path):
        """Empty Python file returns 0 findings without raising."""
        f = tmp_path / "empty.py"
        f.write_text("")

        findings = detector.detect(f)

        assert findings == []

    def test_nonexistent_file_returns_no_findings(self, detector, tmp_path):
        """Non-existent file returns 0 findings without raising."""
        f = tmp_path / "does_not_exist.py"

        findings = detector.detect(f)

        assert findings == []
