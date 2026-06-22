"""Tests for Subprocess Timeout detector.
# tested-by: tests/unit/detectors/reliability/test_subprocess_timeout.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.reliability.subprocess_timeout import SubprocessTimeoutDetector


class TestSubprocessTimeoutDetector:
    """Tests for SubprocessTimeoutDetector (CAL-012)."""

    @pytest.fixture
    def detector(self):
        return SubprocessTimeoutDetector()

    def test_detects_subprocess_run_without_timeout(self, detector):
        """Detects subprocess.run() without timeout."""
        code = """
import subprocess

def run_command(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-012"

    def test_detects_subprocess_call_without_timeout(self, detector):
        """Detects subprocess.call() without timeout."""
        code = """
import subprocess

def run_command(cmd):
    return subprocess.call(cmd, shell=True)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_detects_subprocess_check_output_without_timeout(self, detector):
        """Detects subprocess.check_output() without timeout."""
        code = """
import subprocess

def get_output(cmd):
    return subprocess.check_output(cmd, text=True)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_subprocess_with_timeout(self, detector):
        """No finding when timeout is specified."""
        code = """
import subprocess

def run_command(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_popen_with_timeout(self, detector):
        """No finding when Popen has timeout via communicate."""
        code = """
import subprocess

def run_command(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    stdout, _ = proc.communicate(timeout=30)
    return stdout
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_multiple_violations(self, detector):
        """Detects multiple subprocess calls without timeout."""
        code = """
import subprocess

def run_commands(cmds):
    for cmd in cmds:
        subprocess.run(cmd)
        subprocess.call(cmd)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 2
