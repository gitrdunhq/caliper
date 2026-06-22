"""Tests for DockerPinDriftDetector.
# tested-by: tests/unit/detectors/config/test_docker_pin_drift.py
"""

from __future__ import annotations

import pytest

from caliper.detectors.config.docker_pin_drift import DockerPinDriftDetector


class TestDockerPinDriftDetector:
    """Tests for DockerPinDriftDetector (CAL-018)."""

    @pytest.fixture
    def detector(self):
        return DockerPinDriftDetector()

    def test_detects_pip_version_pin(self, detector, tmp_path):
        """Detects hardcoded pip version pin as potential drift from pyproject.toml."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12-slim\n" "RUN pip install mypkg==1.2.3\n")

        findings = detector.detect(dockerfile)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-018"
        assert "pyproject.toml" in findings[0].message

    def test_detects_latest_image_tag(self, detector, tmp_path):
        """Detects moving ':latest' image tag."""
        dockerfile = tmp_path / "Dockerfile.test"
        dockerfile.write_text(
            "FROM python:3.12-slim\n"
            "COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv\n"
        )

        findings = detector.detect(dockerfile)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-018"
        assert ":latest" in findings[0].message

    def test_detects_both_patterns(self, detector, tmp_path):
        """Both pip pin and :latest tag in same file produce two findings."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim\n"
            "COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv\n"
            "RUN pip install agent-framework-github-copilot==1.0.0b260423\n"
        )

        findings = detector.detect(dockerfile)

        assert len(findings) == 2
        detector_ids = {f.detector_id for f in findings}
        assert detector_ids == {"CAL-018"}

    def test_clean_dockerfile_no_findings(self, detector, tmp_path):
        """Dockerfile with no pip pins and no :latest tag produces no findings."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim\n"
            "COPY --from=ghcr.io/astral-sh/uv:0.4.20 /uv /usr/local/bin/uv\n"
            "RUN uv sync --frozen\n"
        )

        findings = detector.detect(dockerfile)

        assert len(findings) == 0

    def test_python_file_not_applicable(self, detector, tmp_path):
        """Python files are not targeted — detect_safe skips them via is_applicable."""
        py_file = tmp_path / "main.py"
        py_file.write_text("pip install mypkg==1.2.3\n")

        assert not detector.is_applicable(py_file)
        assert detector.detect_safe(py_file) == []

    def test_line_numbers_are_one_indexed(self, detector, tmp_path):
        """Finding line_number must be >= 1."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("RUN pip install mypkg==1.2.3\n")

        findings = detector.detect(dockerfile)

        assert len(findings) == 1
        assert findings[0].line_number >= 1

    def test_does_not_raise_on_unreadable_file(self, detector, tmp_path):
        """detect() must never raise — returns empty list on error."""
        nonexistent = tmp_path / "Dockerfile"
        # File does not exist — should not raise
        findings = detector.detect(nonexistent)
        assert findings == []


# ---------------------------------------------------------------------------
# Regression P14-2 — pip regex must be word-boundary anchored so "mypip install"
# is NOT flagged as a pip version pin.
# ---------------------------------------------------------------------------


class TestDockerPinDriftPipRegexRegression:
    """Regression for P14-2: the original _PIP_PIN_RE matched any substring containing
    'pip install', so 'mypip install x==1' was falsely flagged.  The fix adds \\b
    so only the word 'pip' at a word boundary matches."""

    @pytest.fixture
    def detector(self):
        return DockerPinDriftDetector()

    def test_mypip_install_not_flagged(self, detector, tmp_path):
        """'mypip install package==1.0' must NOT be flagged — 'mypip' is not 'pip'
        (regression for P14-2: _PIP_PIN_RE lacked word boundary anchor)."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12-slim\nRUN mypip install requests==2.28.0\n")

        findings = detector.detect(dockerfile)

        pip_findings = [f for f in findings if "pyproject.toml" in f.message]
        assert len(pip_findings) == 0, (
            f"'mypip install' must NOT be flagged as a pip pin (P14-2 regression), "
            f"got findings: {pip_findings!r}"
        )

    def test_pip_install_is_still_flagged(self, detector, tmp_path):
        """'pip install package==1.0' must still be flagged (positive case preserved)."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12-slim\nRUN pip install requests==2.28.0\n")

        findings = detector.detect(dockerfile)

        pip_findings = [f for f in findings if "pyproject.toml" in f.message]
        assert (
            len(pip_findings) == 1
        ), f"'pip install' must still be flagged — got findings: {pip_findings!r}"

    def test_uv_pip_install_is_flagged(self, detector, tmp_path):
        """'uv pip install package==1.0' contains 'pip install' at a word boundary
        and must be flagged (pip is a distinct word even after 'uv ')."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12-slim\nRUN uv pip install requests==2.28.0\n")

        findings = detector.detect(dockerfile)

        # 'uv pip install' — 'pip' is a word by itself here, so must be flagged
        pip_findings = [f for f in findings if "pyproject.toml" in f.message]
        assert (
            len(pip_findings) == 1
        ), "'uv pip install' must be flagged — 'pip' is a word boundary match"
