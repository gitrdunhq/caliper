"""DockerPinDriftDetector - Detects pip version pins and moving image tags in Dockerfiles.
# tested-by: tests/unit/detectors/config/test_docker_pin_drift.py

GitHub issue: #229
"""

from __future__ import annotations

import re
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector

_PIP_PIN_RE = re.compile(
    r"\bpip\s+install\b.*=="
)  # \b anchors "pip" so "mypip install" doesn't match
_LATEST_TAG_RE = re.compile(r":latest\b")


@register_detector
class DockerPinDriftDetector(BugDetector):
    """Detects two Dockerfile anti-patterns that cause reproducibility drift.

    1. Hardcoded ``pip install PACKAGE==VERSION`` lines that can diverge
       from the versions locked in pyproject.toml / uv.lock.
    2. Moving ``:latest`` image tags that change silently between builds.

    GitHub: #229
    """

    @property
    def detector_id(self) -> str:
        return "CAL-018"

    @property
    def name(self) -> str:
        return "Dockerfile Pin Drift"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.configuration

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("Dockerfile", "Dockerfile.*")

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Scan Dockerfile line by line for pin-drift and moving image tags."""
        if not self.is_applicable(file_path):
            return []
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            return []

        findings: list[DetectorFinding] = []

        for lineno, line in enumerate(lines, start=1):
            if _PIP_PIN_RE.search(line):
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=lineno,
                        message=(
                            "Hardcoded pip version pin in Dockerfile may drift from "
                            "pyproject.toml/uv.lock; consume locked constraints instead"
                        ),
                        snippet=line.strip(),
                        issue_reference="#229",
                        fix_hint=(
                            "Remove inline pip pin and install deps via "
                            "'uv sync --frozen' against the committed lockfile"
                        ),
                    )
                )

            if _LATEST_TAG_RE.search(line):
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=lineno,
                        message=(
                            "Moving ':latest' image tag; pin by version or digest "
                            "for reproducible builds"
                        ),
                        snippet=line.strip(),
                        issue_reference="#229",
                        fix_hint=(
                            "Replace ':latest' with an explicit version tag or "
                            "@sha256:<digest> to lock the image"
                        ),
                    )
                )

        return findings
