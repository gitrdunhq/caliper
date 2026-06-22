"""BugDetector base class and framework utilities.
# tested-by: tests/unit/detectors/test_framework.py

Provides the abstract BugDetector base class that all bug detectors must
inherit from, including suppression support (# noqa: CAL-XXX pattern).
"""

from __future__ import annotations

import abc
import fnmatch
import re
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding

# Pattern to match noqa comments: "noqa" + optional codes
_NOQA_PATTERN = re.compile(
    r"#\s*noqa" + r"(?::\s*([A-Za-z0-9-]+(?:\s*,\s*[A-Za-z0-9-]+)*)?)?" + r"(?:\s*#.*)?$",
    re.IGNORECASE,
)


def _parse_noqa_codes(comment: str) -> set[str]:
    """Parse noqa comment to extract detector codes.

    Examples:
        "# noqa" -> {"all"}
        "# noqa: CAL-001" -> {"CAL-001"}
        "# noqa: CAL-001, CAL-002" -> {"CAL-001", "CAL-002"}
    """
    match = _NOQA_PATTERN.search(comment)
    if not match:
        return set()

    codes_str = match.group(1)
    if codes_str is None:
        # Bare noqa comment - suppresses all warnings on that line
        return {"all"}

    # Split by comma and clean up
    codes = {code.strip() for code in codes_str.split(",")}
    return codes


class BugDetector(abc.ABC):
    """Abstract base for all bug detectors.

    Subclasses must implement all abstract properties and the detect method.
    The detect method must never raise - it should catch all exceptions
    internally and return an empty list on errors.

    Suppression Support:
        Detectors support file-level suppression via # noqa comments:
        - # noqa: CAL-XXX - suppresses specific detector on that line
        - # noqa - suppresses all detectors on that line
    """

    @property
    @abc.abstractmethod
    def detector_id(self) -> str:
        """Unique identifier (e.g., 'CAL-001')."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name."""

    @property
    @abc.abstractmethod
    def category(self) -> DetectorCategory:
        """Bug category (security, reliability, etc.)."""

    @property
    @abc.abstractmethod
    def severity(self) -> FindingSeverity:
        """Default severity for findings from this detector."""

    @property
    def target_files(self) -> tuple[str, ...]:
        """File patterns to analyze (e.g., '*.py', 'config/*.yaml').

        Default: ('*.py',) — override for specialized detectors.
        """
        return ("*.py",)

    def is_applicable(self, file_path: Path) -> bool:
        """Check if this detector applies to the given file."""
        # Match the basename AND the full relative path, so patterns that include a
        # directory (e.g. "config/*.yaml") are not silently unmatchable.
        path_str = str(file_path).replace("\\", "/")
        return any(
            fnmatch.fnmatch(file_path.name, pattern) or fnmatch.fnmatch(path_str, pattern)
            for pattern in self.target_files
        )

    def is_suppressed(
        self, file_path: Path, line_number: int, detector_id: str | None = None
    ) -> bool:
        """Check if a finding at the given line is suppressed by a noqa comment.

        Args:
            file_path: Path to the file being analyzed
            line_number: 1-indexed line number where finding would be reported
            detector_id: Optional detector ID to check (defaults to self.detector_id)

        Returns:
            True if the finding should be suppressed, False otherwise
        """
        target_id = detector_id or self.detector_id

        try:
            with open(file_path, encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return False

        if not lines or line_number < 1 or line_number > len(lines):
            return False

        # Get the line content (line_number is 1-indexed)
        line_content = lines[line_number - 1]

        # Parse noqa codes from the line
        codes = _parse_noqa_codes(line_content)

        # Check if suppressed
        return "all" in codes or target_id in codes

    def _should_report_finding(
        self, file_path: Path, line_number: int, detector_id: str | None = None
    ) -> bool:
        """Check if a finding should be reported (not suppressed).

        This is a convenience method that returns the inverse of is_suppressed.

        Args:
            file_path: Path to the file being analyzed
            line_number: 1-indexed line number
            detector_id: Optional detector ID (defaults to self.detector_id)

        Returns:
            True if the finding should be reported, False if suppressed
        """
        return not self.is_suppressed(file_path, line_number, detector_id)

    @abc.abstractmethod
    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file and return list of findings.

        Must never raise — parse errors return empty list.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of DetectorFinding objects for any issues found
        """

    def detect_safe(self, file_path: Path) -> list[DetectorFinding]:
        """Safe wrapper around detect that catches all exceptions.

        This method ensures the detector never raises, returning an empty
        list on any error. It's used internally by the scanner.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of DetectorFinding objects (may be empty)
        """
        try:
            if not self.is_applicable(file_path):
                return []
            return self.detect(file_path)
        except Exception:
            return []
