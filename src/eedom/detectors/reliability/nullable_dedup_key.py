"""NullableDedupKeyDetector - Detects unguarded advisory_id in dedup/groupby keys.
# tested-by: tests/unit/detectors/reliability/test_nullable_dedup_key.py

GitHub issues: #234
"""

from __future__ import annotations

import re
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


@register_detector
class NullableDedupKeyDetector(BugDetector):
    """Detects advisory_id used in dedup/groupby keys without a None guard.

    Reliability issue: The normalizer deduplicates findings by
    (advisory_id, category, package_name, version). When advisory_id is None,
    distinct findings collapse under the same key, silently dropping real
    vulnerabilities from the output.

    GitHub: #234
    """

    # Substrings that indicate advisory_id is guarded on the same line
    _GUARD_STRINGS: tuple[str, ...] = (
        'or ""',
        "or ''",
        'or "N/A"',
        "or 'N/A'",
        "advisory_id or",
        "advisory_id is not None",
    )

    # Pattern to detect a preceding if-guard for advisory_id
    _IF_GUARD_RE = re.compile(r"\bif\b.*advisory_id")

    @property
    def detector_id(self) -> str:
        return "EED-019"

    @property
    def name(self) -> str:
        return "Nullable advisory_id in Dedup Key"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.low

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for unguarded advisory_id in dedup/groupby keys.

        Must never raise — all exceptions return empty list.
        """
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError:
            return []

        try:
            return self._scan_lines(file_path, content)
        except Exception:
            return []

    def _scan_lines(self, file_path: Path, content: str) -> list[DetectorFinding]:
        """Scan file content line by line for unguarded advisory_id keys."""
        findings: list[DetectorFinding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            line_number = idx + 1  # 1-indexed; validated >= 1 by DetectorFinding

            if not self._is_candidate_line(line):
                continue

            if self._has_inline_guard(line):
                continue

            if self._has_preceding_if_guard(lines, idx):
                continue

            if self._should_report_finding(file_path, line_number):
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=line_number,
                        message=(
                            "Dedup key includes advisory_id which may be None; "
                            "unguarded use can collapse distinct findings"
                        ),
                        snippet=line.strip(),
                        issue_reference="#234",
                        fix_hint=(
                            "Use 'advisory_id or \"\"' in the key tuple to ensure "
                            "None advisory_ids do not collapse distinct findings"
                        ),
                    )
                )

        return findings

    def _is_candidate_line(self, line: str) -> bool:
        """Return True if the line contains advisory_id inside a tuple/key expression."""
        if "advisory_id" not in line:
            return False
        # Must look like a tuple or groupby key (contains comma or opening paren)
        return "," in line or "(" in line

    def _has_inline_guard(self, line: str) -> bool:
        """Return True if the line contains a known None-safety guard for advisory_id."""
        return any(guard in line for guard in self._GUARD_STRINGS)

    def _has_preceding_if_guard(self, lines: list[str], line_idx: int) -> bool:
        """Return True if any of the preceding 3 lines guards advisory_id with an if."""
        start = max(0, line_idx - 3)
        return any(self._IF_GUARD_RE.search(lines[i]) for i in range(start, line_idx))
