"""NonAtomicWriteDetector - Detects direct .write_bytes()/.write_text() without atomic rename.
# tested-by: tests/unit/detectors/reliability/test_non_atomic_write.py

GitHub issue: #232
"""

from __future__ import annotations

from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector

# Write calls that indicate a direct (non-atomic) write
_WRITE_MARKERS = (".write_bytes(", ".write_text(")

# Patterns that indicate an atomic rename is present nearby
_ATOMIC_MARKERS = (".rename(", ".replace(", "os.rename(", "shutil.move(")

# Lines of context to inspect around the write call (before + after)
_WINDOW = 10


@register_detector
class NonAtomicWriteDetector(BugDetector):
    """Detects direct .write_bytes()/.write_text() calls without a nearby atomic rename.

    Reliability issue: Writing bytes directly to the target path is not crash-safe.
    If the process dies mid-write the file is left corrupt. The correct pattern is:
    write to a temp path, then atomically rename/replace it into position.

    GitHub: #232
    """

    @property
    def detector_id(self) -> str:
        return "EED-021"

    @property
    def name(self) -> str:
        return "Non-Atomic File Write"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for non-atomic write patterns.

        For each line containing .write_bytes() or .write_text(), inspect the
        surrounding _WINDOW lines. If no atomic-rename pattern (.rename(),
        .replace(), os.rename(), shutil.move()) is present in that window,
        flag the write call as a finding.

        Must never raise — returns empty list on any error.
        """
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            return []

        findings = []

        for i, line in enumerate(lines):
            if not any(marker in line for marker in _WRITE_MARKERS):
                continue

            # Check surrounding window for atomic rename patterns
            window_start = max(0, i - _WINDOW)
            window_end = min(len(lines), i + _WINDOW + 1)
            window = lines[window_start:window_end]

            if any(atomic in window_line for window_line in window for atomic in _ATOMIC_MARKERS):
                # Atomic rename pattern found nearby — this write is safe
                continue

            line_number = i + 1  # 1-indexed
            if not self._should_report_finding(file_path, line_number):
                continue

            findings.append(
                DetectorFinding(
                    detector_id=self.detector_id,
                    detector_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    file_path=str(file_path),
                    line_number=line_number,
                    message=(
                        "Direct .write_bytes()/.write_text() without atomic rename; "
                        "file is corrupt on crash. "
                        "Use write-to-temp then .replace() or os.rename()."
                    ),
                    snippet=line.strip(),
                    issue_reference="#232",
                    fix_hint=(
                        "Write to a temp path (e.g. target.with_suffix('.tmp')), "
                        "then call tmp.replace(target) or os.rename(tmp, target)."
                    ),
                )
            )

        return findings
