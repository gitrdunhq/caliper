"""TestedByAnnotationDetector - Checks for # tested-by annotations.
# tested-by: tests/unit/detectors/process/test_tested_by.py

GitHub issue: #258
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
class TestedByAnnotationDetector(BugDetector):
    """Detects source files missing # tested-by: annotations.

    Process issue: Source files should reference their test files
    to maintain traceability and coverage awareness.

    GitHub: #258
    """

    # Pattern to match tested-by annotations
    TESTED_BY_PATTERN = re.compile(
        r"#\s*tested-by:\s*(\S+)",
        re.IGNORECASE,
    )

    @property
    def detector_id(self) -> str:
        return "EED-014"

    @property
    def name(self) -> str:
        return "Missing Tested-By Annotation"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.process

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.low

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for tested-by annotation."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError:
            return []

        findings = []

        # Check if file has tested-by annotation
        match = self.TESTED_BY_PATTERN.search(content)

        if not match:
            findings.append(
                DetectorFinding(
                    detector_id=self.detector_id,
                    detector_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    file_path=str(file_path),
                    line_number=1,
                    message="Source file missing # tested-by: annotation",
                    snippet=None,
                    issue_reference="#258",
                    fix_hint=(
                        f"Add '# tested-by: tests/unit/test_{file_path.stem}.py' to top of file"
                    ),
                )
            )
        else:
            # Validate that referenced test file exists
            test_path_str = match.group(1)
            root = file_path.resolve().parent
            candidate = (root / test_path_str).resolve()
            if not candidate.is_relative_to(root) or not candidate.exists():
                # Try relative to cwd (repo root)
                candidate = Path(test_path_str).resolve()

            if not candidate.exists():
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=1,
                        message=f"# tested-by points to non-existent file: {test_path_str}",
                        snippet=match.group(0),
                        issue_reference="#258",
                        fix_hint=f"Create test file at {test_path_str} or update annotation",
                    )
                )

        return findings
