"""ArchBoundaryDetector - Detects presentation→data tier boundary violations.
# tested-by: tests/unit/detectors/security/test_arch_boundary.py

Architecture standards require presentation → core → data layering.
This detector flags Python files in presentation-tier paths (agent/, cli/)
that directly import from eedom.data, bypassing the core tier.

GitHub issue: #231
"""

from __future__ import annotations

import re
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector

# Matches: `from eedom.data import ...` or `from eedom.data.something import ...`
_FROM_DATA_RE = re.compile(r"^\s*from\s+eedom\.data(\.\w+)*\s+import\b")

# Matches: `import eedom.data` or `import eedom.data.something`
_IMPORT_DATA_RE = re.compile(r"^\s*import\s+eedom\.data(\.\w+)*\b")

# Presentation-tier path segments that must not import from eedom.data
_PRESENTATION_SEGMENTS = ("/agent/", "/cli/")


@register_detector
class ArchBoundaryDetector(BugDetector):
    """Detects direct presentation→data tier imports that skip the core tier.

    The three-tier architecture mandates: cli/ and agent/ → core/ → data/.
    A file in a presentation tier that imports directly from eedom.data
    bypasses the pipeline, policy, and service abstractions that live in core,
    creating hidden coupling and violating the boundary contract.

    Allowed:
        - core/ importing from eedom.data   (core→data boundary)
        - any tier importing from eedom.core (correct upward direction)

    Flagged:
        - agent/ or cli/ importing from eedom.data (skips core)

    GitHub: #231
    """

    @property
    def detector_id(self) -> str:
        return "EED-017"

    @property
    def name(self) -> str:
        return "Presentation Tier Imports Data Tier Directly"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Scan file for presentation→data boundary violations.

        Returns an empty list when:
        - the file is not in a presentation-tier path (agent/ or cli/)
        - the file cannot be read
        - no direct eedom.data imports are found
        """
        try:
            path_str = str(file_path)
            if not any(seg in path_str for seg in _PRESENTATION_SEGMENTS):
                return []

            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return []

        findings: list[DetectorFinding] = []

        try:
            lines = content.splitlines()
            for lineno, line in enumerate(lines, start=1):
                if _FROM_DATA_RE.match(line) or _IMPORT_DATA_RE.match(line):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=lineno,
                            message=(
                                "Presentation-tier file imports directly from eedom.data, "
                                "bypassing the core tier. Route through eedom.core instead."
                            ),
                            snippet=line.rstrip(),
                            issue_reference="#231",
                            fix_hint=(
                                "Replace 'from eedom.data import ...' with the equivalent "
                                "import from eedom.core (service, pipeline, or use-case helper)."
                            ),
                        )
                    )
        except Exception:
            return []

        return findings
