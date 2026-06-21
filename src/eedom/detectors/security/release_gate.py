"""ReleaseGateBypassDetector — CI verification step exits 0 on absent status.
# tested-by: tests/unit/detectors/security/test_release_gate.py

GitHub issue: #249 (parent bug: #215)
"""

from __future__ import annotations

import re
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector

_EMPTY_CHECK_RE = re.compile(r'\[\s*-z\s+"\$\w+"\s*\]')
_NULL_CHECK_RE = re.compile(r'"\$\w+"\s*=\s*"null"')
_EXIT_ZERO_RE = re.compile(r"\bexit\s+0\b")
_IF_RE = re.compile(r"^\s*if\b")
_FI_RE = re.compile(r"^\s*fi\b")
_ELSE_RE = re.compile(r"^\s*(else|elif)\b")


@register_detector
class ReleaseGateBypassDetector(BugDetector):
    """Detects CI verification steps that exit 0 when a required status is absent.

    A verification step that exits 0 (success) on a missing status silently
    degrades the gate, allowing downstream publish jobs to proceed without
    proper verification.

    GitHub: #249 (parent bug: #215)
    """

    @property
    def detector_id(self) -> str:
        return "EED-016"

    @property
    def name(self) -> str:
        return "CI Verification Gate Bypass"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.yml", "*.yaml")

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Scan YAML file for verification steps that exit 0 on absent status."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError:
            return []

        lines = content.splitlines()
        findings = []

        in_empty_check = False
        in_then_branch = False
        block_depth = 0
        empty_check_line = -1

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if _IF_RE.match(line) and (
                _EMPTY_CHECK_RE.search(stripped) or _NULL_CHECK_RE.search(stripped)
            ):
                in_empty_check = True
                in_then_branch = True
                block_depth = 1
                empty_check_line = i
                continue

            if not in_empty_check:
                continue

            if _IF_RE.match(line):
                block_depth += 1
            elif _FI_RE.match(line):
                block_depth -= 1
                if block_depth <= 0:
                    in_empty_check = False
                    in_then_branch = False
                    block_depth = 0
            elif _ELSE_RE.match(line) and block_depth == 1:
                in_then_branch = False
            elif in_then_branch and block_depth == 1 and _EXIT_ZERO_RE.search(stripped):
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=i,
                        message=(
                            f"Verification step exits 0 when required status is absent "
                            f"(empty/null check at line {empty_check_line}); "
                            f"use exit 1 to fail the gate"
                        ),
                        snippet=stripped,
                        issue_reference="#215",
                        fix_hint="Replace 'exit 0' with 'exit 1' to prevent silent gate bypass",
                    )
                )

        return findings
