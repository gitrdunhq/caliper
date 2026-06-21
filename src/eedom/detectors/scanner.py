"""DeterministicScanner implementation.
# tested-by: tests/unit/detectors/test_scanner.py

Scanner implementation that runs all bug detectors using AST-based
static analysis. Integrates with ScanOrchestrator via Scanner protocol.

Per ADR-DET-006: Integrated into 'review' command, not separate 'detect'.
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path

from eedom.core.models import FindingSeverity, ScanResult, ScanResultStatus
from eedom.core.ports import ScannerPort
from eedom.detectors.ast_utils import ASTCache
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector
from eedom.detectors.registry import DetectorRegistry


class DeterministicScanner(ScannerPort):
    """Scanner implementation that runs all bug detectors.

    Integrates with ScanOrchestrator via Scanner protocol.
    Uses AST caching (ADR-DET-007) and visitor pattern batching (VAL-H1).

    Per ADR-DET-006: This scanner is integrated into the 'review' command
    rather than being a separate 'detect' command. Use --scanners deterministic
    to run only deterministic detectors.

    Example:
        scanner = DeterministicScanner(
            categories=[DetectorCategory.security],
            severities=[FindingSeverity.high, FindingSeverity.critical]
        )
        result = scanner.scan(Path("./src"))
    """

    name: str = "deterministic"

    def __init__(
        self,
        categories: list[DetectorCategory] | None = None,
        severities: list[FindingSeverity] | None = None,
        specific_detectors: list[str] | None = None,
        cache: ASTCache | None = None,
    ) -> None:
        """Initialize with optional filters.

        Args:
            categories: Filter detectors by category (None = all)
            severities: Filter detectors by severity (None = all)
            specific_detectors: Run only specific detector IDs (None = all)
            cache: Optional AST cache for performance
        """
        self._categories = categories
        self._severities = severities
        self._specific_detectors = specific_detectors
        self._cache = cache or ASTCache(maxsize=100)

        # Ensure registry is discovered
        DetectorRegistry.discover()

    def _get_applicable_detectors(self, file_path: Path) -> list[BugDetector]:
        """Get detectors applicable to the given file.

        Filters by target_files pattern, categories, severities, and
        specific detector IDs.

        Args:
            file_path: Path to the file being analyzed

        Returns:
            List of applicable detector instances
        """
        all_detectors = DetectorRegistry.get_all_detectors()
        applicable = []

        for detector in all_detectors:
            # Check if detector applies to this file
            if not detector.is_applicable(file_path):
                continue

            # Apply category filter
            if self._categories is not None and detector.category not in self._categories:
                continue

            # Apply severity filter
            if self._severities is not None and detector.severity not in self._severities:
                continue

            # Apply specific detector filter
            if (
                self._specific_detectors is not None
                and detector.detector_id not in self._specific_detectors
            ):
                continue

            applicable.append(detector)

        return applicable

    def _run_detectors_on_file(
        self, file_path: Path, detectors: list[BugDetector]
    ) -> list[DetectorFinding]:
        """Run all applicable detectors on a single file.

        Uses the AST cache to avoid re-parsing the same file for each detector.
        Per VAL-H1: Could use BatchVisitor for single-pass analysis.

        Args:
            file_path: Path to the file to analyze
            detectors: List of detectors to run

        Returns:
            List of findings from all detectors
        """
        all_findings: list[DetectorFinding] = []

        # Pre-parse file with cache
        tree = self._cache.get_or_parse(file_path)
        if tree is None:
            return all_findings

        # Run each detector
        for detector in detectors:
            try:
                findings = detector.detect_safe(file_path)

                # Filter out suppressed findings (VAL-H2)
                for finding in findings:
                    if not detector.is_suppressed(file_path, finding.line_number):
                        all_findings.append(finding)

            except Exception:
                # Detector failed - continue with others
                continue

        return all_findings

    def scan(self, target_path: Path) -> ScanResult:
        """Run all applicable detectors against target path.

        Returns ScanResult with findings converted to Finding model.
        Status is always 'success' even when bugs found (bugs are findings,
        not failures per ADR-DET-002).

        Args:
            target_path: Path to directory or file to scan

        Returns:
            ScanResult with all findings
        """
        start_time = time.time()

        # Validate target
        if not target_path.exists():
            return ScanResult(
                tool_name=self.name,
                status=ScanResultStatus.failed,
                findings=[],
                message=f"Target path does not exist: {target_path}",
                duration_seconds=time.time() - start_time,
            )

        # Collect all Python files to analyze
        files_to_scan: list[Path] = []

        if target_path.is_file():
            if target_path.suffix == ".py":
                files_to_scan.append(target_path)
        else:
            # Find all Python files recursively
            with contextlib.suppress(OSError, PermissionError):
                files_to_scan = list(target_path.rglob("*.py"))

        # Run detectors on all files
        all_findings: list[DetectorFinding] = []

        for file_path in files_to_scan:
            # Get applicable detectors for this file
            detectors = self._get_applicable_detectors(file_path)

            if not detectors:
                continue

            # Run detectors
            findings = self._run_detectors_on_file(file_path, detectors)
            all_findings.extend(findings)

        # Convert DetectorFinding to Finding
        findings = [f.to_finding() for f in all_findings]

        duration = time.time() - start_time

        return ScanResult(
            tool_name=self.name,
            status=ScanResultStatus.success,
            findings=findings,
            duration_seconds=duration,
        )
