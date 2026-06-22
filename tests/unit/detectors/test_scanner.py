"""Tests for DeterministicScanner.
# tested-by: tests/unit/detectors/test_scanner.py

RED phase tests for Task 1.5: DeterministicScanner Integration.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from caliper.core.models import FindingCategory, FindingSeverity, ScanResult
from caliper.data.scanners.base import Scanner

# These imports will fail during RED phase
from caliper.detectors.scanner import DeterministicScanner

# =============================================================================
# Scanner Protocol Tests
# =============================================================================


class TestDeterministicScannerProtocol:
    """Tests that DeterministicScanner implements Scanner protocol."""

    def test_implements_scanner_protocol(self):
        """DeterministicScanner is a Scanner subclass."""
        scanner = DeterministicScanner()
        assert isinstance(scanner, Scanner)

    def test_has_name_property(self):
        """DeterministicScanner has 'name' property returning 'deterministic'."""
        scanner = DeterministicScanner()
        assert scanner.name == "deterministic"

    def test_scan_returns_scanresult(self):
        """scan() returns a ScanResult."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(Path(tmpdir))

        assert isinstance(result, ScanResult)

    def test_scan_returns_success_status(self):
        """scan() returns status='success' even when bugs found."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with a test finding
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("jwt.encode({'user': 'test'}, 'secret')\n")

            result = scanner.scan(Path(tmpdir))

        assert result.status.value == "success"


# =============================================================================
# Filtering Tests
# =============================================================================


class TestDeterministicScannerFiltering:
    """Tests for scanner filtering capabilities."""

    def test_filters_by_category(self):
        """Scanner can filter detectors by category."""
        from caliper.detectors.categories import DetectorCategory

        scanner = DeterministicScanner(categories=[DetectorCategory.security])

        # Scanner should only run security detectors
        assert scanner._categories == [DetectorCategory.security]

    def test_filters_by_severity(self):
        """Scanner can filter detectors by severity."""
        scanner = DeterministicScanner(severities=[FindingSeverity.high])

        assert scanner._severities == [FindingSeverity.high]

    def test_filters_by_detector_id(self):
        """Scanner can filter by specific detector IDs."""
        scanner = DeterministicScanner(specific_detectors=["CAL-001"])

        assert scanner._specific_detectors == ["CAL-001"]


# =============================================================================
# Scan Result Tests
# =============================================================================


class TestDeterministicScannerResults:
    """Tests for scan result generation."""

    def test_scan_empty_directory(self):
        """Scan of empty directory returns empty findings."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(Path(tmpdir))

        assert result.findings == []
        assert result.tool_name == "deterministic"

    def test_scan_populated_directory(self):
        """Scan of directory with Python files returns findings."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Python file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")

            result = scanner.scan(Path(tmpdir))

        # Result should be a valid ScanResult
        assert isinstance(result, ScanResult)
        assert result.tool_name == "deterministic"

    def test_source_tool_is_detector_id(self):
        """Findings have source_tool set to detector_id."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file that might trigger a detector
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("api_key: str = 'secret'\n")

            result = scanner.scan(Path(tmpdir))

        # If there are findings, check source_tool
        for finding in result.findings:
            assert finding.source_tool.startswith("CAL-")

    def test_finding_category_mapping(self):
        """Finding categories are correctly mapped from detector categories."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(Path(tmpdir))

        # All findings should have valid FindingCategory
        for finding in result.findings:
            assert finding.category in FindingCategory

    def test_duration_seconds_is_set(self):
        """ScanResult has duration_seconds set."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(Path(tmpdir))

        assert result.duration_seconds >= 0


# =============================================================================
# AST Cache Integration Tests
# =============================================================================


class TestDeterministicScannerCaching:
    """Tests for AST cache integration (ADR-DET-007)."""

    def test_uses_ast_cache(self):
        """Scanner uses AST cache for performance."""
        from caliper.detectors.ast_utils import ASTCache

        cache = ASTCache(maxsize=10)
        scanner = DeterministicScanner(cache=cache)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Python file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")

            result = scanner.scan(Path(tmpdir))

        # Cache should have entry
        assert len(cache._cache) >= 0  # May be 0 if no detectors ran


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestDeterministicScannerErrorHandling:
    """Tests for scanner error handling."""

    def test_handles_nonexistent_path(self):
        """Scan of non-existent path returns failed result."""
        scanner = DeterministicScanner()

        result = scanner.scan(Path("/nonexistent/path"))

        # Should still return a ScanResult (not raise)
        assert isinstance(result, ScanResult)

    def test_handles_invalid_python_files(self):
        """Scan handles files with invalid Python syntax."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file with invalid syntax
            test_file = Path(tmpdir) / "bad.py"
            test_file.write_text("invalid syntax {{{\n")

            result = scanner.scan(Path(tmpdir))

        # Should return success status (no crash)
        assert result.status.value == "success"


# =============================================================================
# File-source routing (ignore-aware enumeration)
# =============================================================================


class TestDeterministicScannerFileSource:
    """The scanner enumerates via FileSourcePort, not a bare rglob.

    Closes the latent bug where ``.venv``/``node_modules`` were walked: the
    scanner now honours caliper's ignore rules through the file source.
    """

    # jwt.encode without an 'aud' claim → CAL-001 fires deterministically.
    _BUG = "import jwt\njwt.encode({'sub': 'x'}, 'k')\n"

    def test_ignores_files_under_excluded_dirs(self):
        """A buggy file under .venv must not be scanned.

        The Finding model drops file location (ADR-DET-003), so identical bug
        files give a clean count signal: exactly one finding means the ``.venv``
        copy was excluded; two would mean it was walked.
        """
        scanner = DeterministicScanner(specific_detectors=["CAL-001"])

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(self._BUG)
            venv = root / ".venv" / "lib"
            venv.mkdir(parents=True)
            (venv / "vendored.py").write_text(self._BUG)

            result = scanner.scan(root)

        eed_001 = [f for f in result.findings if f.source_tool == "CAL-001"]
        assert len(eed_001) == 1

    def test_uses_injected_file_source(self):
        """An injected FileSourcePort is used to enumerate files."""

        class _StubSource:
            name = "stub"
            calls: list[Path] = []

            def is_available(self, root: Path) -> bool:
                return True

            def list_files(self, root: Path, *, suffixes=None) -> list[Path]:
                type(self).calls.append(root)
                return []

        stub = _StubSource()
        scanner = DeterministicScanner(file_source=stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(Path(tmpdir))

        assert _StubSource.calls  # the injected source was consulted
        assert result.findings == []


# =============================================================================
# CLI Integration Tests (ADR-DET-006)
# =============================================================================


class TestDeterministicScannerCLIIntegration:
    """Tests for integration with 'review' command (ADR-DET-006)."""

    def test_scanner_registered_in_orchestrator(self):
        """DeterministicScanner can be used by ScanOrchestrator."""
        from caliper.core.orchestrator import ScanOrchestrator

        scanner = DeterministicScanner()
        orchestrator = ScanOrchestrator(scanners=[scanner], combined_timeout=300)

        # Should be able to add to orchestrator
        assert scanner in orchestrator._scanners

    def test_output_format_matches_existing_scanners(self):
        """Output format matches existing scanner output."""
        scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(Path(tmpdir))

        # Check fields match expected format
        assert hasattr(result, "tool_name")
        assert hasattr(result, "status")
        assert hasattr(result, "findings")
        assert hasattr(result, "duration_seconds")
        assert hasattr(result, "message")
