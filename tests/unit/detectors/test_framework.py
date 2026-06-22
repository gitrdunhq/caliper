"""Tests for the bug detector framework base classes.
# tested-by: tests/unit/detectors/test_framework.py

RED phase tests for Task 1.2: Base Framework Classes.
These tests import from caliper.detectors which doesn't exist yet.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.core.models import FindingCategory, FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding

# These imports will fail with ImportError during RED phase - expected!
from caliper.detectors.framework import BugDetector

# =============================================================================
# BugDetector Base Class Tests
# =============================================================================


class TestBugDetectorAbstract:
    """Tests that BugDetector enforces abstract method contracts."""

    def test_cannot_instantiate_base_class(self):
        """BugDetector is abstract and cannot be instantiated directly."""
        with pytest.raises(TypeError, match="abstract"):
            BugDetector()

    def test_subclass_must_implement_detector_id(self):
        """Subclasses must implement detector_id property."""

        class IncompleteDetector(BugDetector):
            @property
            def name(self) -> str:
                return "Test"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        with pytest.raises(TypeError, match="detector_id"):
            IncompleteDetector()

    def test_subclass_must_implement_name(self):
        """Subclasses must implement name property."""

        class IncompleteDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        with pytest.raises(TypeError, match="name"):
            IncompleteDetector()

    def test_subclass_must_implement_category(self):
        """Subclasses must implement category property."""

        class IncompleteDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST"

            @property
            def name(self) -> str:
                return "Test Detector"

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        with pytest.raises(TypeError, match="category"):
            IncompleteDetector()

    def test_subclass_must_implement_severity(self):
        """Subclasses must implement severity property."""

        class IncompleteDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST"

            @property
            def name(self) -> str:
                return "Test Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        with pytest.raises(TypeError, match="severity"):
            IncompleteDetector()

    def test_subclass_must_implement_detect(self):
        """Subclasses must implement detect method."""

        class IncompleteDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST"

            @property
            def name(self) -> str:
                return "Test Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

        with pytest.raises(TypeError, match="detect"):
            IncompleteDetector()


class TestBugDetectorContract:
    """Tests for complete BugDetector implementations."""

    @pytest.fixture
    def valid_detector(self):
        """Create a minimal valid detector implementation."""

        class ValidTestDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST"

            @property
            def name(self) -> str:
                return "Test Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        return ValidTestDetector()

    def test_can_instantiate_complete_implementation(self, valid_detector):
        """Complete implementation can be instantiated."""
        assert valid_detector is not None
        assert isinstance(valid_detector, BugDetector)

    def test_detector_id_returns_string(self, valid_detector):
        """detector_id returns a non-empty string."""
        assert isinstance(valid_detector.detector_id, str)
        assert valid_detector.detector_id == "CAL-TEST"

    def test_name_returns_string(self, valid_detector):
        """name returns a non-empty string."""
        assert isinstance(valid_detector.name, str)
        assert valid_detector.name == "Test Detector"

    def test_category_returns_detector_category(self, valid_detector):
        """category returns a DetectorCategory enum value."""
        assert valid_detector.category == DetectorCategory.security

    def test_severity_returns_finding_severity(self, valid_detector):
        """severity returns a FindingSeverity enum value."""
        assert valid_detector.severity == FindingSeverity.high

    def test_default_target_files_is_python(self, valid_detector):
        """Default target_files is ('*.py',)."""
        assert valid_detector.target_files == ("*.py",)

    def test_is_applicable_matches_python_files(self, valid_detector):
        """is_applicable returns True for .py files."""
        assert valid_detector.is_applicable(Path("test.py")) is True
        assert valid_detector.is_applicable(Path("/path/to/file.py")) is True

    def test_is_applicable_rejects_other_files(self, valid_detector):
        """is_applicable returns False for non-Python files."""
        assert valid_detector.is_applicable(Path("test.txt")) is False
        assert valid_detector.is_applicable(Path("test.yaml")) is False
        assert valid_detector.is_applicable(Path("test")) is False

    def test_detect_returns_list(self, valid_detector):
        """detect returns a list (possibly empty)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("# test file\n")
            f.flush()
            result = valid_detector.detect(Path(f.name))
            assert isinstance(result, list)

    def test_detect_never_raises(self, valid_detector):
        """detect must never raise - returns empty list on errors."""
        # Test with non-existent file
        result = valid_detector.detect(Path("/nonexistent/file.py"))
        assert result == []

        # Test with file with invalid Python syntax
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("invalid syntax {{\n")
            f.flush()
            result = valid_detector.detect(Path(f.name))
            assert isinstance(result, list)


class TestBugDetectorTargetFiles:
    """Tests for target_files customization."""

    def test_can_override_target_files(self):
        """Subclasses can override target_files."""

        class YamlDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-YAML"

            @property
            def name(self) -> str:
                return "YAML Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.configuration

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.medium

            @property
            def target_files(self) -> tuple[str, ...]:
                return ("*.yaml", "*.yml")

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        detector = YamlDetector()
        assert detector.target_files == ("*.yaml", "*.yml")
        assert detector.is_applicable(Path("config.yaml")) is True
        assert detector.is_applicable(Path("config.yml")) is True
        assert detector.is_applicable(Path("config.py")) is False


class TestIsApplicablePathPatternRegressions:
    """Regression tests for P11-6 fix: is_applicable with directory glob patterns (#432).

    Before the fix, is_applicable only called fnmatch against file_path.name
    (the basename).  A pattern like "config/*.yaml" would never match because
    the basename is just "deployment.yaml" — the directory component was
    silently discarded.  The fix also matches against the full relative path
    string so "config/*.yaml" correctly matches "config/deployment.yaml".
    """

    def _make_dir_detector(self, pattern: str):
        """Return a minimal detector whose target_files uses the given pattern."""

        class DirPatternDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST-DIR"

            @property
            def name(self) -> str:
                return "Dir Pattern Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.configuration

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.medium

            @property
            def target_files(self) -> tuple[str, ...]:
                return (pattern,)

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        return DirPatternDetector()

    def test_dir_glob_pattern_matches_relative_path(self):
        """P11-6: 'config/*.yaml' must match 'config/deployment.yaml'."""
        detector = self._make_dir_detector("config/*.yaml")
        assert (
            detector.is_applicable(Path("config/deployment.yaml")) is True
        ), "is_applicable must match the full relative path, not just the basename"

    def test_dir_glob_pattern_does_not_match_wrong_dir(self):
        """P11-6: 'config/*.yaml' must NOT match 'other/deployment.yaml'."""
        detector = self._make_dir_detector("config/*.yaml")
        assert (
            detector.is_applicable(Path("other/deployment.yaml")) is False
        ), "'config/*.yaml' pattern must not match files in a different directory"

    def test_dir_glob_pattern_does_not_match_basename_only(self):
        """P11-6: 'config/*.yaml' must NOT match a bare 'deployment.yaml' filename."""
        detector = self._make_dir_detector("config/*.yaml")
        assert (
            detector.is_applicable(Path("deployment.yaml")) is False
        ), "A file in the root directory must not match a 'config/*.yaml' pattern"

    def test_basename_only_pattern_still_works(self):
        """P11-6: Existing '*.yaml' basename pattern must still work (no regression)."""
        detector = self._make_dir_detector("*.yaml")
        assert detector.is_applicable(Path("config/deployment.yaml")) is True
        assert detector.is_applicable(Path("deployment.yaml")) is True
        assert detector.is_applicable(Path("config/setup.py")) is False

    def test_nested_dir_glob_pattern_matches(self):
        """P11-6: 'helm/templates/*.yaml' must match 'helm/templates/service.yaml'."""
        detector = self._make_dir_detector("helm/templates/*.yaml")
        assert detector.is_applicable(Path("helm/templates/service.yaml")) is True


# =============================================================================
# DetectorCategory Enum Tests
# =============================================================================


class TestDetectorCategory:
    """Tests for DetectorCategory enum."""

    def test_has_security_category(self):
        """DetectorCategory has security value."""
        assert DetectorCategory.security.value == "security"

    def test_has_reliability_category(self):
        """DetectorCategory has reliability value."""
        assert DetectorCategory.reliability.value == "reliability"

    def test_has_performance_category(self):
        """DetectorCategory has performance value."""
        assert DetectorCategory.performance.value == "performance"

    def test_has_configuration_category(self):
        """DetectorCategory has configuration value."""
        assert DetectorCategory.configuration.value == "configuration"

    def test_has_process_category(self):
        """DetectorCategory has process value."""
        assert DetectorCategory.process.value == "process"

    def test_has_documentation_category(self):
        """DetectorCategory has documentation value."""
        assert DetectorCategory.documentation.value == "documentation"

    def test_has_integration_category(self):
        """DetectorCategory has integration value."""
        assert DetectorCategory.integration.value == "integration"


# =============================================================================
# DetectorFinding Model Tests
# =============================================================================


class TestDetectorFinding:
    """Tests for DetectorFinding model."""

    def test_minimal_finding_creation(self):
        """Can create a finding with minimal required fields."""
        finding = DetectorFinding(
            detector_id="CAL-001",
            detector_name="Test Detector",
            category=DetectorCategory.security,
            severity=FindingSeverity.high,
            file_path="/path/to/file.py",
            line_number=42,
            message="Test finding",
        )
        assert finding.detector_id == "CAL-001"
        assert finding.line_number == 42

    def test_finding_with_optional_fields(self):
        """Can create a finding with all optional fields."""
        finding = DetectorFinding(
            detector_id="CAL-001",
            detector_name="Test Detector",
            category=DetectorCategory.security,
            severity=FindingSeverity.high,
            file_path="/path/to/file.py",
            line_number=42,
            column=10,
            message="Test finding",
            snippet="api_key: str",
            issue_reference="#123",
            fix_hint="Use SecretStr instead",
            confidence=0.95,
        )
        assert finding.column == 10
        assert finding.snippet == "api_key: str"
        assert finding.issue_reference == "#123"
        assert finding.fix_hint == "Use SecretStr instead"
        assert finding.confidence == 0.95

    def test_line_number_must_be_positive(self):
        """line_number must be >= 1."""
        with pytest.raises(ValueError):
            DetectorFinding(
                detector_id="CAL-001",
                detector_name="Test",
                category=DetectorCategory.security,
                severity=FindingSeverity.high,
                file_path="/path/file.py",
                line_number=0,  # Invalid!
                message="Test",
            )

    def test_confidence_must_be_between_0_and_1(self):
        """confidence must be in range [0.0, 1.0]."""
        with pytest.raises(ValueError):
            DetectorFinding(
                detector_id="CAL-001",
                detector_name="Test",
                category=DetectorCategory.security,
                severity=FindingSeverity.high,
                file_path="/path/file.py",
                line_number=1,
                message="Test",
                confidence=1.5,  # Invalid!
            )

    def test_detector_id_pattern_validation(self):
        """detector_id should match CAL-XXX pattern."""
        finding = DetectorFinding(
            detector_id="CAL-001",
            detector_name="Test",
            category=DetectorCategory.security,
            severity=FindingSeverity.high,
            file_path="/path/file.py",
            line_number=1,
            message="Test",
        )
        assert finding.detector_id == "CAL-001"

    def test_default_confidence_is_1(self):
        """Default confidence is 1.0."""
        finding = DetectorFinding(
            detector_id="CAL-001",
            detector_name="Test",
            category=DetectorCategory.security,
            severity=FindingSeverity.high,
            file_path="/path/file.py",
            line_number=1,
            message="Test",
        )
        assert finding.confidence == 1.0


class TestDetectorFindingConversion:
    """Tests for DetectorFinding.to_finding() conversion."""

    @pytest.fixture
    def detector_finding(self):
        """Create a sample DetectorFinding."""
        return DetectorFinding(
            detector_id="CAL-001",
            detector_name="JWT Missing Audience",
            category=DetectorCategory.security,
            severity=FindingSeverity.high,
            file_path="/path/file.py",
            line_number=42,
            message="jwt.encode() missing 'aud' claim",
            issue_reference="#175",
            confidence=0.95,
        )

    def test_to_finding_returns_finding(self, detector_finding):
        """to_finding() returns a Finding instance."""
        from caliper.core.models import Finding

        finding = detector_finding.to_finding()
        assert isinstance(finding, Finding)

    def test_to_finding_preserves_severity(self, detector_finding):
        """Severity is preserved in conversion."""
        finding = detector_finding.to_finding()
        assert finding.severity == FindingSeverity.high

    def test_to_finding_maps_category_security(self, detector_finding):
        """security category maps to FindingCategory.security."""
        finding = detector_finding.to_finding()
        assert finding.category == FindingCategory.security

    def test_to_finding_uses_detector_id_as_source_tool(self, detector_finding):
        """detector_id becomes source_tool."""
        finding = detector_finding.to_finding()
        assert finding.source_tool == "CAL-001"

    def test_to_finding_uses_message_as_description(self, detector_finding):
        """message becomes description."""
        finding = detector_finding.to_finding()
        assert finding.description == "jwt.encode() missing 'aud' claim"

    def test_to_finding_uses_issue_reference_as_advisory_id(self, detector_finding):
        """issue_reference becomes advisory_id."""
        finding = detector_finding.to_finding()
        assert finding.advisory_id == "#175"

    def test_to_finding_preserves_confidence(self, detector_finding):
        """confidence is preserved."""
        finding = detector_finding.to_finding()
        assert finding.confidence == 0.95


# =============================================================================
# Suppression Tests (VAL-H2: noqa CAL-XXX comment support)
# =============================================================================


class TestBugDetectorSuppression:
    """Tests for # noqa: CAL-XXX suppression support."""

    def test_is_suppressed_detects_noqa_comment(self):
        """BugDetector can detect # noqa: CAL-XXX comments."""

        class TestDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST"

            @property
            def name(self) -> str:
                return "Test"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        detector = TestDetector()

        # Create file with noqa comment
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("# Line 1\n")
            f.write("jwt.encode({})  # noqa: CAL-TEST\n")
            f.flush()

            # Check suppression
            is_suppressed = detector.is_suppressed(Path(f.name), 2, "CAL-TEST")
            assert is_suppressed is True

    def test_is_suppressed_returns_false_without_noqa(self):
        """is_suppressed returns False when no noqa comment present."""

        class TestDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-TEST"

            @property
            def name(self) -> str:
                return "Test"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        detector = TestDetector()

        # Create file without noqa comment
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("jwt.encode({})\n")
            f.flush()

            is_suppressed = detector.is_suppressed(Path(f.name), 1, "CAL-TEST")
            assert is_suppressed is False

    def test_is_suppressed_specific_detector_id(self):
        """Suppression is specific to detector ID."""

        class TestDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "CAL-001"

            @property
            def name(self) -> str:
                return "Test"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        detector = TestDetector()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("jwt.encode({})  # noqa: CAL-002\n")  # Different detector
            f.flush()

            is_suppressed = detector.is_suppressed(Path(f.name), 1, "CAL-001")
            assert is_suppressed is False  # Different detector ID


# =============================================================================
# Acceptance Checklist Verification
# =============================================================================
