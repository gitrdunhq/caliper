"""Tests for the detector registry (folded onto the generic ``Registry[T]``).
# tested-by: tests/unit/detectors/test_registry.py

Exercises the functional registry API in ``eedom.detectors._registry``:
``register_detector`` (decorator), ``discover_detectors`` (idempotent
auto-discovery), the ``get_*`` lookups, instance caching, and thread safety
for parallel orchestrator execution (VAL-M1).
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import (
    DETECTORS,
    clear_detectors,
    discover_detectors,
    get_all_detectors,
    get_by_category,
    get_by_severity,
    get_detector,
    register_detector,
)
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector

# =============================================================================
# Test Detector Classes
# =============================================================================


class SampleSecurityDetector(BugDetector):
    """Sample security detector for registry tests."""

    @property
    def detector_id(self) -> str:
        return "EED-TEST-001"

    @property
    def name(self) -> str:
        return "Test Security Detector"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        return []


class SampleReliabilityDetector(BugDetector):
    """Sample reliability detector for registry tests."""

    @property
    def detector_id(self) -> str:
        return "EED-TEST-002"

    @property
    def name(self) -> str:
        return "Test Reliability Detector"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        return []


# =============================================================================
# Registration
# =============================================================================


class TestRegisterDetector:
    """Tests for the ``@register_detector`` decorator."""

    def test_decorator_registers_under_detector_id(self):
        """The decorator registers the class keyed by its detector_id."""

        @register_detector
        class DecoratedDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "EED-DEC-001"

            @property
            def name(self) -> str:
                return "Decorated Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        assert "EED-DEC-001" in DETECTORS

    def test_decorator_returns_class_for_use(self):
        """The decorator returns the class so it stays instantiable."""

        @register_detector
        class ReturnedDetector(BugDetector):
            @property
            def detector_id(self) -> str:
                return "EED-RET-001"

            @property
            def name(self) -> str:
                return "Return Test Detector"

            @property
            def category(self) -> DetectorCategory:
                return DetectorCategory.security

            @property
            def severity(self) -> FindingSeverity:
                return FindingSeverity.high

            def detect(self, file_path: Path) -> list[DetectorFinding]:
                return []

        instance = ReturnedDetector()
        assert instance.detector_id == "EED-RET-001"


# =============================================================================
# Discovery
# =============================================================================


class TestDiscoverDetectors:
    """Tests for ``discover_detectors`` auto-discovery."""

    def test_discover_imports_real_detectors(self):
        """Discovery imports the shipped detector modules and registers them.

        Idempotent: this populates on the first call in the process and is a
        no-op thereafter; the autouse fixture snapshots/restores global state
        so the real registrations survive for the whole file.
        """
        discover_detectors()
        all_detectors = get_all_detectors()
        detector_ids = {d.detector_id for d in all_detectors}
        # A known real detector id must be present after discovery.
        assert "EED-001" in detector_ids
        assert len(all_detectors) > 0

    def test_discover_is_idempotent(self):
        """Repeated discovery does not re-import or duplicate registrations."""
        discover_detectors()
        first = len(get_all_detectors())
        discover_detectors()
        second = len(get_all_detectors())
        assert first == second

    def test_get_all_detectors_returns_instances(self):
        """get_all_detectors() returns BugDetector instances."""
        register_detector(SampleSecurityDetector)
        detectors = get_all_detectors()
        assert all(isinstance(d, BugDetector) for d in detectors)
        assert any(isinstance(d, SampleSecurityDetector) for d in detectors)


# =============================================================================
# Lookup
# =============================================================================


class TestLookup:
    """Tests for the lookup helpers."""

    def test_get_detector_by_id(self):
        register_detector(SampleSecurityDetector)
        detector = get_detector("EED-TEST-001")
        assert detector is not None
        assert detector.detector_id == "EED-TEST-001"

    def test_get_detector_returns_none_for_unknown_id(self):
        assert get_detector("EED-UNKNOWN") is None

    def test_get_by_category_filters_correctly(self):
        clear_detectors()  # isolate from the real detectors for an exact assertion
        register_detector(SampleSecurityDetector)
        register_detector(SampleReliabilityDetector)

        security = get_by_category(DetectorCategory.security)
        assert {d.detector_id for d in security} == {"EED-TEST-001"}

        reliability = get_by_category(DetectorCategory.reliability)
        assert {d.detector_id for d in reliability} == {"EED-TEST-002"}

    def test_get_by_severity_filters_correctly(self):
        clear_detectors()  # isolate from the real detectors for an exact assertion
        register_detector(SampleSecurityDetector)
        register_detector(SampleReliabilityDetector)

        high = get_by_severity(FindingSeverity.high)
        assert {d.detector_id for d in high} == {"EED-TEST-001"}

        medium = get_by_severity(FindingSeverity.medium)
        assert {d.detector_id for d in medium} == {"EED-TEST-002"}


# =============================================================================
# Caching
# =============================================================================


class TestCaching:
    """Detectors are stateless, so instances are cached and shared."""

    def test_get_detector_caches_instances(self):
        register_detector(SampleSecurityDetector)
        first = get_detector("EED-TEST-001")
        second = get_detector("EED-TEST-001")
        assert first is second

    def test_clear_detectors_drops_cache(self):
        register_detector(SampleSecurityDetector)
        first = get_detector("EED-TEST-001")
        clear_detectors()
        register_detector(SampleSecurityDetector)
        second = get_detector("EED-TEST-001")
        assert first is not second


# =============================================================================
# Thread-Safety (VAL-M1)
# =============================================================================


class TestThreadSafety:
    """The registry must tolerate concurrent registration and lookup."""

    def test_concurrent_registration_is_safe(self):
        errors: list[Exception] = []

        def create_and_register(i: int) -> None:
            try:

                class DynamicDetector(BugDetector):
                    _idx = i

                    @property
                    def detector_id(self) -> str:
                        return f"EED-THREAD-{self._idx:03d}"

                    @property
                    def name(self) -> str:
                        return f"Thread Detector {self._idx}"

                    @property
                    def category(self) -> DetectorCategory:
                        return DetectorCategory.security

                    @property
                    def severity(self) -> FindingSeverity:
                        return FindingSeverity.high

                    def detect(self, file_path: Path) -> list[DetectorFinding]:
                        return []

                register_detector(DynamicDetector)
            except Exception as e:  # pragma: no cover - failure path
                errors.append(e)

        threads = [threading.Thread(target=create_and_register, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        ids = {d.detector_id for d in get_all_detectors()}
        for i in range(10):
            assert f"EED-THREAD-{i:03d}" in ids

    def test_concurrent_lookup_is_safe(self):
        for i in range(5):

            class PreRegisteredDetector(BugDetector):
                _idx = i

                @property
                def detector_id(self) -> str:
                    return f"EED-PRE-{self._idx:03d}"

                @property
                def name(self) -> str:
                    return f"Pre-registered {self._idx}"

                @property
                def category(self) -> DetectorCategory:
                    return DetectorCategory.security

                @property
                def severity(self) -> FindingSeverity:
                    return FindingSeverity.high

                def detect(self, file_path: Path) -> list[DetectorFinding]:
                    return []

            register_detector(PreRegisteredDetector)

        errors: list[Exception] = []
        results: list[bool] = []

        def lookup_detectors() -> None:
            try:
                for i in range(5):
                    results.append(get_detector(f"EED-PRE-{i:03d}") is not None)
            except Exception as e:  # pragma: no cover - failure path
                errors.append(e)

        threads = [threading.Thread(target=lookup_detectors) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert all(results)


# =============================================================================
# Isolation
# =============================================================================


@pytest.fixture(autouse=True)
def isolate_registry():
    """Snapshot and restore global registry state around each test.

    Tests register throwaway detectors (and some call ``clear_detectors``);
    snapshotting keeps that isolated to the test while preserving the real,
    already-discovered registrations for the rest of the suite — re-discovery
    cannot repopulate them because the detector modules are import-cached.
    """
    from eedom.detectors import _registry as reg

    saved_factories = dict(reg.DETECTORS._factories)
    saved_instances = dict(reg._instances)
    saved_discovered = reg._discovered
    try:
        yield
    finally:
        reg.DETECTORS._factories.clear()
        reg.DETECTORS._factories.update(saved_factories)
        reg._instances.clear()
        reg._instances.update(saved_instances)
        reg._discovered = saved_discovered
