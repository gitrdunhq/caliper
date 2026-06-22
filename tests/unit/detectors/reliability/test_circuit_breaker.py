"""Tests for Circuit Breaker detector.
# tested-by: tests/unit/detectors/reliability/test_circuit_breaker.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from eedom.detectors.reliability.circuit_breaker import CircuitBreakerDetector


class TestCircuitBreakerDetector:
    """Tests for CircuitBreakerDetector (EED-007)."""

    @pytest.fixture
    def detector(self):
        return CircuitBreakerDetector()

    def test_detects_breaker_without_half_open(self, detector):
        """Detects circuit breaker without half-open state handling."""
        code = """
from pybreaker import CircuitBreaker

breaker = CircuitBreaker(fail_max=5, reset_timeout=60)

@breaker
def call_api():
    return requests.get("https://api.example.com/data")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-007"

    def test_detects_manual_breaker_without_half_open(self, detector):
        """Detects manually implemented breaker without half-open."""
        code = """
class CircuitBreaker:
    def __init__(self):
        self.failures = 0
        self.state = "closed"

    def call(self, func):
        if self.state == "open":
            raise Exception("Circuit open")
        return func()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_breaker_with_half_open(self, detector):
        """No finding when half-open state is implemented."""
        code = """
from pybreaker import CircuitBreaker

breaker = CircuitBreaker(
    fail_max=5,
    reset_timeout=60,
    expected_exception=Exception
)

@breaker
def call_api():
    return requests.get("https://api.example.com/data")

# With half-open monitoring
breaker.half_open_max_calls = 3
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        # Should find no issues when half-open is properly configured
        assert len(findings) == 0

    def test_ignores_no_breaker(self, detector):
        """No finding when no circuit breaker is present."""
        code = """
def call_api():
    return requests.get("https://api.example.com/data")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Regression P13-3 — keyword.arg None must not crash _has_half_open_config
# ---------------------------------------------------------------------------


class TestCircuitBreakerKeywordArgNoneRegression:
    """Regression for P13-3: _has_half_open_config iterated call.keywords and
    called keyword.arg.lower() without guarding for None.  When CircuitBreaker
    is called with **kwargs unpacking, keyword.arg is None and .lower() raised
    AttributeError."""

    @pytest.fixture
    def detector(self):
        return CircuitBreakerDetector()

    def test_kwargs_unpacking_does_not_crash_detector(self, detector):
        """CircuitBreaker(**config_dict) must not raise AttributeError in _has_half_open_config
        (regression for P13-3: keyword.arg is None for **kwargs, guard was missing)."""
        code = """
from pybreaker import CircuitBreaker

config = {"fail_max": 5, "reset_timeout": 60}
breaker = CircuitBreaker(**config)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                findings = detector.detect(Path(f.name))
            except AttributeError as exc:
                import pytest as _pytest

                _pytest.fail(
                    f"CircuitBreakerDetector raised AttributeError on **kwargs call: {exc}. "
                    "keyword.arg is None for **kwargs — must guard before calling .lower()."
                )

        # Should produce a finding (no half-open config detectable) without crashing
        assert isinstance(findings, list)

    def test_kwargs_and_explicit_mixed_does_not_crash(self, detector):
        """Mixed explicit kwargs + **kwargs unpacking must not crash the detector."""
        code = """
from pybreaker import CircuitBreaker

extra = {"reset_timeout": 60}
breaker = CircuitBreaker(fail_max=3, **extra)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert isinstance(findings, list)
