"""Tests for High Cardinality Metrics detector.
# tested-by: tests/unit/detectors/metrics/test_high_cardinality.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.metrics.high_cardinality import HighCardinalityMetricsDetector


class TestHighCardinalityMetricsDetector:
    """Tests for HighCardinalityMetricsDetector (CAL-015)."""

    @pytest.fixture
    def detector(self):
        return HighCardinalityMetricsDetector()

    def test_detects_user_id_in_metric_labels(self, detector):
        """Detects user_id as metric label (high cardinality)."""
        code = """
from prometheus_client import Counter

request_count = Counter("http_requests", "HTTP requests", ["user_id", "endpoint"])

def handle_request(user_id, endpoint):
    request_count.labels(user_id=user_id, endpoint=endpoint).inc()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-015"

    def test_detects_request_id_in_labels(self, detector):
        """Detects request_id as metric label (high cardinality)."""
        code = """
from prometheus_client import Histogram

request_duration = Histogram("request_duration", "Request duration", ["request_id"])

def process(request_id):
    with request_duration.labels(request_id=request_id).time():
        do_work()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_detects_email_in_labels(self, detector):
        """Detects email as metric label (high cardinality)."""
        code = """
from prometheus_client import Gauge

active_users = Gauge("active_users", "Active users", ["email"])

def track_user(email):
    active_users.labels(email=email).set(1)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_low_cardinality_labels(self, detector):
        """No finding for low cardinality labels."""
        code = """
from prometheus_client import Counter

request_count = Counter("http_requests", "HTTP requests", ["method", "status"])

def handle_request(method, status):
    request_count.labels(method=method, status=status).inc()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_no_metrics(self, detector):
        """No finding when no metrics are used."""
        code = """
def process(data):
    return data.upper()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_timestamp_in_labels(self, detector):
        """Detects timestamp as metric label (high cardinality)."""
        code = """
from prometheus_client import Counter

events = Counter("events", "Events", ["timestamp"])

def log_event(ts):
    events.labels(timestamp=ts).inc()
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
