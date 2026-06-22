"""Tests for Rate Limiting detector.
# tested-by: tests/unit/detectors/security/test_rate_limiting.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.security.rate_limiting import RateLimitingDetector


class TestRateLimitingDetector:
    """Tests for RateLimitingDetector (CAL-003)."""

    @pytest.fixture
    def detector(self):
        return RateLimitingDetector()

    def test_detects_fastapi_endpoint_without_limit(self, detector):
        """Detects FastAPI endpoint without rate limiting decorator."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/data")
def get_data():
    return {"data": "value"}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-003"

    def test_detects_flask_endpoint_without_limit(self, detector):
        """Detects Flask endpoint without rate limiting."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route("/api/data")
def get_data():
    return {"data": "value"}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_fastapi_with_limit(self, detector):
        """No finding when FastAPI has rate limit decorator."""
        code = """
from fastapi import FastAPI
from slowapi import Limiter

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)

@app.get("/api/data")
@limiter.limit("5/minute")
def get_data():
    return {"data": "value"}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_flask_with_limit(self, detector):
        """No finding when Flask has rate limit decorator."""
        code = """
from flask import Flask
from flask_limiter import Limiter

app = Flask(__name__)
limiter = Limiter(app)

@app.route("/api/data")
@limiter.limit("5/minute")
def get_data():
    return {"data": "value"}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_non_endpoint_functions(self, detector):
        """No finding for regular functions."""
        code = """
def helper_function():
    return "help"

class MyClass:
    def method(self):
        return "method"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0
