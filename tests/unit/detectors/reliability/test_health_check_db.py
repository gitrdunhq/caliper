"""Tests for Health Check DB detector.
# tested-by: tests/unit/detectors/reliability/test_health_check_db.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.reliability.health_check_db import HealthCheckDBDetector


class TestHealthCheckDBDetector:
    """Tests for HealthCheckDBDetector (CAL-011)."""

    @pytest.fixture
    def detector(self):
        return HealthCheckDBDetector()

    def test_detects_health_endpoint_without_db_check(self, detector):
        """Detects health check endpoint without DB verification."""
        code = """
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-011"

    def test_detects_fastapi_health_without_db(self, detector):
        """Detects FastAPI health endpoint without DB check."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "healthy"}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1

    def test_ignores_health_with_db_check(self, detector):
        """No finding when DB is verified in health check."""
        code = """
from flask import Flask, jsonify
import psycopg2

app = Flask(__name__)

@app.route("/health")
def health():
    try:
        conn = psycopg2.connect(app.config["DATABASE_URI"])
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return jsonify({"status": "ok", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "error", "database": str(e)}), 500
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_non_health_endpoints(self, detector):
        """No finding for non-health endpoints."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route("/api/users")
def get_users():
    return {"users": []}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_readiness_without_db(self, detector):
        """Detects readiness endpoint without DB check."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/ready")
def readiness():
    return {"ready": True}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
