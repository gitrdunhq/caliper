"""Tests for JWT Audience detector.
# tested-by: tests/unit/detectors/security/test_jwt_audience.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from caliper.detectors.security.jwt_audience import JWTAudienceDetector


class TestJWTAudienceDetector:
    """Tests for JWTAudienceDetector (CAL-001)."""

    @pytest.fixture
    def detector(self):
        return JWTAudienceDetector()

    def test_detects_missing_aud_in_dict_literal(self, detector):
        """Detects jwt.encode with dict literal missing 'aud'."""
        code = """
import jwt
token = jwt.encode({"user": "alice"}, "secret", algorithm="HS256")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-001"
        assert "missing 'aud' claim" in findings[0].message

    def test_ignores_when_aud_present(self, detector):
        """No finding when 'aud' claim is present."""
        code = """
import jwt
token = jwt.encode({"user": "alice", "aud": "my-api"}, "secret", algorithm="HS256")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_ignores_variable_payload(self, detector):
        """Does not flag when payload is a variable (can't analyze statically)."""
        code = """
import jwt
payload = {"user": "alice"}
token = jwt.encode(payload, "secret", algorithm="HS256")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        # Should not flag variables (can't know if aud is present)
        assert len(findings) == 0

    def test_detects_multiple_violations(self, detector):
        """Detects multiple jwt.encode calls without aud."""
        code = """
import jwt
token1 = jwt.encode({"user": "alice"}, "secret", algorithm="HS256")
token2 = jwt.encode({"user": "bob"}, "secret", algorithm="HS256")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 2

    def test_returns_line_numbers(self, detector):
        """Findings have correct line numbers."""
        code = """x = 1
import jwt
token = jwt.encode({"user": "alice"}, "secret", algorithm="HS256")
y = 2
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].line_number == 3
