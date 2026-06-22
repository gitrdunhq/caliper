"""Tests for SecretStr detector.
# tested-by: tests/unit/detectors/security/test_secret_str.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from eedom.detectors.security.secret_str import SecretStrDetector


class TestSecretStrDetector:
    """Tests for SecretStrDetector (EED-004)."""

    @pytest.fixture
    def detector(self):
        return SecretStrDetector()

    def test_detects_api_key_as_str(self, detector):
        """Detects api_key: str as a violation."""
        code = "api_key: str = 'secret123'"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-004"
        assert "api_key" in findings[0].message
        assert "SecretStr" in findings[0].message

    def test_ignores_api_key_as_secretstr(self, detector):
        """No finding when using SecretStr."""
        code = "api_key: SecretStr = 'secret123'"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_password_as_str(self, detector):
        """Detects password: str as a violation."""
        code = "password: str = 'hunter2'"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert "password" in findings[0].message

    def test_detects_secret_token_as_str(self, detector):
        """Detects secret_token: str as a violation."""
        code = "secret_token: str = 'abc123'"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert findings[0].detector_id == "EED-004"

    def test_ignores_non_secret_names(self, detector):
        """No finding for non-secret field names."""
        code = """
name: str = "Alice"
age: int = 30
username: str = "alice123"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 0

    def test_detects_credential_as_str(self, detector):
        """Detects credential: str as a violation."""
        code = "credential: str = 'secret'"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert "credential" in findings[0].message


class TestSecretStrRegressions:
    """Regression tests for P12-1 fix: bare ast.Assign flagging (#432).

    Before the fix, only annotated assignments (api_key: str = "x") were
    detected.  Plain assignments (api_key = "x") were a false negative.
    """

    @pytest.fixture
    def detector(self):
        return SecretStrDetector()

    def test_bare_assign_api_key_literal_flagged(self, detector):
        """P12-1: api_key = "literal" (bare ast.Assign) must be flagged.

        This was a false negative before the fix — only ast.AnnAssign was
        checked, not ast.Assign.
        """
        code = 'api_key = "s3cr3t-key-value"'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 1, "bare api_key = '...' must be flagged as a hardcoded secret"
        assert findings[0].detector_id == "EED-004"
        assert "api_key" in findings[0].message

    def test_bare_assign_password_literal_flagged(self, detector):
        """P12-1: password = "literal" must also be flagged."""
        code = 'password = "hunter2"'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 1
        assert "password" in findings[0].message

    def test_bare_assign_non_literal_not_flagged(self, detector):
        """P12-1: api_key = some_variable (not a string literal) must NOT be flagged.

        Only hardcoded string literals are in scope — variable references and
        function calls are fine (they're not hardcoded secrets).
        """
        code = "api_key = get_secret_from_vault()"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 0, "api_key assigned from a function call must NOT be flagged"

    def test_annotated_assign_still_flagged(self, detector):
        """P12-1: annotated form (api_key: str = ...) must still be flagged (no regression)."""
        code = 'api_key: str = "value"'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) >= 1, "annotated api_key: str must still be detected"

    def test_bare_assign_non_secret_name_not_flagged(self, detector):
        """P12-1: username = "alice" must NOT be flagged (not a secret name)."""
        code = 'username = "alice"'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = detector.detect(Path(f.name))

        assert len(findings) == 0, "non-secret name must not be flagged"
