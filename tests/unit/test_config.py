"""Tests for eedom.core.config — configuration module."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError


class TestEedomSettings:
    """Test suite for EedomSettings configuration loading."""

    @staticmethod
    def _minimal_env() -> dict[str, str]:
        """Return the minimum required env vars for a valid config."""
        return {
            "EEDOM_DB_DSN": "postgresql://user:pass@localhost:5432/testdb",
        }

    @staticmethod
    def _full_env() -> dict[str, str]:
        """Return a complete env var set with all fields specified."""
        return {
            "EEDOM_OPERATING_MODE": "advise",
            "EEDOM_DB_DSN": "postgresql://user:pass@localhost:5432/testdb",
            "EEDOM_EVIDENCE_PATH": "/tmp/evidence",
            "EEDOM_SCANNER_TIMEOUT": "90",
            "EEDOM_COMBINED_SCANNER_TIMEOUT": "200",
            "EEDOM_OPA_TIMEOUT": "15",
            "EEDOM_LLM_TIMEOUT": "45",
            "EEDOM_PIPELINE_TIMEOUT": "400",
            "EEDOM_OPA_POLICY_PATH": "/opt/policies",
            "EEDOM_ENABLED_SCANNERS": "syft,trivy",
            "EEDOM_LLM_ENABLED": "true",
            "EEDOM_LLM_ENDPOINT": "https://llm.example.com/v1",
            "EEDOM_LLM_MODEL": "gpt-4o",
            "EEDOM_LLM_API_KEY": "sk-test-key",
            "EEDOM_ALTERNATIVES_PATH": "/opt/alternatives.json",
        }

    def test_valid_config_loads_from_env(self) -> None:
        """Full env var set produces a correctly populated settings object."""
        from eedom.core.config import EedomSettings

        env = self._full_env()
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        assert settings.operating_mode.value == "advise"
        assert settings.db_dsn == "postgresql://user:pass@localhost:5432/testdb"
        assert settings.evidence_path == "/tmp/evidence"
        assert settings.scanner_timeout == 90
        assert settings.combined_scanner_timeout == 200
        assert settings.opa_timeout == 15
        assert settings.llm_timeout == 45
        assert settings.pipeline_timeout == 400
        assert settings.opa_policy_path == "/opt/policies"
        assert settings.enabled_scanners == ["syft", "trivy"]
        assert settings.llm_enabled is True
        assert settings.llm_endpoint == "https://llm.example.com/v1"
        assert settings.llm_model == "gpt-4o"
        assert settings.llm_api_key.get_secret_value() == "sk-test-key"
        assert settings.alternatives_path == "/opt/alternatives.json"

    def test_file_source_defaults_to_auto(self) -> None:
        """file_source defaults to 'auto' and is overridable via env."""
        from eedom.core.config import EedomSettings

        with patch.dict(os.environ, {"EEDOM_DB_DSN": "postgresql://u:p@h:5432/d"}, clear=True):
            assert EedomSettings().file_source == "auto"

        env = {"EEDOM_DB_DSN": "postgresql://u:p@h:5432/d", "EEDOM_FILE_SOURCE": "walk"}
        with patch.dict(os.environ, env, clear=True):
            assert EedomSettings().file_source == "walk"

    def test_missing_db_dsn_raises_validation_error(self) -> None:
        """Config without DB_DSN must fail with a clear validation error."""
        from eedom.core.config import EedomSettings

        with patch.dict(os.environ, {}, clear=True), pytest.raises(ValidationError) as exc_info:
            EedomSettings()

        errors = exc_info.value.errors()
        field_names = [e["loc"][-1] for e in errors]
        assert "db_dsn" in field_names

    def test_invalid_operating_mode_raises_validation_error(self) -> None:
        """Operating mode must be restricted to 'monitor' and 'advise'."""
        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        env["EEDOM_OPERATING_MODE"] = "enforce"
        with patch.dict(os.environ, env, clear=True), pytest.raises(ValidationError) as exc_info:
            EedomSettings()

        errors = exc_info.value.errors()
        # The error should reference operating_mode
        field_names = [e["loc"][-1] for e in errors]
        assert "operating_mode" in field_names

    def test_default_values_are_correct(self) -> None:
        """When only required fields are provided, defaults match the architecture doc."""
        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        # Operating mode defaults to monitor
        assert settings.operating_mode.value == "monitor"

        # Timeout defaults per Section 14.3
        assert settings.scanner_timeout == 60
        assert settings.combined_scanner_timeout == 180
        assert settings.opa_timeout == 10
        assert settings.llm_timeout == 30
        assert settings.pipeline_timeout == 300

        # Path defaults
        assert settings.evidence_path == "./evidence"
        assert settings.opa_policy_path == "./policies/policy.rego"
        assert settings.alternatives_path == "./alternatives.json"

        # Scanner defaults
        assert settings.enabled_scanners == ["syft", "osv-scanner", "trivy", "scancode"]

        # LLM defaults
        assert settings.llm_enabled is False
        assert settings.llm_endpoint is None
        assert settings.llm_model is None
        assert settings.llm_api_key is None

    def test_minimal_config_loads_with_defaults(self) -> None:
        """Minimal config (just DB_DSN) loads successfully."""
        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        assert settings.db_dsn == "postgresql://user:pass@localhost:5432/testdb"

    def test_enabled_scanners_parsed_from_comma_separated(self) -> None:
        """Comma-separated scanner list is parsed into a Python list."""
        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        env["EEDOM_ENABLED_SCANNERS"] = "syft,trivy,osv-scanner"
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        assert settings.enabled_scanners == ["syft", "trivy", "osv-scanner"]

    def test_llm_api_key_is_secret_str(self) -> None:
        """F-021: llm_api_key must be a SecretStr, not a plain str."""
        from pydantic import SecretStr

        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        env["EEDOM_LLM_API_KEY"] = "sk-my-key"
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        assert isinstance(settings.llm_api_key, SecretStr)
        # repr/str must not expose the value
        assert "sk-my-key" not in repr(settings.llm_api_key)
        assert settings.llm_api_key.get_secret_value() == "sk-my-key"

    def test_scancode_timeout_default(self) -> None:
        """scancode_timeout defaults to 60 (closes #335)."""
        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        assert settings.scancode_timeout == 60

    def test_scancode_license_score_default(self) -> None:
        """scancode_license_score defaults to 0 (disabled) (closes #335)."""
        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        assert settings.scancode_license_score == 0

    def test_scancode_timeout_overridden_by_env(self) -> None:
        """EEDOM_SCANCODE_TIMEOUT env var overrides the default."""
        from eedom.core.config import EedomSettings

        env = self._minimal_env()
        env["EEDOM_SCANCODE_TIMEOUT"] = "30"
        with patch.dict(os.environ, env, clear=True):
            settings = EedomSettings()

        assert settings.scancode_timeout == 30
