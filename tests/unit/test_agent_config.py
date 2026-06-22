"""Tests for Foreman agent configuration security.
# tested-by: tests/unit/test_agent_config.py
"""

from __future__ import annotations

from pydantic import ValidationError

from caliper.agent.config import AgentSettings


def test_db_dsn_has_no_hardcoded_credentials(monkeypatch):
    """db_dsn default must not contain hardcoded credentials."""
    monkeypatch.delenv("FOREMAN_DB_DSN", raising=False)

    try:
        settings = AgentSettings(github_token="test-token")
        # If a default exists it must not embed 'unused' credentials
        assert (
            "unused" not in settings.db_dsn.lower()
        ), f"Default db_dsn contains hardcoded credentials: {settings.db_dsn}"
    except ValidationError:
        # Required field with no default — acceptable; forces explicit config
        pass


def test_db_dsn_can_be_set_via_env_var(monkeypatch):
    """db_dsn must be configurable via FOREMAN_DB_DSN environment variable."""
    test_dsn = "postgresql://user:pass@prod-db:5432/mydb"
    monkeypatch.setenv("FOREMAN_DB_DSN", test_dsn)

    settings = AgentSettings(github_token="test-token")
    assert settings.db_dsn == test_dsn
