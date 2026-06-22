"""Agent-specific configuration for Foreman.
# tested-by: tests/unit/test_agent_config.py

Separate from CaliperSettings — uses FOREMAN_ env prefix.
The agent constructs an CaliperSettings internally when calling the pipeline.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources.providers.env import EnvSettingsSource


class _CommaSeparatedEnvSource(EnvSettingsSource):
    """Handles comma-separated strings for list fields (e.g. 'syft,trivy')."""

    def decode_complex_value(self, field_name: str, field: Any, value: str) -> Any:  # noqa: ANN401
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            if isinstance(value, str) and "," in value:
                return [s.strip() for s in value.split(",") if s.strip()]
            return value


class EnforcementMode(StrEnum):
    """How the agent enforces policy decisions on PRs."""

    block = "block"
    warn = "warn"
    log = "log"


class AgentSettings(BaseSettings):
    """Foreman agent configuration loaded from FOREMAN_* env vars."""

    model_config = SettingsConfigDict(
        env_prefix="FOREMAN_",
        case_sensitive=False,
    )

    enforcement_mode: EnforcementMode = EnforcementMode.warn
    github_token: SecretStr
    llm_model: str = "gpt-4.1"
    max_comment_length: int = Field(default=3900, ge=500)
    repo_path: Path = Path(".")
    evidence_path: Path = Path("./evidence")
    opa_policy_path: Path = Path("./policies")
    enabled_scanners: list[str] = Field(default=["syft", "osv-scanner", "trivy"])
    semgrep_timeout: int = 120
    pipeline_timeout: int = 300
    # TODO: replace with Optional[str] once no-DB mode is implemented.
    # Currently triggers NullRepository fallback in the pipeline.
    # Removal condition: when CaliperSettings.db_dsn becomes optional.
    # No credentials in the default DSN — override via FOREMAN_DB_DSN.
    db_dsn: str = "postgresql://localhost/caliper"
    policy_version: str = "1.0.0"

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: Any,  # noqa: ANN401
        env_settings: Any,  # noqa: ANN401
        dotenv_settings: Any,  # noqa: ANN401
        file_secret_settings: Any,  # noqa: ANN401
    ) -> tuple[Any, ...]:
        return (
            init_settings,
            _CommaSeparatedEnvSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )
