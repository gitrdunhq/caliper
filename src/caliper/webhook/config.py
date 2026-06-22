"""Webhook server configuration.
# tested-by: tests/unit/test_webhook.py

Loaded from CALIPER_WEBHOOK_* environment variables:
    CALIPER_WEBHOOK_SECRET        — shared secret for HMAC-SHA256 signature validation
    CALIPER_WEBHOOK_GITHUB_TOKEN  — GitHub PAT for posting PR comments
    CALIPER_WEBHOOK_PORT          — port to listen on (default 12800)
"""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class WebhookSettings(BaseSettings):
    """Configuration for the caliper webhook HTTP server."""

    model_config = SettingsConfigDict(
        env_prefix="CALIPER_WEBHOOK_",
        case_sensitive=False,
    )

    secret: str
    github_token: SecretStr
    port: int = 12800
