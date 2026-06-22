"""Deterministic source-inspection guard for plaintext secrets in settings (Issue #261).

Bug: Two sensitive fields are declared as plain str instead of Pydantic SecretStr,
     so their values are exposed in repr(), logs, and JSON serialisation.

Evidence:
  - webhook/config.py line 24: `secret: str`     — HMAC signing secret
  - config.py line 59:         `db_dsn: str`      — PostgreSQL connection string
                                                    (contains password in DSN)

Fix:
  - WebhookSettings.secret  → SecretStr
  - CaliperSettings.db_dsn    → SecretStr
  Access via .get_secret_value() at the one site that actually needs the raw string.

Parent bug: #227 / Epic: #146.
Status: xfail — both fields are still plain str.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #261 — use SecretStr for secrets, then green",
    strict=False,
)


def test_261_webhook_secret_uses_secret_str() -> None:
    """WebhookSettings.secret must be annotated as SecretStr, not str.

    The webhook signing secret is a sensitive credential.  Annotating it as
    plain str means it will appear in repr(WebhookSettings(...)), structured
    log output, and any JSON serialisation of the config object.

    SecretStr prevents accidental exposure by returning [redacted] from repr()
    and __str__(), while still allowing the raw value via .get_secret_value().
    """
    from caliper.webhook.config import WebhookSettings

    src = inspect.getsource(WebhookSettings)
    assert len(src) > 20, "inspect.getsource returned empty source — WebhookSettings not found"
    assert "secret: SecretStr" in src, (
        "BUG #261: WebhookSettings.secret is not SecretStr. "
        "The HMAC signing secret is stored as plain str and will be exposed "
        "in logs and repr() output.  Change `secret: str` to `secret: SecretStr` "
        "and call .get_secret_value() at the HMAC verification site."
    )


def test_261_caliper_settings_db_dsn_uses_secret_str() -> None:
    """CaliperSettings.db_dsn must be annotated as SecretStr, not str.

    A PostgreSQL DSN contains the database password in the URL.  Annotating
    it as plain str means the password appears in repr(), structured logs,
    and any serialised config dump.

    SecretStr prevents accidental password exposure while still providing
    .get_secret_value() for the one site that passes the DSN to the driver.
    """
    from caliper.core.config import CaliperSettings

    src = inspect.getsource(CaliperSettings)
    assert len(src) > 20, "inspect.getsource returned empty source — CaliperSettings not found"
    assert "db_dsn: SecretStr" in src, (
        "BUG #261: CaliperSettings.db_dsn is not SecretStr. "
        "The PostgreSQL DSN (which contains the database password) is stored as "
        "plain str and will be exposed in logs and repr() output.  "
        "Change `db_dsn: str` to `db_dsn: SecretStr` and call "
        ".get_secret_value() when passing the DSN to the database driver."
    )
