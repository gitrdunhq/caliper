"""Configuration module for eedom.

All configuration is loaded from environment variables with the EEDOM_ prefix.
# tested-by: tests/unit/test_config.py
Uses Pydantic BaseSettings for validation and type coercion.
"""

from typing import Any

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources.providers.env import EnvSettingsSource

from eedom.core.models import OperatingMode

# scancode intentionally orphaned (disabled) — its transitive dep lacks arm64
# wheels and breaks cross-platform builds. Re-enable by adding "scancode" back.
_SCANNERS_DEFAULT = ["syft", "osv-scanner", "trivy"]

# On-by-default finding enrichers (ADR-006). Single source of truth shared by the
# EedomSettings default and the settings-free build_default_enrichers() helper.
# Semgrep enrichment is opt-in (subprocess cost), so it is deliberately absent here.
DEFAULT_ENRICHERS = ("enclosing_symbol", "code_graph")


class _CommaSeparatedEnvSource(EnvSettingsSource):
    """Custom env source that splits comma-separated strings for list fields.

    pydantic-settings' default EnvSettingsSource tries json.loads() on complex
    types. For list[str] fields where the env var is a plain comma-separated
    string (e.g. "syft,trivy"), this fails. This source catches the
    JSONDecodeError and falls back to comma-splitting.
    """

    def decode_complex_value(self, field_name: str, field: Any, value: str) -> Any:  # noqa: ANN401
        """Try JSON first; fall back to comma-split for list fields."""
        import json

        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            # Comma-separated fallback for simple list[str] fields. A single
            # value with no comma (e.g. "pypi") still becomes a one-element
            # list — without this, single-value env overrides fail list
            # validation (e.g. EEDOM_SUPPLY_CHAIN_DIFF_ECOSYSTEMS=pypi).
            if isinstance(value, str):
                return [s.strip() for s in value.split(",") if s.strip()]
            return value


class EedomSettings(BaseSettings):
    """Eedom configuration loaded from EEDOM_* env vars.

    db_dsn (PostgreSQL connection string) is optional: when unset, the composition
    root falls back to a NullRepository (decisions are not persisted) rather than
    crashing at startup — consistent with the existing fail-open fallback.

    All timeout values match architecture doc Section 14.3.
    """

    model_config = SettingsConfigDict(
        env_prefix="EEDOM_",
        case_sensitive=False,
    )

    # Operating mode
    operating_mode: OperatingMode = OperatingMode.monitor

    # Database — optional; NullRepository fallback when unset (see class docstring).
    db_dsn: str | None = None

    # Evidence storage
    evidence_path: str = "./evidence"

    # Timeout values per Section 14.3
    scanner_timeout: int = 60
    combined_scanner_timeout: int = 180
    opa_timeout: int = 10
    llm_timeout: int = 30
    pipeline_timeout: int = 300
    pypi_timeout: int = 10

    # OSV-Scanner path exclusions (passed as --experimental-exclude flags)
    # Excludes e2e fixture dirs that contain intentionally pinned old deps.
    osv_exclude_paths: list[str] = Field(
        default=["tests/e2e/fixtures"],
    )

    # File enumeration strategy: "auto" (git ls-files when the target is a
    # usable repo, else an ignore-aware walk), "git", or "walk".
    file_source: str = "auto"

    # OPA policy path
    opa_policy_path: str = "./policies/policy.rego"

    # Enabled scanners (comma-separated in env, e.g. "syft,trivy,osv-scanner")
    enabled_scanners: list[str] = Field(default=_SCANNERS_DEFAULT)

    # Detect-then-enrich (ADR-006): which finding enrichers run after detection.
    # On-by-default enrichers are cheap+deterministic; semgrep is opt-in (per-file
    # subprocess cost). The whole pass is fail-open and bounded by enrichment_timeout.
    enabled_enrichers: list[str] = Field(default=list(DEFAULT_ENRICHERS))
    enrichment_timeout: int = 30

    # LLM task-fit advisory settings
    llm_enabled: bool = False
    llm_endpoint: str | None = None
    llm_model: str | None = None
    llm_api_key: SecretStr | None = None  # F-021: use SecretStr to prevent accidental logging

    # Supply-chain version-bump source-diff analysis (a separate, gated step —
    # NOT part of the normal scan). Off by default: it needs registry egress to
    # fetch package distributions. The optional LLM narrative reuses the llm_*
    # settings and the "supply_chain_threat" enricher (opt-in via enabled_enrichers).
    supply_chain_diff_enabled: bool = False
    supply_chain_diff_timeout: int = 60
    supply_chain_diff_ecosystems: list[str] = Field(default=["pypi", "npm"])
    supply_chain_diff_max_archive_bytes: int = 64 * 1024 * 1024

    # Code grounding (a separate, gated, on-demand producer/consumer step —
    # NOT part of the normal scan). Off by default. Produces a deterministic
    # "fact sheet" (symbols defined in the changed files) + "type context"
    # (type-like contracts referenced from elsewhere) so a downstream consumer
    # starts grounded. Mirrors the supply-chain analyzer's gated shape.
    grounding_enabled: bool = False
    grounding_provider: str = "auto"
    grounding_timeout: int = 60
    grounding_max_symbols: int = 40
    gitnexus_graph_path: str | None = None

    # Alternatives catalog
    alternatives_path: str = "./alternatives.json"

    # ScanCode-specific tuning (closes #335)
    scancode_timeout: int = 60
    scancode_license_score: int = 0

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: Any,  # noqa: ANN401
        env_settings: Any,  # noqa: ANN401
        dotenv_settings: Any,  # noqa: ANN401
        file_secret_settings: Any,  # noqa: ANN401
    ) -> tuple[Any, ...]:
        """Replace default env source with one that handles comma-separated lists."""
        return (
            init_settings,
            _CommaSeparatedEnvSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )
