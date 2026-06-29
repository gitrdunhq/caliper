# tested-by: tests/unit/test_repo_config.py
# tested-by: tests/unit/test_repo_config_merge.py
"""Repo-level configuration loaded from .caliper.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, ValidationError

from caliper.core.models import PartTarget

logger = structlog.get_logger()

_CONFIG_FILENAME = ".caliper.yaml"


class SemgrepConfig(BaseModel):
    """Semgrep/opengrep tuning passed to the runner."""

    extra_config_dirs: list[str] = []
    exclude_rules: list[str] = []


class PluginConfig(BaseModel):
    """Per-plugin allow/deny filtering."""

    enabled: list[str] | None = None
    disabled: list[str] | None = None
    semgrep: SemgrepConfig = SemgrepConfig()


class TelemetryConfig(BaseModel):
    """Anonymous opt-in telemetry settings."""

    enabled: bool = False
    endpoint: str = "https://telemetry.caliper.dev/v1/events"


# Default classification globs for parting. Matched (fnmatch-style) against the
# posix relative path AND the basename, so both ``poetry.lock`` and
# ``sub/dir/poetry.lock`` match. Order does not matter — classification in
# ``part_stock`` checks generated, then config, then test, then falls to logic.
_DEFAULT_GENERATED_GLOBS: list[str] = [
    "*.lock",
    "package-lock.json",
    "poetry.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "uv.lock",
    "*.generated.*",
    "*.gen.go",
    "*_pb2.py",
    "*_pb2.pyi",
    "*.pb.go",
    "*.snap",
    "vendor/**",
    "**/vendor/**",
    "**/__generated__/**",
    "**/__snapshots__/**",
]
_DEFAULT_CONFIG_GLOBS: list[str] = [
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.ini",
    "*.cfg",
    "*.conf",
    "*.properties",
    ".github/**",
    "**/.github/**",
    "Dockerfile",
    "**/Dockerfile",
    "*.env",
    ".env*",
]
_DEFAULT_TEST_GLOBS: list[str] = [
    "test_*.py",
    "*_test.py",
    "*_test.go",
    "*.test.*",
    "*.spec.*",
    "tests/**",
    "**/tests/**",
    "test/**",
    "**/test/**",
    "**/__tests__/**",
]


class PartingConfig(BaseModel):
    """Configuration for ``caliper part`` (the parting / diff-cutting operation).

    All knobs are deterministic inputs to the pure ``part()`` decision and the
    pinned git diff invocation. The defaults target reviewable parts of roughly
    50-200 changed lines with a hard cap of 400.
    """

    size_cap: int = 400
    target: PartTarget = PartTarget.stack
    # Pinned git diff thresholds — fixed so classification never depends on
    # ambient git config (see core/part_stock.py).
    rename_threshold: int = 50  # --find-renames=N%
    copy_threshold: int = 50  # --find-copies=N%
    rename_limit: int = 1000  # -l <limit>
    # A move (rename) whose content delta exceeds this is not a confident move:
    # it is re-emitted as ``logic`` and recorded in the cut list's ambiguities.
    move_ambiguity_size: int = 50
    generated_globs: list[str] = _DEFAULT_GENERATED_GLOBS
    config_globs: list[str] = _DEFAULT_CONFIG_GLOBS
    test_globs: list[str] = _DEFAULT_TEST_GLOBS
    # Optional per-part validate command run after each peel by restack.sh.
    # Empty (the default) means the self-check is skipped silently.
    validate_command: str = ""


class RepoConfig(BaseModel):
    """Top-level repo config parsed from .caliper.yaml."""

    plugins: PluginConfig = PluginConfig()
    thresholds: dict[str, dict[str, Any]] = {}
    telemetry: TelemetryConfig = TelemetryConfig()
    parting: PartingConfig = PartingConfig()


def load_merged_config(repo_path: Path, package_root: Path | None = None) -> RepoConfig:
    """Load root config, optionally merge with package-level config.

    When *package_root* is ``None`` or equal to *repo_path*, the root config
    is returned as-is.  When *package_root* points to a subdirectory that
    contains its own ``.caliper.yaml``, the two configs are merged:

    * ``plugins.disabled`` / ``plugins.enabled``: package value takes precedence
      when set; falls back to root when the package config omits the field.
    * ``thresholds``: root thresholds are the base; package thresholds override
      on a per-key basis.
    """
    root_config = load_repo_config(repo_path)
    if package_root is None or package_root == repo_path:
        return root_config
    pkg_config_file = package_root / _CONFIG_FILENAME
    if not pkg_config_file.exists():
        return root_config
    pkg_config = load_repo_config(package_root)
    merged_plugins = PluginConfig(
        enabled=pkg_config.plugins.enabled or root_config.plugins.enabled,
        disabled=pkg_config.plugins.disabled or root_config.plugins.disabled,
        # Preserve the semgrep sub-config (extra_config_dirs / exclude_rules): package
        # takes precedence when it sets one, else fall back to root. Previously this was
        # reconstructed without semgrep and silently reset to defaults (P05-6).
        semgrep=(
            pkg_config.plugins.semgrep
            if pkg_config.plugins.semgrep != PluginConfig().semgrep
            else root_config.plugins.semgrep
        ),
    )
    merged_thresholds = {**root_config.thresholds, **pkg_config.thresholds}
    # Carry telemetry through the merge (package precedence when set, else root).
    # Previously RepoConfig was built without telemetry, dropping root telemetry to
    # defaults during a package merge (#262).
    merged_telemetry = (
        pkg_config.telemetry if pkg_config.telemetry != TelemetryConfig() else root_config.telemetry
    )
    return RepoConfig(
        plugins=merged_plugins,
        thresholds=merged_thresholds,
        telemetry=merged_telemetry,
    )


def load_repo_config(repo_path: Path) -> RepoConfig:
    """Load .caliper.yaml from *repo_path*.

    Returns RepoConfig() with defaults when the file is absent.
    Raises ValueError on invalid YAML or schema violations.
    """
    config_file = repo_path / _CONFIG_FILENAME

    if not config_file.exists():
        logger.debug("repo_config.not_found", path=str(config_file))
        return RepoConfig()

    try:
        raw_text = config_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Cannot read {config_file}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {config_file}: {exc}") from exc

    # Empty file → yaml.safe_load returns None
    if data is None:
        return RepoConfig()

    if not isinstance(data, dict):
        raise ValueError(f"{config_file} must contain a YAML mapping, got {type(data).__name__}")

    try:
        return RepoConfig.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Schema error in {config_file}: {exc}") from exc
