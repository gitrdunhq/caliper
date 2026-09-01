# tested-by: tests/unit/test_repo_config.py
# tested-by: tests/unit/test_repo_config_merge.py
"""Repo-level configuration loaded from .caliper.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from caliper.core.models import ChangeType, PartTarget

# Structural buckets are facts from git, not classification guesses — an override
# may not target them (a file is a delete/move/binary or it is not).
_STRUCTURAL_BUCKETS: frozenset[ChangeType] = frozenset(
    {ChangeType.move, ChangeType.delete, ChangeType.binary}
)

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
# Generic runtime/app config. Deliberately low-precedence: ``*.yaml`` is greedy,
# so the specific buckets below (ci_cd, infra, schema_contracts, supply_chain) are
# matched FIRST in ``part_stock._classify``. ``.github/**`` and ``Dockerfile`` used
# to live here; they now route to ci_cd / infra respectively.
_DEFAULT_CONFIG_GLOBS: list[str] = [
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.ini",
    "*.cfg",
    "*.conf",
    "*.properties",
    "*.env",
    ".env*",
]
# Security & policy-as-code (Rego, IAM, policy bundles).
_DEFAULT_SECURITY_POLICY_GLOBS: list[str] = [
    "*.rego",
    "policies/**",
    "**/policies/**",
    "iam/**",
    "**/iam/**",
    "*.policy.json",
]
# Dependency manifests (the human-edited source; lockfiles stay ``generated``).
_DEFAULT_SUPPLY_CHAIN_GLOBS: list[str] = [
    "package.json",
    "**/package.json",
    "pyproject.toml",
    "**/pyproject.toml",
    "requirements*.txt",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "*.csproj",
    "Pipfile",
]
# CI/CD pipelines and build orchestration.
_DEFAULT_CI_CD_GLOBS: list[str] = [
    ".github/workflows/**",
    "**/.github/workflows/**",
    "Makefile",
    "**/Makefile",
    "GNUmakefile",
    ".gitlab-ci.yml",
    "*.gitlab-ci.yml",
    "Jenkinsfile",
    "**/Jenkinsfile",
    "azure-pipelines.yml",
    ".circleci/**",
    "**/.circleci/**",
    ".pre-commit-config.yaml",
]
# Schemas, contracts, and migrations — the wire/storage shape.
_DEFAULT_SCHEMA_CONTRACTS_GLOBS: list[str] = [
    "*.proto",
    "migrations/**",
    "**/migrations/**",
    "openapi*.yaml",
    "openapi*.yml",
    "openapi*.json",
    "swagger*.yaml",
    "swagger*.json",
    "*.graphql",
    "*.gql",
    "*.avsc",
    "schema.sql",
    "**/schema.sql",
]
# Documentation and prose.
_DEFAULT_DOCUMENTATION_GLOBS: list[str] = [
    "*.md",
    "*.mdx",
    "*.rst",
    "*.adoc",
    "docs/**",
    "**/docs/**",
    "README*",
    "**/README*",
    "CHANGELOG*",
    "LICENSE",
    "LICENSE.*",
    "NOTICE",
    "AUTHORS",
    "CONTRIBUTING*",
]
# Infrastructure-as-code and runtime/cloud topology.
_DEFAULT_INFRA_GLOBS: list[str] = [
    "*.tf",
    "*.tfvars",
    "*.tf.json",
    "terraform/**",
    "**/terraform/**",
    "cdk/**",
    "**/cdk/**",
    "*-stack.ts",
    "*.stack.ts",
    "Dockerfile",
    "**/Dockerfile",
    "Dockerfile.*",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "*.bicep",
    "k8s/**",
    "**/k8s/**",
    "kubernetes/**",
    "**/kubernetes/**",
    "helm/**",
    "**/helm/**",
    "serverless.yml",
    "serverless.yaml",
    "Pulumi.yaml",
]
# Architectural code tiers that are NOT glob-determinable across repos
# (frontend/data/business) default to empty: unmatched code falls to the
# ``logic`` residual and is tiered by a human via the reclassify loop.
_DEFAULT_FRONTEND_GLOBS: list[str] = []
_DEFAULT_DATA_GLOBS: list[str] = []
_DEFAULT_BUSINESS_GLOBS: list[str] = []
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


class OverrideRule(BaseModel):
    """A human reclassification: files matching ``glob`` are forced into ``bucket``.

    Overrides are the deterministic feedback loop — a version-controlled table that
    sits above the heuristic globs in ``_classify`` but below the structural facts
    (delete/move/binary), so a reviewer can correct a tier without touching code.
    Glob-based (not exact paths) so a rename does not silently orphan an override.
    First matching rule in list order wins.
    """

    model_config = ConfigDict(extra="forbid")

    glob: str
    bucket: ChangeType
    note: str = ""  # why the human reclassified; provenance only, never gates

    @field_validator("glob")
    @classmethod
    def _glob_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("override glob must be non-empty")
        return v

    @field_validator("bucket")
    @classmethod
    def _bucket_not_structural(cls, v: ChangeType) -> ChangeType:
        if v in _STRUCTURAL_BUCKETS:
            raise ValueError(
                f"override bucket {v!r} is structural (delete/move/binary) and is "
                "decided by git, not by reclassification"
            )
        return v


class PartingConfig(BaseModel):
    """Configuration for ``caliper part`` (the parting / diff-cutting operation).

    All knobs are deterministic inputs to the pure ``part()`` decision and the
    pinned git diff invocation. The default is *uncapped*: a cut is one commit per
    labelled bucket. A ``size_cap`` is opt-in (CLI ``--size-cap`` or config) and
    only refines a bucket by splitting it into ~50-200 line parts when set.
    """

    size_cap: int | None = None
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
    # Two-axis taxonomy globs, checked most-specific-first in _classify (see the
    # precedence list in part_stock.py). Non-code intent buckets first, then the
    # architectural code tiers (sparse by default — human-tiered via overrides).
    security_policy_globs: list[str] = _DEFAULT_SECURITY_POLICY_GLOBS
    supply_chain_globs: list[str] = _DEFAULT_SUPPLY_CHAIN_GLOBS
    ci_cd_globs: list[str] = _DEFAULT_CI_CD_GLOBS
    schema_contracts_globs: list[str] = _DEFAULT_SCHEMA_CONTRACTS_GLOBS
    documentation_globs: list[str] = _DEFAULT_DOCUMENTATION_GLOBS
    infra_globs: list[str] = _DEFAULT_INFRA_GLOBS
    data_globs: list[str] = _DEFAULT_DATA_GLOBS
    frontend_globs: list[str] = _DEFAULT_FRONTEND_GLOBS
    business_globs: list[str] = _DEFAULT_BUSINESS_GLOBS
    # Human reclassification table (the feedback loop). Applied above the globs but
    # below structural facts in _classify; first matching rule wins. Part of the
    # config_digest, so an override changes provenance.
    overrides: list[OverrideRule] = Field(default_factory=list)
    # Optional per-part validate command run after each peel by restack.sh.
    # Empty (the default) means the self-check is skipped silently.
    validate_command: str = ""

    @model_validator(mode="after")
    def _no_duplicate_override_globs(self) -> PartingConfig:
        """Reject duplicate override globs at load — a conflict is a config error.

        Two rules with the same glob assigning different buckets is ambiguous; even
        same-bucket duplicates are dead weight. Fail loudly rather than silently
        picking one (first-match-wins only disambiguates *different* globs).
        """
        seen: set[str] = set()
        dupes: set[str] = set()
        for rule in self.overrides:
            if rule.glob in seen:
                dupes.add(rule.glob)
            seen.add(rule.glob)
        if dupes:
            raise ValueError(f"duplicate override glob(s): {sorted(dupes)}")
        return self


class BaselineConfig(BaseModel):
    """Configuration for finding baseline/suppression (``caliper baseline``)."""

    path: str = ".caliper-baseline.yaml"
    default_ttl_days: int = 90


class ArchitectureConfig(BaseModel):
    """Optional enforced tier-boundary layering for CAL-022 (tier_boundary detector).

    Mirrors caliper's own guard test (``core/tier_map.py`` +
    ``tests/unit/test_deterministic_architecture_guards.py``) but is entirely
    opt-in for a scanned repo: unconfigured (``tiers`` empty, or ``package``/
    ``src_root`` unset) means CAL-022 never fires -- caliper never fabricates
    a layering the repo did not declare (fail-open).

    ``src_root`` is the path (relative to the repo root) of the directory
    that directly contains the tiered subdirectories -- e.g. ``src/myapp``,
    not just ``src``. ``tiers`` maps each subdirectory name under
    ``src_root`` to a tier name (e.g. ``{"api": "presentation", "db": "data"}``).
    ``allow`` maps a source tier to the set of target tiers it may import;
    a tier omitted from ``allow`` may only import itself (default-deny, so a
    half-configured allow-set never becomes silently permissive).
    """

    model_config = ConfigDict(extra="forbid")

    package: str = ""
    src_root: str = ""
    tiers: dict[str, str] = Field(default_factory=dict)
    allow: dict[str, list[str]] = Field(default_factory=dict)


class RepoConfig(BaseModel):
    """Top-level repo config parsed from .caliper.yaml."""

    plugins: PluginConfig = PluginConfig()
    thresholds: dict[str, dict[str, Any]] = {}
    telemetry: TelemetryConfig = TelemetryConfig()
    parting: PartingConfig = PartingConfig()
    baseline: BaselineConfig = BaselineConfig()
    architecture: ArchitectureConfig = ArchitectureConfig()


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
    # Carry parting through the merge (package precedence when set, else root).
    # Previously RepoConfig was rebuilt with only plugins/thresholds/telemetry,
    # silently dropping parting to defaults on a package merge — which would also
    # wipe a parting.overrides table (#442).
    merged_parting = (
        pkg_config.parting if pkg_config.parting != PartingConfig() else root_config.parting
    )
    return RepoConfig(
        plugins=merged_plugins,
        thresholds=merged_thresholds,
        telemetry=merged_telemetry,
        parting=merged_parting,
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
    except OSError as exc:  # noqa: CAL-002  # caught by fixed upstream handler
        raise ValueError(f"Cannot read {config_file}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:  # noqa: CAL-002  # caught by fixed upstream handler
        raise ValueError(f"Invalid YAML in {config_file}: {exc}") from exc

    # Empty file → yaml.safe_load returns None
    if data is None:
        return RepoConfig()

    if not isinstance(data, dict):
        raise ValueError(f"{config_file} must contain a YAML mapping, got {type(data).__name__}")

    try:
        return RepoConfig.model_validate(data)
    except ValidationError as exc:  # noqa: CAL-002  # caught by fixed upstream handler
        raise ValueError(f"Schema error in {config_file}: {exc}") from exc
