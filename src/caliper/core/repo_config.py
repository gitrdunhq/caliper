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


# Bucket -> admissible claim categories (research-fed default; rule 4). Empty list
# means "drop all claims" for that bucket. A move part admits only behavioral-change.
_ALL_CATEGORIES: list[str] = [
    "correctness",
    "security",
    "behavioral-change",
    "maintainability",
    "performance",
    "style",
]
_DEFAULT_ALLOWED_CATEGORIES: dict[str, list[str]] = {
    "generated": [],
    "binary": [],
    "move": ["behavioral-change"],
    "config": ["correctness", "security", "maintainability", "style"],
    "test": ["correctness", "maintainability", "style"],
    "logic": list(_ALL_CATEGORIES),
    "delete": ["correctness", "behavioral-change"],
    # Architectural tiers (code) — inherit the full logic category set.
    "frontend": list(_ALL_CATEGORIES),
    "business": list(_ALL_CATEGORIES),
    "data": list(_ALL_CATEGORIES),
    "infra": list(_ALL_CATEGORIES),
    # Content intent (non-code).
    "documentation": ["correctness", "maintainability", "style"],
    "supply_chain": ["security", "correctness", "behavioral-change"],
    "ci_cd": ["correctness", "security", "maintainability"],
    "security_policy": ["security", "correctness", "behavioral-change"],
    "schema_contracts": ["correctness", "behavioral-change", "security"],
}

# Bucket -> minimum admissible severity (rule 5). Default "nit" keeps everything;
# research tunes per bucket.
_DEFAULT_SEVERITY_FLOOR: dict[str, str] = {
    "generated": "nit",
    "binary": "nit",
    "move": "nit",
    "config": "nit",
    "test": "nit",
    "logic": "nit",
    "delete": "nit",
    "frontend": "nit",
    "business": "nit",
    "data": "nit",
    "infra": "nit",
    "documentation": "nit",
    "supply_chain": "nit",
    "ci_cd": "nit",
    "security_policy": "nit",
    "schema_contracts": "nit",
}

# Bucket -> Screen gauge routing (analyzer category names, run scoped to the part).
# Research-fed default; reuses existing analyzers, never new scanners.
_DEFAULT_BUCKET_GAUGES: dict[str, list[str]] = {
    "generated": [],  # checksum/stamp handled structurally; no analyzers, no LLM
    "binary": ["supply_chain"],  # malware/size
    "move": [],  # structural-identity gauge handled structurally
    "config": ["infra", "quality"],
    "test": ["quality"],
    "logic": ["code", "quality", "supply_chain"],  # full set + LLM
    "delete": [],  # reference gauge where available (v0 cross-part gap)
    # Architectural tiers (code).
    "frontend": ["code", "quality"],
    "business": ["code", "quality", "supply_chain"],
    "data": ["code", "quality"],
    "infra": ["infra", "quality"],
    # Content intent (non-code).
    "documentation": ["quality"],
    "supply_chain": ["supply_chain"],
    "ci_cd": ["infra", "quality"],
    "security_policy": ["code", "quality"],
    "schema_contracts": ["code", "quality"],
}

# Buckets whose parts get a Review pass. Others are Screen only. The code tiers
# (and the contract/policy buckets) earn an LLM pass; pure non-code data buckets
# (supply_chain manifests, ci_cd, documentation) stay Screen-only.
_DEFAULT_LLM_BUCKETS: list[str] = [
    "logic",
    "config",
    "test",
    "frontend",
    "business",
    "data",
    "infra",
    "security_policy",
    "schema_contracts",
]

# Claim category -> compatible Screen finding categories for evidence binding
# (research-fed default). A blocking claim needs a binding to keep gate-shaped signal.
_DEFAULT_CATEGORY_COMPAT: dict[str, list[str]] = {
    "security": ["security", "vulnerability", "malicious", "malware", "supply_chain"],
    "correctness": ["correctness", "behavioral", "code_smell", "bug"],
    "behavioral-change": ["behavioral", "behavioral-change", "code_smell"],
    "maintainability": ["code_smell", "maintainability", "quality"],
    "performance": ["performance", "resource"],
    "style": ["style", "code_smell"],
}


class InspectConfig(BaseModel):
    """Configuration for ``caliper inspect`` (per-part review).

    Every research-fed default is a knob here so a finding can replace it without
    restructuring. The adjudicator is pure and reads only this config.
    """

    token_budget: int = 8000  # lower-parts context budget (research-fed)
    backend: str = "null"  # LLMPort backend key (research-fed: oMLX + cloud fallback)
    model_id: str = "unset"  # part of the cache key
    prompt_version: str = "v0"  # part of the cache key
    allowed_categories: dict[str, list[str]] = Field(
        default_factory=lambda: dict(_DEFAULT_ALLOWED_CATEGORIES)
    )
    severity_floor: dict[str, str] = Field(default_factory=lambda: dict(_DEFAULT_SEVERITY_FLOOR))
    bucket_gauges: dict[str, list[str]] = Field(
        default_factory=lambda: dict(_DEFAULT_BUCKET_GAUGES)
    )
    llm_buckets: list[str] = Field(default_factory=lambda: list(_DEFAULT_LLM_BUCKETS))
    category_compat: dict[str, list[str]] = Field(
        default_factory=lambda: dict(_DEFAULT_CATEGORY_COMPAT)
    )
    # Fail-closed default: a Screen gauge that cannot run is a hard error. Relax
    # only for local dev where scanner binaries are absent.
    allow_missing_gauges: bool = False


class GaugeConfig(BaseModel):
    """Configuration for ``caliper gauge`` (the flywheel).

    The bias guards are mandatory defaults, all config-tunable: only correctness/
    security/behavioral-change claims are candidate-eligible, and a cluster must
    recur across enough distinct parts and authors before it can be drafted. The
    backtest thresholds are the deterministic gate.
    """

    # Candidacy floor: nits and pure-style claims are ineligible by default.
    eligible_categories: list[str] = Field(
        default_factory=lambda: ["correctness", "security", "behavioral-change"]
    )
    # Recurrence threshold: N distinct parts and M distinct authors/PRs.
    recurrence_min_parts: int = 3
    recurrence_min_authors: int = 2
    # Backtest gates.
    recall_floor: float = 0.7  # must catch at least this fraction of historical hits
    precision_fp_ceiling: float = 0.05  # max false-positive rate on the clean corpus
    runtime_budget_ms: int = 2000  # Screen time budget for a single gauge
    # propose default.
    top_default: int = 10
    # LLM drafting backend (the only LLM step) + lineage stamps.
    drafter: str = "null"
    model_id: str = "unset"
    prompt_version: str = "v0"


class RepoConfig(BaseModel):
    """Top-level repo config parsed from .caliper.yaml."""

    plugins: PluginConfig = PluginConfig()
    thresholds: dict[str, dict[str, Any]] = {}
    telemetry: TelemetryConfig = TelemetryConfig()
    parting: PartingConfig = PartingConfig()
    inspect: InspectConfig = InspectConfig()
    gauge: GaugeConfig = GaugeConfig()


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
