# tested-by: tests/unit/test_ports.py
"""Port protocols for eedom's hexagonal architecture boundaries.

These @runtime_checkable Protocol classes define the contracts that
adapters must satisfy. No business logic lives here.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from eedom.core.enrichment import EnrichmentContext
    from eedom.core.models import PolicyEvaluation, ReviewDecision, ScanResult
    from eedom.core.plugin import PluginFinding


@runtime_checkable
class FileSourcePort(Protocol):
    """Contract for enumerating the files eedom should scan under a root.

    One seam replaces the ad-hoc ``rglob``/``os.walk`` calls scattered across
    the CLI, the supply-chain plugin, and the deterministic scanner. Adapters
    decide *how* files are discovered (git index vs. filesystem walk); the
    eedom exclusion layer (``core.ignore``) composes on top regardless.

    ``list_files`` is deterministic (sorted) and fail-open (never raises;
    returns ``[]`` when a source cannot read the tree). ``is_available`` lets
    the resolver probe a source before committing to it.
    """

    @property
    def name(self) -> str: ...

    def is_available(self, root: Path) -> bool: ...

    def list_files(self, root: Path, *, suffixes: tuple[str, ...] | None = None) -> list[Path]: ...


@runtime_checkable
class ScannerPort(Protocol):
    """Structural contract for a dependency scanner.

    The canonical home of the scanner port; ``data.scanners.base`` re-exports
    it so adapters and the orchestrator depend on a core-owned contract rather
    than a data-tier class.  ``scan`` returns a ``ScanResult`` and never raises
    (failures are represented via ``ScanResult.status``).
    """

    @property
    def name(self) -> str: ...

    def scan(self, target_path: Path) -> ScanResult: ...


@runtime_checkable
class SemgrepRunnerPort(Protocol):
    """Contract for running a semgrep/opengrep ruleset over changed files."""

    def run(
        self,
        changed_files: list,
        repo_path: str,
        timeout: int = 120,
        extra_config_dirs: list | None = None,
        exclude_rules: list | None = None,
    ) -> dict: ...


@runtime_checkable
class CodeGraphCheckPort(Protocol):
    """Contract for running the SQL code-graph checks against the built graph."""

    def run_checks(self, changed_files: list) -> list: ...


@runtime_checkable
class EvidenceWriterPort(Protocol):
    """Contract for the per-run evidence bundle writer used by the pipeline."""

    def get_path(self, run_id: str, package: str) -> str: ...

    def store(self, run_id: str, rel_path: str, content: Any) -> Any: ...


@runtime_checkable
class PackageMetadataPort(Protocol):
    """Contract for fetching package metadata (release dates, etc.)."""

    def fetch_metadata(self, name: str, version: str) -> dict: ...

    def close(self) -> None: ...


@runtime_checkable
class DecisionRepositoryPort(Protocol):
    """Rich persistence contract the review pipeline drives per package.

    Distinct from the narrow ``DecisionStorePort`` (which only persists the
    final decision); the pipeline records the request, scan results, policy
    evaluation, and decision, then closes the connection.
    """

    def connect(self) -> bool: ...

    def save_request(self, request: Any) -> None: ...

    def save_scan_results(self, request_id: Any, results: list) -> None: ...

    def save_policy_evaluation(self, request_id: Any, evaluation: PolicyEvaluation) -> None: ...

    def save_decision(self, request_id: Any, decision: ReviewDecision) -> None: ...

    def close(self) -> None: ...


@runtime_checkable
class AnalyzerRegistryPort(Protocol):
    """Contract for running all registered analyzer plugins."""

    def run_all(self, files: list, repo_path: Path, **kwargs) -> list: ...

    def list(self, category=None, names=None) -> list: ...


@runtime_checkable
class DecisionStorePort(Protocol):
    """Contract for persisting policy decisions."""

    def save_decision(self, decision) -> None: ...


@runtime_checkable
class EvidenceStorePort(Protocol):
    """Contract for writing evidence artifacts."""

    def write_artifact(self, path: str, content: bytes) -> str: ...


@runtime_checkable
class PackageIndexPort(Protocol):
    """Contract for querying package metadata from an index."""

    def get_package_info(self, name: str, ecosystem: str) -> dict: ...


@runtime_checkable
class RepoSnapshotPort(Protocol):
    """Contract for checking out a repository snapshot at a given ref."""

    def checkout_ref(self, ref: str) -> Path: ...

    def cleanup(self) -> None: ...


@runtime_checkable
class PullRequestPublisherPort(Protocol):
    """Contract for publishing review artifacts back to a pull request."""

    def post_comment(self, repo: str, pr_num: int, body: str) -> bool: ...

    def post_review(self, repo: str, pr_num: int, review: dict) -> bool: ...

    def add_label(self, repo: str, pr_num: int, label: str) -> bool: ...


@dataclasses.dataclass
class ReviewReport:
    """Structured output produced by the review pipeline."""

    verdict: str
    security_score: float
    quality_score: float
    plugin_results: list[Any]
    actionability: dict[str, Any]


@runtime_checkable
class ReportRendererPort(Protocol):
    """Contract for rendering a ReviewReport to a string."""

    def render(self, report: ReviewReport) -> str: ...


@runtime_checkable
class AuditSinkPort(Protocol):
    """Contract for sealing audit evidence and appending audit log entries."""

    def seal(self, artifact_refs: list[str]) -> str: ...

    def append_audit_log(self, entry: dict) -> None: ...


@runtime_checkable
class EnricherPort(Protocol):
    """Contract for a deterministic finding enricher (detect-then-enrich, ADR-006).

    ``enrich`` attaches context to a finding's ``metadata['enrichment']`` and returns a
    new finding. It must be deterministic, zero-LLM, fail-open (never raise; on error
    return the finding unchanged), and time-bounded — the verdict never depends on it.
    """

    @property
    def name(self) -> str: ...

    def applies_to(self, finding: PluginFinding) -> bool: ...

    def enrich(self, finding: PluginFinding, ctx: EnrichmentContext) -> PluginFinding: ...
