# tested-by: tests/unit/test_bootstrap_wiring.py
"""ApplicationContext — the core-owned container of wired port dependencies.

This is a pure core contract: it references only core port Protocols. The
composition tier (``caliper.composition``) constructs instances; core consumers
(``use_cases``, the pipeline) depend on the *type*, never on the wiring.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from caliper.core.policy_port import PolicyEnginePort
from caliper.core.ports import (
    AnalyzerRegistryPort,
    AuditSinkPort,
    DecisionRepositoryPort,
    DecisionStorePort,
    EvidenceStorePort,
    EvidenceWriterPort,
    GroundingProviderPort,
    PackageIndexPort,
    PackageMetadataPort,
    PullRequestPublisherPort,
    ScannerPort,
    ScribePort,
)
from caliper.core.tool_runner import ToolRunnerPort


@dataclass
class ApplicationContext:
    """Holds all wired port dependencies for one application instance.

    The first eight fields are the always-present hexagonal ports. The trailing
    fields are the review-pipeline collaborators; they default to empty/None and
    are populated by ``bootstrap(settings)`` in the composition tier. Core reads
    them only through the ``caliper.core.accessors`` get_* functions, which raise a
    clear error when a required collaborator is missing.
    """

    analyzer_registry: AnalyzerRegistryPort
    policy_engine: PolicyEnginePort
    tool_runner: ToolRunnerPort
    decision_store: DecisionStorePort
    evidence_store: EvidenceStorePort
    package_index: PackageIndexPort
    audit_sink: AuditSinkPort
    publisher: PullRequestPublisherPort

    # Review-pipeline collaborators (injected by the composition tier).
    scanners: list[ScannerPort] = field(default_factory=list)
    evidence_writer: EvidenceWriterPort | None = None
    package_metadata: PackageMetadataPort | None = None
    decision_repository: DecisionRepositoryPort | None = None
    audit_log_appender: Callable[[Path, list, str], object] | None = None
    scribes: list[ScribePort] = field(default_factory=list)

    # Gated, on-demand code-grounding provider (invisible unless grounding_enabled;
    # NullGroundingProvider otherwise). Not consulted by the normal review path.
    grounding: GroundingProviderPort | None = None
