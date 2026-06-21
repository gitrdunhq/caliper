# tested-by: tests/unit/test_bootstrap_wiring.py
"""ApplicationContext — the core-owned container of wired port dependencies.

This is a pure core contract: it references only core port Protocols. The
composition tier (``eedom.composition``) constructs instances; core consumers
(``use_cases``, the pipeline) depend on the *type*, never on the wiring.
"""

from __future__ import annotations

from dataclasses import dataclass

from eedom.core.policy_port import PolicyEnginePort
from eedom.core.ports import (
    AnalyzerRegistryPort,
    AuditSinkPort,
    DecisionStorePort,
    EvidenceStorePort,
    PackageIndexPort,
    PullRequestPublisherPort,
)
from eedom.core.tool_runner import ToolRunnerPort


@dataclass
class ApplicationContext:
    """Holds all wired port dependencies for one application instance."""

    analyzer_registry: AnalyzerRegistryPort
    policy_engine: PolicyEnginePort
    tool_runner: ToolRunnerPort
    decision_store: DecisionStorePort
    evidence_store: EvidenceStorePort
    package_index: PackageIndexPort
    audit_sink: AuditSinkPort
    publisher: PullRequestPublisherPort
