# tested-by: tests/unit/test_port_registries.py
"""Core-owned adapter registries for the external-dependency ports.

These registries live in ``core`` (not ``data``/``adapters``) on purpose: the
enforced tier boundary forbids ``data`` and ``adapters`` from importing each
other, but both may import ``core``. So the registry that an osv-style data
adapter *and* a Null/File adapter both register into has to be core-owned.

Adapters self-register on import via ``@REGISTRY.register("key")``. Because
``autodiscover`` cannot cross tier boundaries, registration is triggered by the
composition tier importing the adapter modules (see
``eedom.composition.bootstrap.load_adapters``); conformance tests import them
directly.
"""

from __future__ import annotations

from eedom.core.policy_port import PolicyEnginePort
from eedom.core.ports import (
    CodeGraphCheckPort,
    DecisionStorePort,
    EnricherPort,
    EvidenceStorePort,
    FileSourcePort,
    PackageMetadataPort,
    PackageSourcePort,
    PullRequestPublisherPort,
    ReportRendererPort,
    RepoSnapshotPort,
    SemgrepRunnerPort,
)
from eedom.registry import Registry

ENRICHERS: Registry[EnricherPort] = Registry("enricher")
POLICY_ENGINES: Registry[PolicyEnginePort] = Registry("policy_engine")
RENDERERS: Registry[ReportRendererPort] = Registry("renderer")
RULE_RUNNERS: Registry[SemgrepRunnerPort] = Registry("rule_runner")
CODEGRAPH_CHECKS: Registry[CodeGraphCheckPort] = Registry("codegraph_check")
# git ls-files vs. filesystem walk — one seam for file enumeration.
FILE_SOURCES: Registry[FileSourcePort] = Registry("file_source")
# data/pypi's PyPIClient implements PackageMetadataPort (fetch_metadata/close),
# which is the real PyPI contract the pipeline uses; PackageIndexPort is vestigial.
PACKAGE_INDEXES: Registry[PackageMetadataPort] = Registry("package_index")
# data/pkgsrc's PyPISource/NpmSource fetch+extract a version's distribution so the
# supply-chain version-bump analyzer can diff the actual source between two versions.
PACKAGE_SOURCES: Registry[PackageSourcePort] = Registry("package_source")
DECISION_STORES: Registry[DecisionStorePort] = Registry("decision_store")
EVIDENCE_STORES: Registry[EvidenceStorePort] = Registry("evidence_store")
PUBLISHERS: Registry[PullRequestPublisherPort] = Registry("publisher")
REPO_SNAPSHOTS: Registry[RepoSnapshotPort] = Registry("repo_snapshot")

__all__ = [
    "CODEGRAPH_CHECKS",
    "DECISION_STORES",
    "ENRICHERS",
    "EVIDENCE_STORES",
    "FILE_SOURCES",
    "PACKAGE_INDEXES",
    "PACKAGE_SOURCES",
    "POLICY_ENGINES",
    "PUBLISHERS",
    "RENDERERS",
    "REPO_SNAPSHOTS",
    "RULE_RUNNERS",
]
