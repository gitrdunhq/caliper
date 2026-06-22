# tested-by: tests/unit/test_persistence_adapters.py
"""Persistence adapters for eedom's hexagonal architecture ports.

NullDecisionStore, NullEvidenceStore, NullAuditSink — no-op implementations
used when no backing store is configured.

FileEvidenceStore — writes evidence artifacts to a local filesystem directory.
"""

from __future__ import annotations

from pathlib import Path


class NullDecisionStore:
    """No-op DecisionStorePort — discards all decisions silently."""

    def save_decision(self, decision) -> None:
        """Discard the decision. No-op."""


class NullEvidenceStore:
    """No-op EvidenceStorePort — discards all artifacts silently."""

    def write_artifact(self, path: str, content: bytes) -> str:
        """Discard the artifact and return an empty string ref."""
        return ""


class NullAuditSink:
    """No-op AuditSinkPort — discards all audit events silently."""

    def seal(self, artifact_refs: list[str]) -> str:
        """Discard artifact refs and return an empty seal hash."""
        return ""

    def append_audit_log(self, entry: dict) -> None:
        """Discard the audit log entry. No-op."""


class FileEvidenceStore:
    """EvidenceStorePort that writes artifacts to a local filesystem directory."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir

    def write_artifact(self, path: str, content: bytes) -> str:
        """Write content bytes to base_dir/path, creating parent dirs as needed.

        Returns the absolute path string of the written file.
        """
        target = self.base_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return str(target)


from eedom.core.registries import DECISION_STORES, EVIDENCE_STORES  # noqa: E402  (wiring)


@DECISION_STORES.register("null")
def build_null_decision_store() -> NullDecisionStore:
    return NullDecisionStore()


@EVIDENCE_STORES.register("file")
def build_file_evidence_store(*, base_dir: Path) -> FileEvidenceStore:
    return FileEvidenceStore(base_dir=base_dir)


@EVIDENCE_STORES.register("null")
def build_null_evidence_store() -> NullEvidenceStore:
    return NullEvidenceStore()
