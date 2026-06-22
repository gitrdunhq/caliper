# tested-by: tests/unit/test_persistence_adapters.py
"""Contract tests for persistence adapters (issue #186).

RED phase: all tests import from caliper.adapters.persistence which does not exist yet.
"""

from __future__ import annotations

from pathlib import Path

from caliper.adapters.persistence import (  # noqa: F401 — will ImportError until green
    FileEvidenceStore,
    NullAuditSink,
    NullDecisionStore,
    NullEvidenceStore,
)
from caliper.core.ports import AuditSinkPort, DecisionStorePort, EvidenceStorePort

# ---------------------------------------------------------------------------
# NullDecisionStore
# ---------------------------------------------------------------------------


class TestNullDecisionStoreProtocolConformance:
    def test_null_decision_store_satisfies_decision_store_port(self):
        """NullDecisionStore must be an instance of DecisionStorePort."""
        store = NullDecisionStore()
        assert isinstance(store, DecisionStorePort)


class TestNullDecisionStore:
    def test_save_decision_returns_none(self):
        """save_decision is a no-op and returns None."""
        store = NullDecisionStore()
        result = store.save_decision({"id": "abc", "verdict": "approve"})
        assert result is None

    def test_save_decision_does_not_raise(self):
        """save_decision must never raise, regardless of input."""
        store = NullDecisionStore()
        store.save_decision(None)
        store.save_decision({})
        store.save_decision({"id": "x", "verdict": "reject"})

    def test_save_decision_callable_multiple_times(self):
        """NullDecisionStore can be called many times without side effects."""
        store = NullDecisionStore()
        for i in range(10):
            store.save_decision({"id": str(i)})


# ---------------------------------------------------------------------------
# NullEvidenceStore
# ---------------------------------------------------------------------------


class TestNullEvidenceStoreProtocolConformance:
    def test_null_evidence_store_satisfies_evidence_store_port(self):
        """NullEvidenceStore must be an instance of EvidenceStorePort."""
        store = NullEvidenceStore()
        assert isinstance(store, EvidenceStorePort)


class TestNullEvidenceStore:
    def test_write_artifact_returns_string(self):
        """write_artifact must return a string (even if empty or placeholder)."""
        store = NullEvidenceStore()
        result = store.write_artifact("sbom.xml", b"<sbom/>")
        assert isinstance(result, str)

    def test_write_artifact_does_not_raise(self):
        """write_artifact must never raise."""
        store = NullEvidenceStore()
        store.write_artifact("any/path.json", b"{}")
        store.write_artifact("", b"")

    def test_write_artifact_callable_multiple_times(self):
        """NullEvidenceStore can be called repeatedly without side effects."""
        store = NullEvidenceStore()
        for i in range(5):
            store.write_artifact(f"artifact_{i}.bin", bytes([i]))


# ---------------------------------------------------------------------------
# NullAuditSink
# ---------------------------------------------------------------------------


class TestNullAuditSinkProtocolConformance:
    def test_null_audit_sink_satisfies_audit_sink_port(self):
        """NullAuditSink must be an instance of AuditSinkPort."""
        sink = NullAuditSink()
        assert isinstance(sink, AuditSinkPort)


class TestNullAuditSink:
    def test_seal_returns_string(self):
        """seal must return a string."""
        sink = NullAuditSink()
        result = sink.seal(["ref1", "ref2"])
        assert isinstance(result, str)

    def test_seal_does_not_raise(self):
        """seal must never raise, regardless of input."""
        sink = NullAuditSink()
        sink.seal([])
        sink.seal(["single-ref"])
        sink.seal(["a", "b", "c", "d"])

    def test_append_audit_log_returns_none(self):
        """append_audit_log is a no-op and returns None."""
        sink = NullAuditSink()
        result = sink.append_audit_log({"action": "scan", "repo": "org/repo"})
        assert result is None

    def test_append_audit_log_does_not_raise(self):
        """append_audit_log must never raise."""
        sink = NullAuditSink()
        sink.append_audit_log({})
        sink.append_audit_log({"action": "complete", "sha": "abc"})

    def test_null_audit_sink_callable_multiple_times(self):
        """NullAuditSink can be called repeatedly without side effects."""
        sink = NullAuditSink()
        for i in range(5):
            sink.seal([f"ref{i}"])
            sink.append_audit_log({"step": i})


# ---------------------------------------------------------------------------
# FileEvidenceStore
# ---------------------------------------------------------------------------


class TestFileEvidenceStoreProtocolConformance:
    def test_file_evidence_store_satisfies_evidence_store_port(self):
        """FileEvidenceStore must be an instance of EvidenceStorePort."""
        store = FileEvidenceStore(base_dir=Path("/evidence"))
        assert isinstance(store, EvidenceStorePort)


class TestFileEvidenceStoreConstructor:
    def test_constructor_accepts_base_dir(self):
        """Constructor takes a base_dir: Path argument."""
        store = FileEvidenceStore(base_dir=Path("/evidence/base"))
        assert store.base_dir == Path("/evidence/base")


class TestFileEvidenceStoreWriteArtifact:
    def test_write_artifact_returns_string_path(self, tmp_path):
        """write_artifact returns a string path to the written file."""
        store = FileEvidenceStore(base_dir=tmp_path)
        result = store.write_artifact("sbom.xml", b"<sbom/>")
        assert isinstance(result, str)

    def test_write_artifact_creates_file_on_disk(self, tmp_path):
        """write_artifact must write the content bytes to a file under base_dir."""
        store = FileEvidenceStore(base_dir=tmp_path)
        store.write_artifact("report.json", b'{"ok": true}')
        files = list(tmp_path.rglob("*"))
        assert any(f.is_file() for f in files)

    def test_write_artifact_content_matches(self, tmp_path):
        """The file written by write_artifact must contain the exact bytes passed in."""
        store = FileEvidenceStore(base_dir=tmp_path)
        content = b"hello evidence world"
        ref = store.write_artifact("evidence.bin", content)
        written = Path(ref).read_bytes()
        assert written == content

    def test_write_artifact_path_contains_artifact_name(self, tmp_path):
        """The returned path string must include the artifact filename."""
        store = FileEvidenceStore(base_dir=tmp_path)
        ref = store.write_artifact("my_artifact.txt", b"data")
        assert "my_artifact.txt" in ref

    def test_write_artifact_creates_parent_dirs(self, tmp_path):
        """write_artifact must create nested subdirectories if needed."""
        store = FileEvidenceStore(base_dir=tmp_path)
        store.write_artifact("subdir/nested/file.bin", b"nested")
        nested = tmp_path / "subdir" / "nested" / "file.bin"
        assert nested.exists()

    def test_write_artifact_returns_path_under_base_dir(self, tmp_path):
        """The returned path must be under base_dir."""
        store = FileEvidenceStore(base_dir=tmp_path)
        ref = store.write_artifact("artifact.xml", b"<xml/>")
        assert str(ref).startswith(str(tmp_path))

    def test_write_artifact_can_be_called_multiple_times(self, tmp_path):
        """Multiple write_artifact calls produce distinct files."""
        store = FileEvidenceStore(base_dir=tmp_path)
        ref1 = store.write_artifact("file1.bin", b"aaa")
        ref2 = store.write_artifact("file2.bin", b"bbb")
        assert ref1 != ref2
        assert Path(ref1).read_bytes() == b"aaa"
        assert Path(ref2).read_bytes() == b"bbb"
