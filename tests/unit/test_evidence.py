"""Tests for caliper.data.evidence — evidence storage service."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest


def _random_request_id() -> str:
    return "test-request-abc123"


class TestEvidenceStore:
    """Tests for the EvidenceStore class."""

    def test_store_creates_directory_structure(self, tmp_path: Path) -> None:
        """store() should create <root>/<request_id>/ directory."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        result = store.store(rid, "report.json", b'{"ok": true}')

        expected_dir = tmp_path / str(rid)
        assert expected_dir.is_dir()
        assert result == str(expected_dir / "report.json")

    def test_store_writes_correct_content(self, tmp_path: Path) -> None:
        """store() should write the exact content to the artifact file."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()
        content = b"binary evidence data"

        result = store.store(rid, "artifact.bin", content)

        assert Path(result).read_bytes() == content

    def test_store_handles_string_content(self, tmp_path: Path) -> None:
        """store() should handle str content, not just bytes."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()
        content = "text evidence"

        result = store.store(rid, "notes.txt", content)

        assert Path(result).read_text() == content

    def test_store_atomic_write_uses_temp_then_rename(self, tmp_path: Path) -> None:
        """store() should write to a temp file then rename (atomic write)."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        with patch("os.rename", wraps=os.rename) as mock_rename:
            store.store(rid, "data.json", b"content")
            mock_rename.assert_called_once()
            # The first arg is the temp path, second is the final path
            final_path = mock_rename.call_args[0][1]
            assert final_path.endswith("data.json")

    def test_store_file_copies_correctly(self, tmp_path: Path) -> None:
        """store_file() should copy the source file to the evidence directory."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        # Create a source file
        source = tmp_path / "source_report.txt"
        source.write_text("scan output here")

        result = store.store_file(rid, "report.txt", source)

        assert Path(result).read_text() == "scan output here"
        # Source file should still exist
        assert source.exists()

    def test_store_file_atomic_write(self, tmp_path: Path) -> None:
        """store_file() should use temp + rename for atomic writes."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        source = tmp_path / "source.bin"
        source.write_bytes(b"binary data")

        with patch("os.rename", wraps=os.rename) as mock_rename:
            store.store_file(rid, "copy.bin", source)
            mock_rename.assert_called_once()

    def test_get_path_returns_expected_path(self, tmp_path: Path) -> None:
        """get_path() should return the expected path without checking existence."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        result = store.get_path(rid, "report.json")

        expected = str(tmp_path / str(rid) / "report.json")
        assert result == expected

    def test_get_path_does_not_require_existence(self, tmp_path: Path) -> None:
        """get_path() should return a path even if the file does not exist."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        result = store.get_path(rid, "nonexistent.json")

        # Should return a path string, not empty
        assert len(result) > 0
        assert not Path(result).exists()

    def test_list_artifacts_returns_stored_files(self, tmp_path: Path) -> None:
        """list_artifacts() should return filenames of stored artifacts."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        store.store(rid, "report.json", b"data1")
        store.store(rid, "scan.txt", b"data2")
        store.store(rid, "sbom.xml", b"data3")

        artifacts = store.list_artifacts(rid)

        assert sorted(artifacts) == ["report.json", "sbom.xml", "scan.txt"]

    def test_list_artifacts_empty_for_unknown_request(self, tmp_path: Path) -> None:
        """list_artifacts() should return empty list for nonexistent request."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))

        result = store.list_artifacts("test-request-abc123")

        assert result == []

    def test_store_failure_logs_and_returns_empty_string(self, tmp_path: Path) -> None:
        """On storage failure, store() should log error and return empty string."""
        if os.getuid() == 0:
            pytest.skip("root bypasses chmod — cannot test permission failure")
        from caliper.data.evidence import EvidenceStore

        # Use a path that will fail (read-only directory)
        read_only_dir = tmp_path / "readonly"
        read_only_dir.mkdir()
        os.chmod(str(read_only_dir), 0o444)

        store = EvidenceStore(root_path=str(read_only_dir))
        rid = _random_request_id()

        result = store.store(rid, "fail.txt", b"data")

        assert result == ""

        # Cleanup: restore permissions so pytest can clean up
        os.chmod(str(read_only_dir), 0o755)

    def test_store_file_failure_logs_and_returns_empty_string(self, tmp_path: Path) -> None:
        """On storage failure, store_file() should log error and return empty string."""
        if os.getuid() == 0:
            pytest.skip("root bypasses chmod — cannot test permission failure")
        from caliper.data.evidence import EvidenceStore

        read_only_dir = tmp_path / "readonly2"
        read_only_dir.mkdir()

        source = tmp_path / "source.txt"
        source.write_text("data")

        os.chmod(str(read_only_dir), 0o444)

        store = EvidenceStore(root_path=str(read_only_dir))
        rid = _random_request_id()

        result = store.store_file(rid, "fail.txt", source)

        assert result == ""

        os.chmod(str(read_only_dir), 0o755)

    def test_directory_auto_creation(self, tmp_path: Path) -> None:
        """store() should create nested directories as needed."""
        from caliper.data.evidence import EvidenceStore

        deep_root = tmp_path / "a" / "b" / "c"
        store = EvidenceStore(root_path=str(deep_root))
        rid = _random_request_id()

        result = store.store(rid, "artifact.txt", b"data")

        assert Path(result).exists()
        assert Path(result).read_bytes() == b"data"

    # F-022 path traversal tests

    def test_dotdot_artifact_name_is_rejected(self, tmp_path: Path) -> None:
        """F-022: store() must block artifact names that escape the dest_dir."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        result = store.store(rid, "../../etc/passwd", b"bad")
        assert result == ""

    def test_single_dotdot_is_rejected(self, tmp_path: Path) -> None:
        """F-022: A single '../sibling' escape is also blocked."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        result = store.store(rid, "../sibling.txt", b"bad")
        assert result == ""

    def test_traversal_does_not_write_outside_dest_dir(self, tmp_path: Path) -> None:
        """F-022: A blocked traversal attempt must not create any file outside dest_dir."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()
        outside_file = tmp_path / "evil.txt"

        store.store(rid, "../evil.txt", b"owned")

        assert not outside_file.exists()

    def test_normal_artifact_name_is_still_accepted(self, tmp_path: Path) -> None:
        """F-022: A legitimate filename must not be blocked by the traversal check."""
        from caliper.data.evidence import EvidenceStore

        store = EvidenceStore(root_path=str(tmp_path))
        rid = _random_request_id()

        result = store.store(rid, "scan-report.json", b'{"ok": true}')
        assert result != ""
        assert Path(result).exists()


class TestEvidenceSymlinkTraversal:
    """F-022: Symlink-based path traversal via the key directory.

    The check in store()/store_file() currently validates:
        resolved.is_relative_to(dest_dir.resolve())

    When the key directory is a symlink pointing outside the evidence root,
    dest_dir.resolve() follows the symlink to the external directory.  The
    resolved artifact path IS then relative to that external directory, so the
    guard silently passes and the write lands outside the evidence root.

    The fix: check against self._root.resolve() — the evidence root — not the
    (potentially symlinked) dest_dir.
    """

    def test_symlink_key_dir_does_not_write_outside_root(self, tmp_path: Path) -> None:
        """store(): a symlink key-dir pointing outside root must be blocked."""
        from caliper.data.evidence import EvidenceStore

        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        external_dir = tmp_path / "external"
        external_dir.mkdir()

        # Attacker-controlled symlink inside the evidence root → escapes to external_dir
        (evidence_root / "attacker_key").symlink_to(external_dir)

        store = EvidenceStore(root_path=str(evidence_root))

        result = store.store("attacker_key", "evil.txt", b"owned")

        assert result == "", "Symlink key escaping evidence root must be blocked"
        assert not (
            external_dir / "evil.txt"
        ).exists(), "File must not be written outside evidence root"

    def test_store_file_symlink_key_dir_does_not_write_outside_root(self, tmp_path: Path) -> None:
        """store_file(): a symlink key-dir pointing outside root must be blocked."""
        from caliper.data.evidence import EvidenceStore

        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        external_dir = tmp_path / "external"
        external_dir.mkdir()

        source = tmp_path / "source.txt"
        source.write_text("sensitive data")

        (evidence_root / "attacker_key").symlink_to(external_dir)

        store = EvidenceStore(root_path=str(evidence_root))

        result = store.store_file("attacker_key", "evil.txt", source)

        assert result == "", "Symlink key escaping evidence root must be blocked"
        assert not (
            external_dir / "evil.txt"
        ).exists(), "File must not be copied outside evidence root"
