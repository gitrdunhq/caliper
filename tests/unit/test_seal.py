"""Tests for caliper.core.seal — evidence integrity chain.

# tested-by: tests/unit/test_seal.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from caliper.core.seal import (
    SEAL_FILENAME,
    create_seal,
    find_previous_seal_hash,
    verify_seal,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_two_files(directory: Path) -> None:
    """Write two canonical test artifacts into directory."""
    (directory / "file_a.txt").write_text("content A")
    (directory / "file_b.txt").write_text("content B")


def _make_seal_json(
    run_id: str,
    timestamp: str,
    seal_hash: str,
    previous_seal_hash: str = "",
) -> dict:
    """Build a minimal seal.json dict for test fixtures."""
    return {
        "version": "1.0",
        "run_id": run_id,
        "commit_sha": "abc",
        "timestamp": timestamp,
        "previous_seal_hash": previous_seal_hash,
        "artifacts": [],
        "artifact_count": 0,
        "manifest_hash": "sha256:aaabbbccc",
        "seal_hash": seal_hash,
    }


# ---------------------------------------------------------------------------
# Example-based: create + verify round-trip
# ---------------------------------------------------------------------------


class TestCreateSealRoundTrip:
    def test_create_seal_produces_valid_seal(self, tmp_path: Path) -> None:
        """Write 2 files, create seal, verify should pass with no errors."""
        _write_two_files(tmp_path)

        seal = create_seal(tmp_path, "run/001", "abc123", "")

        result = verify_seal(tmp_path)
        assert result["valid"] is True
        assert result["errors"] == []
        assert len(seal["artifacts"]) == 2

    def test_empty_directory_produces_empty_seal(self, tmp_path: Path) -> None:
        """No files → seal with empty artifacts list, still verifies clean."""
        seal = create_seal(tmp_path, "run/001", "abc123", "")

        assert seal["artifacts"] == []
        assert seal["artifact_count"] == 0

        result = verify_seal(tmp_path)
        assert result["valid"] is True

    def test_seal_json_excluded_from_artifacts(self, tmp_path: Path) -> None:
        """seal.json itself must not appear in the artifact list."""
        (tmp_path / "real_artifact.txt").write_text("data")

        seal = create_seal(tmp_path, "run/001", "abc123", "")

        artifact_paths = [a["path"] for a in seal["artifacts"]]
        assert SEAL_FILENAME not in artifact_paths
        # Only the one real artifact should be listed
        assert len(seal["artifacts"]) == 1


# ---------------------------------------------------------------------------
# Example-based: tamper detection
# ---------------------------------------------------------------------------


class TestVerifyTamperDetection:
    def test_verify_detects_tampered_file(self, tmp_path: Path) -> None:
        """Modify an artifact after sealing → verify reports tampered."""
        (tmp_path / "file_a.txt").write_text("original content")
        create_seal(tmp_path, "run/001", "abc123", "")

        (tmp_path / "file_a.txt").write_text("TAMPERED content")

        result = verify_seal(tmp_path)
        assert result["valid"] is False
        assert any("tampered" in e for e in result["errors"])

    def test_verify_detects_missing_file(self, tmp_path: Path) -> None:
        """Delete an artifact after sealing → verify reports missing."""
        _write_two_files(tmp_path)
        create_seal(tmp_path, "run/001", "abc123", "")

        (tmp_path / "file_a.txt").unlink()

        result = verify_seal(tmp_path)
        assert result["valid"] is False
        assert any("missing" in e for e in result["errors"])

    def test_verify_detects_added_file(self, tmp_path: Path) -> None:
        """Adding a file after sealing must break the seal (#230).

        The seal manifest is a complete inventory of the evidence directory
        at sealing time — a file added afterward is unaccounted-for evidence
        and verify_seal must flag it, not silently pass.
        """
        (tmp_path / "file_a.txt").write_text("original content")
        create_seal(tmp_path, "run/001", "abc123", "")

        # Add a new file after sealing
        (tmp_path / "file_b.txt").write_text("new file — not sealed")

        result = verify_seal(tmp_path)
        assert result["valid"] is False
        assert any("unexpected" in e and "file_b.txt" in e for e in result["errors"])

    def test_verify_catches_modified_manifest(self, tmp_path: Path) -> None:
        """Manually editing manifest_hash in seal.json → verify fails."""
        (tmp_path / "artifact.txt").write_text("hello world")
        create_seal(tmp_path, "run/001", "abc123", "")

        seal_path = tmp_path / SEAL_FILENAME
        seal_data = json.loads(seal_path.read_text())
        seal_data["manifest_hash"] = "sha256:fakehashfakehash00000000"
        seal_path.write_text(json.dumps(seal_data))

        result = verify_seal(tmp_path)
        assert result["valid"] is False
        assert any("manifest_hash" in e for e in result["errors"])

    def test_verify_catches_modified_seal_hash(self, tmp_path: Path) -> None:
        """Manually editing seal_hash in seal.json → verify fails."""
        (tmp_path / "artifact.txt").write_text("hello world")
        create_seal(tmp_path, "run/001", "abc123", "")

        seal_path = tmp_path / SEAL_FILENAME
        seal_data = json.loads(seal_path.read_text())
        seal_data["seal_hash"] = "sha256:fakesealhashfake000000000"
        seal_path.write_text(json.dumps(seal_data))

        result = verify_seal(tmp_path)
        assert result["valid"] is False
        assert any("seal_hash" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# Example-based: chain / previous hash
# ---------------------------------------------------------------------------


class TestSealChaining:
    def test_seal_chains_to_previous(self, tmp_path: Path) -> None:
        """Seal created with a previous_seal_hash stores it and differs from unchained seal."""
        (tmp_path / "file_a.txt").write_text("content A")
        previous_hash = "sha256:deadbeefdeadbeef0000000000000000"

        # Seal with chain
        seal_with_chain = create_seal(tmp_path, "run/001", "abc123", previous_hash)
        assert seal_with_chain["previous_seal_hash"] == previous_hash

        # Seal without chain (overwrites seal.json — both exclude it from artifacts)
        seal_no_chain = create_seal(tmp_path, "run/001", "abc123", "")

        assert seal_with_chain["seal_hash"] != seal_no_chain["seal_hash"]

    def test_different_previous_hash_produces_different_seal(self, tmp_path: Path) -> None:
        """Same artifacts, different previous_seal_hash → different seal_hash."""
        dir_a = tmp_path / "run_a"
        dir_b = tmp_path / "run_b"
        dir_a.mkdir()
        dir_b.mkdir()

        (dir_a / "artifact.txt").write_bytes(b"identical content")
        (dir_b / "artifact.txt").write_bytes(b"identical content")

        seal_a = create_seal(dir_a, "run/001", "abc123", "sha256:hash_one")
        seal_b = create_seal(dir_b, "run/001", "abc123", "sha256:hash_two")

        assert seal_a["seal_hash"] != seal_b["seal_hash"]


# ---------------------------------------------------------------------------
# Example-based: find_previous_seal_hash
# ---------------------------------------------------------------------------


class TestFindPreviousSealHash:
    def test_find_previous_seal_hash_empty_on_first_run(self, tmp_path: Path) -> None:
        """No prior seals → returns empty string (first run)."""
        result = find_previous_seal_hash(tmp_path, "run1")
        assert result == ""

    def test_find_previous_seal_hash_returns_most_recent(self, tmp_path: Path) -> None:
        """Two sealed runs → returns the hash of the more recent one."""
        run1_dir = tmp_path / "run1"
        run2_dir = tmp_path / "run2"
        run1_dir.mkdir()
        run2_dir.mkdir()

        # run1 has an earlier timestamp
        (run1_dir / SEAL_FILENAME).write_text(
            json.dumps(
                _make_seal_json(
                    run_id="run1",
                    timestamp="2026-04-23T10:00:00+00:00",
                    seal_hash="sha256:seal_hash_one",
                )
            )
        )
        # run2 has a later timestamp
        (run2_dir / SEAL_FILENAME).write_text(
            json.dumps(
                _make_seal_json(
                    run_id="run2",
                    timestamp="2026-04-23T12:00:00+00:00",
                    seal_hash="sha256:seal_hash_two",
                    previous_seal_hash="sha256:seal_hash_one",
                )
            )
        )

        result = find_previous_seal_hash(tmp_path, "run3")
        assert result == "sha256:seal_hash_two"

    def test_find_previous_seal_hash_skips_current_run(self, tmp_path: Path) -> None:
        """The current run_id is excluded from the search."""
        run_dir = tmp_path / "current_run"
        run_dir.mkdir()

        (run_dir / SEAL_FILENAME).write_text(
            json.dumps(
                _make_seal_json(
                    run_id="current_run_id",
                    timestamp="2026-04-23T10:00:00+00:00",
                    seal_hash="sha256:current_seal_hash",
                )
            )
        )

        result = find_previous_seal_hash(tmp_path, "current_run_id")
        assert result == ""


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------

_FILES_STRATEGY = st.dictionaries(
    st.from_regex(r"[a-z][a-z0-9]{1,8}\.bin", fullmatch=True),
    st.binary(min_size=1, max_size=100),
    min_size=1,
    max_size=5,
)

_HASH_STRATEGY = st.text(
    alphabet="abcdef0123456789",
    min_size=0,
    max_size=64,
)


@given(files=_FILES_STRATEGY, previous_hash=_HASH_STRATEGY)
@settings(max_examples=200)
def test_seal_is_deterministic(files: dict[str, bytes], previous_hash: str) -> None:
    """Same directory content + same previous_seal_hash always produces the same seal_hash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        evidence_dir = Path(tmpdir)
        for name, content in files.items():
            (evidence_dir / name).write_bytes(content)

        seal1 = create_seal(evidence_dir, "run/001", "abc123", previous_hash)
        # Second call: seal.json is already present but excluded from artifacts.
        seal2 = create_seal(evidence_dir, "run/001", "abc123", previous_hash)

        assert seal1["seal_hash"] == seal2["seal_hash"]


@given(
    content=st.binary(min_size=2, max_size=200),
    byte_idx=st.integers(min_value=0, max_value=199),
    delta=st.integers(min_value=1, max_value=255),
)
@settings(max_examples=200)
def test_any_single_byte_change_breaks_seal(
    content: bytes,
    byte_idx: int,
    delta: int,
) -> None:
    """Flipping any single byte in a sealed artifact causes verify_seal to report invalid."""
    with tempfile.TemporaryDirectory() as tmpdir:
        evidence_dir = Path(tmpdir)
        fname = "artifact.bin"
        (evidence_dir / fname).write_bytes(content)

        create_seal(evidence_dir, "run/001", "sha123", "")

        # Flip one byte — delta in [1,255] guarantees the value changes
        idx = byte_idx % len(content)
        modified = bytearray(content)
        modified[idx] = (modified[idx] + delta) % 256
        (evidence_dir / fname).write_bytes(bytes(modified))

        result = verify_seal(evidence_dir)
        assert not result["valid"]


# ---------------------------------------------------------------------------
# Security: path traversal in artifact["path"]
# ---------------------------------------------------------------------------


class TestPathTraversalRejected:
    def test_relative_traversal_rejected(self, tmp_path: Path) -> None:
        """'../secret.txt' in artifact path must be caught as path traversal, not followed."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()

        # Place a real file outside evidence_dir that the traversal would reach
        external = tmp_path / "secret.txt"
        external.write_text("top secret")

        seal = {
            "version": "1.0",
            "run_id": "test/run",
            "commit_sha": "abc123",
            "timestamp": "2026-04-23T14:30:00Z",
            "previous_seal_hash": "",
            "artifacts": [{"path": "../secret.txt", "sha256": "abc"}],
            "manifest_hash": "sha256:abc",
            "seal_hash": "sha256:def",
        }
        (evidence_dir / SEAL_FILENAME).write_text(json.dumps(seal))

        result = verify_seal(evidence_dir)

        assert result["valid"] is False
        assert any("path traversal" in e.lower() for e in result["errors"])

    def test_absolute_path_in_artifact_rejected(self, tmp_path: Path) -> None:
        """An absolute artifact path like '/etc/passwd' must be rejected as path traversal."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()

        seal = {
            "version": "1.0",
            "run_id": "test/run",
            "commit_sha": "abc123",
            "timestamp": "2026-04-23T14:30:00Z",
            "previous_seal_hash": "",
            "artifacts": [{"path": "/etc/passwd", "sha256": "abc"}],
            "manifest_hash": "sha256:abc",
            "seal_hash": "sha256:def",
        }
        (evidence_dir / SEAL_FILENAME).write_text(json.dumps(seal))

        result = verify_seal(evidence_dir)

        assert result["valid"] is False
        assert any("path traversal" in e.lower() for e in result["errors"])

    def test_legitimate_subdir_artifact_still_works(self, tmp_path: Path) -> None:
        """A normal relative artifact path within evidence_dir continues to work."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / "sub").mkdir()
        (evidence_dir / "sub" / "report.json").write_text('{"ok": true}')

        create_seal(evidence_dir, "run/001", "abc123", "")

        result = verify_seal(evidence_dir)
        assert result["valid"] is True


@given(
    content=st.binary(min_size=1, max_size=100),
    hash1=st.text(alphabet="abcdef0123456789", min_size=4, max_size=64),
    hash2=st.text(alphabet="abcdef0123456789", min_size=4, max_size=64),
)
@settings(max_examples=200)
def test_seal_hash_changes_with_previous_hash(
    content: bytes,
    hash1: str,
    hash2: str,
) -> None:
    """Different previous_seal_hash values must always produce different seal hashes."""
    assume(hash1 != hash2)

    with (
        tempfile.TemporaryDirectory() as dir1,
        tempfile.TemporaryDirectory() as dir2,
    ):
        evidence_dir1 = Path(dir1)
        evidence_dir2 = Path(dir2)
        (evidence_dir1 / "file.bin").write_bytes(content)
        (evidence_dir2 / "file.bin").write_bytes(content)

        seal1 = create_seal(evidence_dir1, "run/001", "sha1", hash1)
        seal2 = create_seal(evidence_dir2, "run/001", "sha1", hash2)

        assert seal1["seal_hash"] != seal2["seal_hash"]
