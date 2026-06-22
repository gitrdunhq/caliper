"""Deterministic guards for EvidenceStore parent dir creation — Issue #242 / Parent #208.

Bug: FileEvidenceStore.store() creates the run-key directory (dest_dir) but does
not ensure the artifact's parent directory exists when artifact_name contains a
subdirectory (e.g. "requests/decision.json"). The atomic rename then fails with
FileNotFoundError because dest_dir/requests/ was never created.

These are xfail until store() calls final_path.parent.mkdir(parents=True,
exist_ok=True) before the rename. See issues #208 and #242.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #208 — "
        "FileEvidenceStore.store() does not mkdir(final_path.parent) when "
        "artifact_name contains a subdirectory; fix the store() method"
    ),
    strict=False,
)

from caliper.data.evidence import EvidenceStore


class TestEvidenceStoreParentDirCreation:
    """EvidenceStore.store() must succeed for nested artifact_name paths."""

    def test_store_with_nested_artifact_name_returns_nonempty_path(self) -> None:
        """store() must return the artifact path when artifact_name contains a slash.

        pipeline.py stores "requests/decision.json" as the artifact_name. The
        bug: dest_dir = root / key is mkdir'd, but dest_dir / "requests" is not
        — so os.rename() fails (caught internally) and store() returns "".
        Fix: call final_path.parent.mkdir(parents=True, exist_ok=True) before rename.
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(root_path=tmp)
            result = store.store(
                key="abc123",
                artifact_name="requests/decision.json",
                content=b'{"verdict": "approve"}',
            )
            assert result != "", (
                "EvidenceStore.store() returned '' for a nested artifact_name. "
                "The atomic rename failed because dest_dir/requests/ was not created. "
                "Fix: call final_path.parent.mkdir(parents=True, exist_ok=True). "
                "See issue #208."
            )

    def test_stored_nested_artifact_is_readable(self) -> None:
        """Content written to a nested artifact_name must be retrievable."""
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(root_path=tmp)
            store.store(
                key="abc123",
                artifact_name="requests/decision.json",
                content=b'{"verdict": "approve"}',
            )
            artifact = Path(tmp) / "abc123" / "requests" / "decision.json"
            assert artifact.exists(), (
                f"Expected artifact at {artifact} but it was not created. "
                "EvidenceStore.store() did not mkdir the parent directory "
                "before the atomic rename. See issue #208."
            )
            assert artifact.read_bytes() == b'{"verdict": "approve"}'

    def test_store_file_with_nested_artifact_name_returns_nonempty_path(self) -> None:
        """store_file() must return the artifact path when artifact_name contains a slash."""
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(root_path=tmp)
            src = Path(tmp) / "memo.md"
            src.write_text("# memo")
            result = store.store_file(
                key="abc123",
                artifact_name="requests/memo.md",
                source_path=src,
            )
            assert result != "", (
                "EvidenceStore.store_file() returned '' for a nested artifact_name. "
                "The parent directory requests/ was not created before the atomic rename. "
                "See issue #208."
            )
