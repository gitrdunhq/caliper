"""Evidence storage service -- atomic file-based artifact persistence.
# tested-by: tests/unit/test_evidence.py

Stores scan outputs, SBOMs, and other evidence artifacts organized by
evidence key (commit SHA or request ID). All writes are atomic
(temp file + os.rename) to prevent half-written files on crash.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class EvidenceStore:
    """File-based evidence storage organized by evidence key.

    Directory layout::

        <root_path>/
            <evidence_key>/          # commit SHA, request UUID, etc.
                report.json
                sbom.xml
                scan-output.txt

    All writes are atomic: content is written to a temp file in the same
    directory, then renamed into place. On any failure the error is logged
    and an empty string is returned -- storage failures never raise.
    """

    def __init__(self, root_path: str) -> None:
        self._root = Path(root_path)

    def _evidence_dir(self, key: str) -> Path:
        return self._root / key

    def store(self, key: str, artifact_name: str, content: bytes | str) -> str:
        """Write content to ``<root>/<key>/<artifact_name>`` atomically.

        Returns the full path on success, empty string on failure.
        """
        try:
            dest_dir = self._evidence_dir(key)
            dest_dir.mkdir(parents=True, exist_ok=True)

            resolved_dest = dest_dir.resolve()
            resolved_root = self._root.resolve()
            # Guard 1: the key directory must not escape the evidence root via a symlink.
            if not resolved_dest.is_relative_to(resolved_root):
                logger.error(
                    "path_traversal_attempt",
                    evidence_key=key,
                    artifact_name=artifact_name,
                )
                return ""
            # Guard 2: the artifact path must stay within the key directory.
            resolved = (dest_dir / artifact_name).resolve()
            if not resolved.is_relative_to(resolved_dest):
                logger.error(
                    "path_traversal_attempt",
                    evidence_key=key,
                    artifact_name=artifact_name,
                )
                return ""

            final_path = dest_dir / artifact_name
            final_path.parent.mkdir(parents=True, exist_ok=True)

            is_bytes = isinstance(content, bytes)
            mode = "wb" if is_bytes else "w"

            fd, tmp_path = tempfile.mkstemp(dir=str(dest_dir))
            try:
                with os.fdopen(fd, mode) as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                os.rename(tmp_path, str(final_path))
            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

            logger.info(
                "evidence_stored",
                evidence_key=key,
                artifact=artifact_name,
                path=str(final_path),
            )
            return str(final_path)
        except Exception:
            logger.error(
                "evidence_store_failed",
                evidence_key=key,
                artifact=artifact_name,
                exc_info=True,
            )
            return ""

    def store_file(self, key: str, artifact_name: str, source_path: Path) -> str:
        """Copy a file from source_path into the evidence directory atomically.

        Returns the full path on success, empty string on failure.
        """
        try:
            dest_dir = self._evidence_dir(key)
            dest_dir.mkdir(parents=True, exist_ok=True)

            resolved_dest = dest_dir.resolve()
            resolved_root = self._root.resolve()
            # Guard 1: the key directory must not escape the evidence root via a symlink.
            if not resolved_dest.is_relative_to(resolved_root):
                logger.error(
                    "path_traversal_attempt",
                    evidence_key=key,
                    artifact_name=artifact_name,
                )
                return ""
            # Guard 2: the artifact path must stay within the key directory.
            resolved = (dest_dir / artifact_name).resolve()
            if not resolved.is_relative_to(resolved_dest):
                logger.error(
                    "path_traversal_attempt",
                    evidence_key=key,
                    artifact_name=artifact_name,
                )
                return ""

            final_path = dest_dir / artifact_name
            final_path.parent.mkdir(parents=True, exist_ok=True)

            fd, tmp_path = tempfile.mkstemp(dir=str(dest_dir))
            os.close(fd)
            try:
                shutil.copy2(str(source_path), tmp_path)
                os.rename(tmp_path, str(final_path))
            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

            logger.info(
                "evidence_file_stored",
                evidence_key=key,
                artifact=artifact_name,
                source=str(source_path),
                path=str(final_path),
            )
            return str(final_path)
        except Exception:
            logger.error(
                "evidence_store_file_failed",
                evidence_key=key,
                artifact=artifact_name,
                source=str(source_path),
                exc_info=True,
            )
            return ""

    def get_path(self, key: str, artifact_name: str) -> str:
        """Return the expected path for an artifact (does not check existence)."""
        return str(self._evidence_dir(key) / artifact_name)

    def list_artifacts(self, key: str) -> list[str]:
        """List all artifact filenames for an evidence key.

        Returns an empty list if the directory does not exist or on any error.
        """
        try:
            dest_dir = self._evidence_dir(key)
            if not dest_dir.is_dir():
                return []
            return sorted(f.name for f in dest_dir.iterdir() if f.is_file())
        except Exception:
            logger.error(
                "evidence_list_failed",
                evidence_key=key,
                exc_info=True,
            )
            return []
