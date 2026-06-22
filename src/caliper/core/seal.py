"""Evidence seal — blockchain-style integrity chain for audit artifacts.
# tested-by: tests/unit/test_seal.py

Each pipeline run produces a seal: a SHA-256 manifest of every evidence
artifact, chained to the previous seal. Tampering with any file, adding
a file, removing a file, or reordering files breaks the chain.

Seal layout:
    evidence/<sha>/<ts>/seal.json
    {
        "version": "1.0",
        "run_id": "<sha>/<ts>",
        "commit_sha": "abc123...",
        "timestamp": "2026-04-23T14:30:00Z",
        "previous_seal_hash": "sha256:...",   # empty string for first run
        "artifacts": [
            {"path": "insecure-lib/decision.json", "sha256": "..."},
            {"path": "insecure-lib/memo.md", "sha256": "..."},
        ],
        "manifest_hash": "sha256:...",         # hash of sorted artifact hashes
        "seal_hash": "sha256:..."              # hash of (manifest_hash + previous_seal_hash)
    }

To verify: recompute all file hashes, rebuild manifest_hash, rebuild
seal_hash with the previous_seal_hash. If seal_hash matches, the evidence
is intact. Walk the chain backwards to verify the entire history.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

SEAL_FILENAME = "seal.json"
SEAL_VERSION = "1.0"


def hash_file(path: Path) -> str:
    """SHA-256 hash of a file's contents. Returns hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_seal(
    evidence_dir: Path,
    run_id: str,
    commit_sha: str | None,
    previous_seal_hash: str = "",
) -> dict:
    """Create a seal for all artifacts in an evidence directory.

    Walks the directory, hashes every file (excluding seal.json itself),
    builds a deterministic manifest hash, and chains it to the previous seal.
    """
    artifacts: list[dict] = []

    if not evidence_dir.exists():
        logger.warning("seal_no_evidence_dir", path=str(evidence_dir))
        return {}

    for fpath in sorted(evidence_dir.rglob("*")):
        if not fpath.is_file():
            continue
        if fpath.name == SEAL_FILENAME:
            continue

        rel_path = str(fpath.relative_to(evidence_dir))
        file_hash = hash_file(fpath)
        artifacts.append({"path": rel_path, "sha256": file_hash})

    manifest_content = "\n".join(f"{a['sha256']}  {a['path']}" for a in artifacts)
    manifest_hash = hash_bytes(manifest_content.encode())

    seal_input = f"{manifest_hash}:{previous_seal_hash}"
    seal_hash = hash_bytes(seal_input.encode())

    seal = {
        "version": SEAL_VERSION,
        "run_id": run_id,
        "commit_sha": commit_sha or "unknown",
        "timestamp": datetime.now(UTC).isoformat(),
        "previous_seal_hash": previous_seal_hash,
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "manifest_hash": f"sha256:{manifest_hash}",
        "seal_hash": f"sha256:{seal_hash}",
    }

    seal_path = evidence_dir / SEAL_FILENAME
    seal_path.write_text(json.dumps(seal, indent=2))

    logger.info(
        "evidence_sealed",
        run_id=run_id,
        artifacts=len(artifacts),
        seal_hash=seal_hash[:16],
    )

    return seal


def verify_seal(evidence_dir: Path) -> dict:
    """Verify the integrity of a sealed evidence directory.

    Returns:
        {"valid": True/False, "errors": [...], "seal": <seal dict>}
    """
    seal_path = evidence_dir / SEAL_FILENAME
    if not seal_path.exists():
        return {"valid": False, "errors": ["seal.json not found"], "seal": None}

    try:
        seal = json.loads(seal_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return {"valid": False, "errors": [f"seal.json unreadable: {e}"], "seal": None}

    errors: list[str] = []

    evidence_dir_resolved = evidence_dir.resolve()

    for artifact in seal.get("artifacts", []):
        fpath = (evidence_dir / artifact["path"]).resolve()

        # Reject any path that resolves outside evidence_dir (path traversal guard).
        try:
            fpath.relative_to(evidence_dir_resolved)
        except ValueError:
            errors.append(f"path traversal attempt: {artifact['path']}")
            continue

        if not fpath.exists():
            errors.append(f"missing: {artifact['path']}")
            continue
        actual_hash = hash_file(fpath)
        if actual_hash != artifact["sha256"]:
            errors.append(
                f"tampered: {artifact['path']} "
                f"(expected {artifact['sha256'][:16]}..., got {actual_hash[:16]}...)"
            )

    manifest_content = "\n".join(f"{a['sha256']}  {a['path']}" for a in seal.get("artifacts", []))
    expected_manifest = hash_bytes(manifest_content.encode())
    actual_manifest = seal.get("manifest_hash", "").replace("sha256:", "")
    if expected_manifest != actual_manifest:
        errors.append("manifest_hash mismatch — artifact list was modified")

    seal_input = f"{actual_manifest}:{seal.get('previous_seal_hash', '')}"
    expected_seal = hash_bytes(seal_input.encode())
    actual_seal = seal.get("seal_hash", "").replace("sha256:", "")
    if expected_seal != actual_seal:
        errors.append("seal_hash mismatch — seal was modified")

    valid = len(errors) == 0

    if valid:
        logger.info(
            "seal_verified", run_id=seal.get("run_id"), artifacts=len(seal.get("artifacts", []))
        )
    else:
        logger.warning("seal_verification_failed", errors=errors)

    return {"valid": valid, "errors": errors, "seal": seal}


def find_previous_seal_hash(evidence_root: Path, current_run_id: str) -> str:
    """Find the most recent seal.json before this run and return its seal_hash.

    Walks the evidence directory for seal.json files, sorted by timestamp,
    and returns the seal_hash of the most recent one that isn't the current run.
    Returns empty string if no previous seal exists (first run).
    """
    seals: list[tuple[str, str]] = []

    for seal_path in evidence_root.rglob(SEAL_FILENAME):
        try:
            seal = json.loads(seal_path.read_text())
            if seal.get("run_id") == current_run_id:
                continue
            ts = seal.get("timestamp", "")
            sh = seal.get("seal_hash", "")
            if ts and sh:
                seals.append((ts, sh))
        except (json.JSONDecodeError, OSError):
            continue

    if not seals:
        return ""

    seals.sort(key=lambda x: x[0], reverse=True)
    return seals[0][1]
