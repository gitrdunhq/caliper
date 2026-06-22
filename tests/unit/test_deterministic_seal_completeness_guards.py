"""Deterministic behavioral guard for seal completeness gap (Issue #264).

Bug: verify_seal() validates only the files listed in the seal manifest.  Any file
     added to the evidence directory after sealing is silently ignored, meaning
     an attacker can inject arbitrary artifacts into the evidence bundle without
     breaking verification.

Evidence:
  - seal.py lines 134-152: verify_seal() iterates over seal["artifacts"], checks
    those files, and then checks manifest_hash and seal_hash — but never compares
    the set of files currently on disk against the sealed artifact list.
  - tests/unit/test_seal.py line ~120 explicitly asserts that adding a new file
    does not break verification (documenting the current (buggy) behavior).

Fix: After checking all sealed artifacts, walk evidence_dir for any files not in
     the sealed artifact set (excluding seal.json itself).  If extra files are
     found, append an error per unexpected file so that valid is False.

Parent bug: #230 / Epic: #146.
Status: xfail — verify_seal() currently ignores extra files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #264 — detect extra files in verify_seal, then green",
    strict=False,
)


def _setup_sealed_dir(base: Path) -> Path:
    """Create a minimal sealed evidence directory with one legitimate file."""
    from caliper.core.seal import create_seal

    evidence_dir = base / "evidence"
    evidence_dir.mkdir()

    # Write the one legitimate pre-seal artifact
    (evidence_dir / "decision.json").write_text('{"verdict": "approved"}')

    create_seal(evidence_dir, run_id="test-run-264", commit_sha="abc123def456")
    return evidence_dir


def test_264_verify_seal_fails_when_file_added_after_sealing(tmp_path: Path) -> None:
    """verify_seal() must return valid=False when an extra file is added after sealing.

    The seal captures a snapshot of the evidence directory.  Any file added after
    that snapshot was taken is an unexpected artifact — it could be an injected
    report, tampered log, or exfiltrated data — and must break verification.

    When the bug is fixed, the injected file will be detected and verify_seal()
    will return {"valid": False, ...}.
    """
    from caliper.core.seal import verify_seal

    evidence_dir = _setup_sealed_dir(tmp_path)

    # Sanity: the seal is valid before injection
    pre_result = verify_seal(evidence_dir)
    assert pre_result["valid"] is True, (
        "Setup failed: seal should be valid immediately after creation; "
        "check that create_seal() is working correctly"
    )

    # Inject a new file after sealing
    (evidence_dir / "injected.json").write_text('{"malicious": true}')

    # The seal must now be invalid
    post_result = verify_seal(evidence_dir)
    assert post_result["valid"] is False, (
        "BUG #264: verify_seal() returned valid=True even after an extra file "
        "(injected.json) was added to the evidence directory after sealing. "
        "The verification step must enumerate all files on disk and fail when "
        "any file is present that was not included in the sealed manifest."
    )


def test_264_verify_seal_reports_injected_file_in_errors(tmp_path: Path) -> None:
    """verify_seal() must report the unexpected file name in the errors list.

    An operator who receives valid=False needs to know which files are
    problematic.  The errors list must include a reference to the injected file
    so that the incident can be investigated.
    """
    from caliper.core.seal import verify_seal

    evidence_dir = _setup_sealed_dir(tmp_path)
    (evidence_dir / "injected.json").write_text('{"malicious": true}')

    result = verify_seal(evidence_dir)
    errors = result.get("errors", [])

    # When the bug is fixed, valid will be False and errors will name the file.
    # The assertion on valid=False is the primary detector; this is the secondary.
    assert any("injected.json" in e for e in errors), (
        "BUG #264: verify_seal() errors list does not mention the injected file. "
        "When extra files are detected, each unexpected file path should appear "
        "in the errors list to support incident investigation."
    )
