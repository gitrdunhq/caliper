"""Deterministic detector for SBOM evaluation audit trail (Issue #251).

# tested-by: tests/unit/test_deterministic_sbom_guards.py

This module detects missing Parquet append and evidence sealing in
evaluate_sbom() to ensure proper audit trail for SBOM-based evaluations.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _make_config(tmp_path: Path, **overrides: object):
    from caliper.core.config import CaliperSettings

    defaults: dict[str, object] = {
        "db_dsn": "postgresql://test:test@localhost/test",
        "evidence_path": str(tmp_path / "evidence"),
        "opa_policy_path": str(tmp_path / "policy.rego"),
        "enabled_scanners": [],
        "scanner_timeout": 13,
        "combined_scanner_timeout": 17,
        "opa_timeout": 19,
        "pipeline_timeout": 300,
        "pypi_timeout": 23,
    }
    defaults.update(overrides)
    return CaliperSettings(**defaults)


def _component(name: str, version: str, purl: str) -> dict[str, str]:
    return {"type": "library", "name": name, "version": version, "purl": purl}


def _sbom(*components: dict[str, str]) -> dict[str, object]:
    return {"bomFormat": "CycloneDX", "components": list(components)}


class _FakeDb:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.closed = False

    def connect(self) -> bool:
        return True

    def save_request(self, request: object) -> None:
        return None

    def save_scan_results(self, request_id: object, scan_results: list[object]) -> None:
        return None

    def save_policy_evaluation(self, request_id: object, policy_eval: object) -> None:
        return None

    def save_decision(self, request_id: object, decision: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeEvidence:
    def __init__(self, root_path: str) -> None:
        self.root = Path(root_path)

    def get_path(self, key: str, artifact_name: str) -> str:
        return str(self.root / key / artifact_name)

    def store(self, key: str, artifact_name: str, content: bytes | str) -> str:
        target = self.root / key / artifact_name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
        return str(target)


class _FakePyPIClient:
    def __init__(self, timeout: int = 10) -> None:
        pass

    def fetch_metadata(self, package_name: str, version: str | None = None) -> dict[str, object]:
        return {"available": False}


class _FakeOpaEvaluator:
    def __init__(self, policy_path: str, timeout: int = 10) -> None:
        pass

    def evaluate(self, findings: list[object], package_metadata: dict[str, object]):
        from caliper.core.models import DecisionVerdict, PolicyEvaluation

        return PolicyEvaluation(
            decision=DecisionVerdict.approve,
            triggered_rules=[],
            policy_bundle_version="fake",
        )


class _FakeOrchestrator:
    def __init__(self, scanners: list[object], combined_timeout: int) -> None:
        pass

    def run(self, repo_path: Path) -> list[object]:
        return []


def _patch_pipeline_runtime(
    monkeypatch: pytest.MonkeyPatch,
    append_calls: list[tuple[Path, list[object], str]] | None = None,
    seal_calls: list[tuple[Path, str, str | None]] | None = None,
) -> None:
    import caliper.core.pipeline as pipeline_mod

    def append_decisions(evidence_root: Path, decisions: list[object], run_id: str = "") -> Path:
        if append_calls is not None:
            append_calls.append((evidence_root, decisions, run_id))
        return evidence_root / "decisions.parquet"

    monkeypatch.setattr(pipeline_mod, "OpaEvaluator", _FakeOpaEvaluator)
    monkeypatch.setattr(pipeline_mod, "ScanOrchestrator", _FakeOrchestrator)
    monkeypatch.setattr(pipeline_mod, "find_previous_seal_hash", lambda root, run_id: "prev_hash")
    monkeypatch.setattr(
        pipeline_mod,
        "create_seal",
        lambda evidence_dir, run_id, commit_sha, previous_hash: (
            seal_calls.append((evidence_dir, run_id, previous_hash))
            if seal_calls is not None
            else None
        ),
    )
    monkeypatch.setattr(
        pipeline_mod,
        "_data_imports",
        lambda: {
            "DecisionRepository": _FakeDb,
            "NullRepository": _FakeDb,
            "RepositoryProtocol": object,
            "EvidenceStore": _FakeEvidence,
            "append_decisions": append_decisions,
            "PyPIClient": _FakePyPIClient,
            "OsvScanner": type("_DefaultScanner", (), {"name": "fake"}),
            "ScanCodeScanner": type("_DefaultScanner", (), {"name": "fake"}),
            "SyftScanner": type("_DefaultScanner", (), {"name": "fake"}),
            "TrivyScanner": type("_DefaultScanner", (), {"name": "fake"}),
        },
    )


@pytest.mark.xfail(reason="deterministic bug detector for #251", strict=False)
def test_251_evaluate_sbom_missing_parquet_append_and_evidence_sealing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    Issue #251: evaluate_sbom skips Parquet append and evidence sealing.

    The evaluate_sbom() method should follow the same audit trail patterns
    as evaluate():
    1. Append decisions to the parquet audit log
    2. Seal evidence artifacts for tamper detection

    This test detects the missing audit trail guards in evaluate_sbom().
    """
    from caliper.core.models import OperatingMode
    from caliper.core.pipeline import ReviewPipeline

    append_calls: list[tuple[Path, list[object], str]] = []
    seal_calls: list[tuple[Path, str, str | None]] = []
    _patch_pipeline_runtime(monkeypatch, append_calls=append_calls, seal_calls=seal_calls)

    before_sbom = _sbom()
    after_sbom = _sbom(_component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))

    decisions = ReviewPipeline(_make_config(tmp_path)).evaluate_sbom(
        before_sbom=before_sbom,
        after_sbom=after_sbom,
        pr_url="https://github.com/org/repo/pull/1",
        team="platform",
        mode=OperatingMode.monitor,
        repo_path=tmp_path,
        commit_sha="abc123def456",
    )

    # Must have decisions to process
    assert decisions, "evaluate_sbom must return decisions for changed packages"

    # BUG DETECTOR: These assertions detect the missing audit trail in evaluate_sbom()
    # The evaluate() method has these at lines 285-294, but evaluate_sbom() omits them
    assert append_calls, "BUG #251: evaluate_sbom must append decisions to the parquet audit log"
    assert seal_calls, "BUG #251: evaluate_sbom must seal evidence artifacts like evaluate()"

    # Verify the append was called with the expected structure
    assert len(append_calls) == 1, "append_decisions should be called exactly once"
    evidence_root, decisions_list, run_id = append_calls[0]
    assert evidence_root == Path(tmp_path / "evidence")
    assert len(decisions_list) > 0, "decisions list should not be empty"
    assert run_id, "run_id should be non-empty"

    # Verify the seal was called with the expected structure
    assert len(seal_calls) == 1, "create_seal should be called exactly once"
    seal_dir, seal_run_id, prev_hash = seal_calls[0]
    assert prev_hash == "prev_hash", "previous hash should be passed correctly"
