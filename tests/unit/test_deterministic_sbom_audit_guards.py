"""Deterministic source-inspection guard for SBOM audit trail gap (Issue #251).

Bug: evaluate_sbom() omits the two audit-trail calls that evaluate() makes:
  1. append_decisions() — Parquet audit log append
  2. create_seal() — tamper-evident evidence sealing

Evidence:
  - pipeline.py evaluate() lines 285-294: calls both append_decisions and create_seal
  - pipeline.py evaluate_sbom() finally block (line 476-477): only calls db.close()

These tests detect the gap by inspecting the source of evaluate_sbom() for the
required function call strings.  When the bug is fixed, both strings will appear
in the source and these tests will go green.

Status: xfail — bug still present in pipeline.py.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #251 — fix evaluate_sbom() audit trail, then green",
    strict=False,
)


def _get_evaluate_sbom_source() -> str:
    from caliper.core.pipeline import ReviewPipeline

    src = inspect.getsource(ReviewPipeline.evaluate_sbom)
    assert len(src) > 100, (
        "inspect.getsource returned a suspiciously short string — "
        "the import or class structure may have changed"
    )
    return src


def test_251_evaluate_sbom_calls_append_decisions() -> None:
    """evaluate_sbom() must call append_decisions() to write the Parquet audit log.

    The evaluate() method calls append_decisions() at line 286 of pipeline.py.
    evaluate_sbom() omits this call, leaving SBOM-derived decisions out of the
    audit log.  The fix is to add the same call to evaluate_sbom()'s finally
    block (or equivalent).
    """
    src = _get_evaluate_sbom_source()
    assert "append_decisions" in src, (
        "BUG #251: evaluate_sbom() does not call append_decisions(). "
        "SBOM-based decisions are silently omitted from the Parquet audit log. "
        "Add append_decisions(Path(config.evidence_path), decisions, run_id) "
        "to the evaluate_sbom() finally block, mirroring evaluate()."
    )


def test_251_evaluate_sbom_calls_create_seal() -> None:
    """evaluate_sbom() must call create_seal() to seal evidence artifacts.

    The evaluate() method calls create_seal() at line 292 of pipeline.py.
    evaluate_sbom() omits this call, leaving evidence from SBOM-based runs
    unsealed and vulnerable to undetected tampering.
    """
    src = _get_evaluate_sbom_source()
    assert "create_seal" in src, (
        "BUG #251: evaluate_sbom() does not call create_seal(). "
        "Evidence artifacts from SBOM-based pipeline runs are never sealed. "
        "Add the create_seal() call to evaluate_sbom()'s finally block, "
        "mirroring the pattern in evaluate()."
    )
