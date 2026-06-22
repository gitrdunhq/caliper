"""Deterministic source-inspection guard for PyPI client lifecycle (Issue #255).

Bug: ReviewPipeline.evaluate() creates a PyPIClient but never closes it.
     The finally block at pipeline.py lines 296-297 only calls db.close().
     Any connection pool or keep-alive session held by PyPIClient is leaked.

Evidence:
  - pipeline.py line 149: `pypi_client = d["PyPIClient"](timeout=config.pypi_timeout)`
  - pipeline.py lines 296-297: `finally: db.close()` — no pypi_client.close()

Fix: Add `pypi_client.close()` to the finally block of evaluate(), alongside
     the existing `db.close()` call.

Parent bug: #221 / Epic: #146.
Status: xfail — pypi_client.close() missing from the evaluate() finally block.
"""

from __future__ import annotations

import inspect

import pytest


def _get_evaluate_source() -> str:
    from caliper.core.pipeline import ReviewPipeline

    src = inspect.getsource(ReviewPipeline.evaluate)
    assert len(src) > 200, (
        "inspect.getsource returned a suspiciously short string — "
        "ReviewPipeline.evaluate may have been renamed or moved"
    )
    return src


@pytest.mark.xfail(
    reason="deterministic bug detector for #255 — close pypi_client in evaluate(), then green",
    strict=False,
)
def test_255_evaluate_closes_pypi_client() -> None:
    """evaluate() must call pypi_client.close() in its finally block.

    The PyPIClient is allocated on every evaluate() call.  Without explicit
    cleanup the underlying HTTP session / connection pool is leaked each time
    the pipeline runs.  The fix is a single pypi_client.close() call in the
    existing finally block, alongside db.close().
    """
    src = _get_evaluate_source()
    assert "pypi_client.close()" in src, (
        "BUG #255: evaluate() does not call pypi_client.close(). "
        "The PyPIClient HTTP session is leaked on every pipeline run. "
        "Add `pypi_client.close()` to the finally block of evaluate(), "
        "immediately after the existing `db.close()` call."
    )


def test_255_evaluate_creates_pypi_client() -> None:
    """Sanity: evaluate() must create a pypi_client (non-vacuity guard).

    If the pypi_client allocation were removed, the close() test would be
    testing nothing.  This guard ensures the client is still created so
    that the lifecycle test above is meaningful.
    """
    src = _get_evaluate_source()
    assert "pypi_client" in src, (
        "evaluate() no longer creates a pypi_client at all. "
        "The lifecycle test in this file is now vacuous — update it to "
        "match the new PyPI metadata lookup pattern."
    )
