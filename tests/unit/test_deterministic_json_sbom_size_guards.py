"""Deterministic source-inspection guard for SBOM bloat in plugin results (Issue #257).

Bug: SyftPlugin.run() stores the full raw SBOM dict inside PluginResult.summary
     under the key "sbom".  A CycloneDX JSON SBOM for a large repo can be
     multiple megabytes, inflating every PluginResult that passes through the
     pipeline, the JSON report, and in-memory aggregation.

Evidence:
  - syft.py line 83: `summary={"components": len(components), "sbom": data}`
    where `data` is the full parsed CycloneDX SBOM dict.

Fix: Remove "sbom": data from the summary.  Store only the count and a reference
     (e.g. an artifact path where the full SBOM was written to disk).  The
     SyftScanner data-tier class may write the SBOM to the evidence store.

Parent bug: #223 / Epic: #146.
Status: fixed — SyftPlugin.run() no longer stores the full SBOM in summary.
"""

from __future__ import annotations

import inspect


def _get_syft_run_source() -> str:
    from caliper.plugins.syft import SyftPlugin

    src = inspect.getsource(SyftPlugin.run)
    assert len(src) > 50, (
        "inspect.getsource returned a suspiciously short string — "
        "SyftPlugin.run may have been renamed or moved"
    )
    return src


def test_257_syft_summary_does_not_embed_full_sbom() -> None:
    """SyftPlugin.run() must not embed the full SBOM dict in summary[\"sbom\"].

    Storing the entire parsed SBOM in PluginResult.summary means every consumer
    of the result (JSON report, PR comment renderer, in-memory normalizer) has
    to carry a multi-megabyte payload.  Only the component count and an artifact
    path reference belong in the summary.

    When the bug is fixed, the \"sbom\": data assignment will be gone from
    SyftPlugin.run() and this test will go green.
    """
    src = _get_syft_run_source()
    assert '"sbom": data' not in src, (
        'BUG #257: SyftPlugin.run() stores the full SBOM via summary={"sbom": data}. '
        "This inflates every PluginResult with a potentially multi-megabyte payload. "
        'Remove "sbom": data from the summary dict. Store only the component count '
        "and, if the full SBOM is needed downstream, write it to the evidence store "
        "and include the artifact path reference instead."
    )


def test_257_syft_summary_retains_component_count() -> None:
    """Non-vacuity guard: SyftPlugin.run() must still report a component count.

    The fix must not silently drop useful metadata.  The summary must still
    contain the component count so that the renderer and report can display it.
    """
    src = _get_syft_run_source()
    assert "components" in src, (
        "SyftPlugin.run() no longer includes a component count in its summary. "
        'The fix for #257 must keep `"components": len(components)` in the summary '
        "while only removing the full SBOM blob."
    )
