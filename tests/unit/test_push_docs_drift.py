"""Drift guard: docs/CAPABILITIES.md documents --push (#524).

# tested-by: tests/unit/test_push_docs_drift.py

Cheap literal-substring check, same pattern as test_capability_counts.py's
``TestCapabilitiesDocInSync`` — catches the doc silently falling out of sync
with the stacked-PR push feature and its new port capability.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def test_capabilities_doc_mentions_push_and_create_pull_request() -> None:
    text = (_REPO / "docs" / "CAPABILITIES.md").read_text()
    assert "--push" in text, "docs/CAPABILITIES.md missing the --push flag"
    assert "create_pull_request" in text, "docs/CAPABILITIES.md missing create_pull_request"
