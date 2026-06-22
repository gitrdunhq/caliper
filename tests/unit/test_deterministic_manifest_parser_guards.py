"""Deterministic guards for manifest detection vs parser coverage — Issue #244 / Parent #210.

Bug: diff.py detects setup.py, setup.cfg, Pipfile, Pipfile.lock, and poetry.lock
as dependency files that trigger a review. However, pipeline_helpers.parse_changes()
only handles requirements.txt, requirements-dev.txt, and pyproject.toml. A changed
Pipfile or setup.py is detected, routes into the pipeline, then silently produces
no dependency review decision — the user sees no feedback.

These are xfail until either:
  (a) every detected manifest has a parser in parse_changes(), or
  (b) unsupported manifests are explicitly routed through the SBOM diff path.
See issues #210 and #244.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #210 — "
        "diff._DEPENDENCY_FILES contains manifests that parse_changes() cannot parse; "
        "add parsers or route unsupported manifests through SBOM diff"
    ),
    strict=False,
)

from caliper.core.diff import _DEPENDENCY_FILES
from caliper.core.pipeline_helpers import parse_changes


class TestManifestDetectionMatchesParserCoverage:
    """Every file detected as a dependency change must have a corresponding parser."""

    def test_all_detected_manifests_have_a_parser(self) -> None:
        """Every name in _DEPENDENCY_FILES must be handled by parse_changes().

        Detected-but-unparsed manifests (Pipfile, setup.py, setup.cfg,
        Pipfile.lock, poetry.lock) route into the pipeline and then silently
        produce no dependency review decision. The user sees a triggered review
        with no findings — misleadingly clean.

        Fix: add parsers for each manifest, or route them through the SBOM diff
        path, or remove them from _DEPENDENCY_FILES if review is intentionally
        unsupported. See issue #210.
        """
        # Probe which manifests parse_changes() handles by passing synthetic diffs
        # and checking whether it returns [] (unhandled) or non-empty changes.
        handled: set[str] = set()
        probe_diff = "--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-old\n+new\n"

        for name in _DEPENDENCY_FILES:
            changes = parse_changes(
                before_content="old\n",
                after_content="new\n",
                file_path=f"/{name}",
            )
            if changes:
                handled.add(name)

        unhandled = _DEPENDENCY_FILES - handled
        assert not unhandled, (
            f"These manifests are detected by diff._DEPENDENCY_FILES but produce "
            f"no changes from parse_changes(): {sorted(unhandled)}. "
            "A changed file triggers review but delivers no findings — "
            "silently incomplete. Fix: add parsers or route to SBOM diff. "
            "See issue #210."
        )
