"""Deterministic guards for plugin fail-open behaviour — Issue #245 / Parent #211.

Bug: sarif.py emits caliper-plugin-error results at level "error". sarif_to_review()
treats any SARIF error as a blocking finding (REQUEST_CHANGES), so a scanner
timeout or tool crash blocks a PR review exactly as if it were a security
violation — contradicting the fail-open invariant.

These are xfail until plugin errors are tagged separately and downgraded to
COMMENT behaviour. See issues #211 and #245.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #211 — "
        "caliper-plugin-error SARIF results at level='error' trigger REQUEST_CHANGES; "
        "downgrade to COMMENT (or a new 'degraded' level) for degraded tool failures"
    ),
    strict=False,
)

from caliper.core.pr_review import PRReview, sarif_to_review


def _plugin_error_sarif(tool_name: str = "syft", message: str = "scanner timed out") -> dict:
    """Minimal SARIF with a single caliper-plugin-error result."""
    return {
        "runs": [
            {
                "tool": {"driver": {"name": tool_name}},
                "results": [
                    {
                        "ruleId": "caliper-plugin-error",
                        "level": "error",
                        "message": {"text": message},
                        "locations": [],
                    }
                ],
            }
        ]
    }


class TestPluginErrorDoesNotBlockPr:
    """A degraded plugin failure must not block a PR review as if it were a violation."""

    def test_plugin_error_produces_comment_not_request_changes(self) -> None:
        """sarif_to_review() must emit COMMENT for caliper-plugin-error, not REQUEST_CHANGES.

        A scanner timeout or crash is a degraded tool failure, not a policy
        violation. Blocking the PR (REQUEST_CHANGES) contradicts the fail-open
        invariant and falsely signals a security concern to reviewers.

        Fix: detect caliper-plugin-error ruleId and route those results to a
        COMMENT (or dedicated degraded-tool-failure) event regardless of level.
        See issue #211.
        """
        sarif = _plugin_error_sarif()
        review: PRReview = sarif_to_review(sarif, diff_files=set())
        assert review.event == "COMMENT", (
            f"sarif_to_review() returned event={review.event!r} for an "
            f"caliper-plugin-error result — expected 'COMMENT'. "
            "A scanner timeout or crash must not block the PR review. "
            "Fix: downgrade caliper-plugin-error results to COMMENT behaviour. "
            "See issue #211."
        )

    def test_plugin_error_verdict_indicates_degraded_not_blocked(self) -> None:
        """The review verdict for a plugin error must communicate degradation, not a block."""
        sarif = _plugin_error_sarif(message="syft timed out after 60s")
        review: PRReview = sarif_to_review(sarif, diff_files=set())
        # Must not indicate blocking findings — that would mislead reviewers
        assert "blocking" not in review.verdict.lower(), (
            f"Review verdict {review.verdict!r} mentions 'blocking' for a plugin error. "
            "Degraded tool failures must not be presented as blocking violations. "
            "See issue #211."
        )
