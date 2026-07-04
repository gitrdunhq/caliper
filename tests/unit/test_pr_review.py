"""Tests for PR review posting — SARIF to inline GitHub review comments.
# tested-by: tests/unit/test_pr_review.py
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from hypothesis import given
from hypothesis import strategies as st

from caliper.core.pr_review import (
    get_pr_diff_hunks,
    line_in_hunks,
    parse_hunk_ranges,
    sarif_to_review,
)
from tests.unit._strategies import garbage_text


def _sarif(results: list[dict], tool: str = "test-tool") -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool}},
                "results": results,
            }
        ],
    }


def _finding(
    file: str = "src/app.py",
    line: int = 10,
    level: str = "error",
    rule: str = "test-rule",
    msg: str = "test finding",
) -> dict:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": msg},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": line},
                }
            }
        ],
    }


class TestSarifToReview:
    def test_empty_sarif_produces_comment_no_findings(self):
        review = sarif_to_review(_sarif([]), diff_files=set())
        assert review.event == "COMMENT"
        assert "No findings" in review.body
        assert review.comments == []

    def test_error_finding_in_diff_becomes_inline_comment(self):
        sarif = _sarif([_finding(file="src/app.py", line=42, level="error")])
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "REQUEST_CHANGES"
        assert len(review.comments) == 1
        assert review.comments[0].path == "src/app.py"
        assert review.comments[0].line == 42
        assert "test-rule" in review.comments[0].body

    def test_finding_outside_diff_goes_to_summary(self):
        sarif = _sarif([_finding(file="src/other.py", level="warning")])
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "COMMENT"
        assert len(review.comments) == 0
        assert len(review.outside_diff) == 1
        assert "src/other.py" in review.body

    def test_mixed_findings_request_changes_on_errors(self):
        sarif = _sarif(
            [
                _finding(file="src/app.py", level="error"),
                _finding(file="src/app.py", line=20, level="warning", rule="warn-rule"),
                _finding(file="src/other.py", level="note", rule="note-rule"),
            ]
        )
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "REQUEST_CHANGES"
        assert len(review.comments) == 2
        assert len(review.outside_diff) == 1
        assert "3" in review.body

    def test_warnings_only_uses_comment_event(self):
        sarif = _sarif([_finding(file="src/app.py", level="warning")])
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert review.event == "COMMENT"
        assert "warning" in review.body.lower()

    def test_summary_counts_are_correct(self):
        sarif = _sarif(
            [
                _finding(level="error", rule="r1"),
                _finding(level="error", rule="r2", line=20),
                _finding(level="warning", rule="r3", line=30),
                _finding(level="note", rule="r4", file="other.py"),
            ]
        )
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert "2 error" in review.body
        assert "1 warning" in review.body
        assert "4" in review.body

    def test_plugin_error_sentinel_does_not_block(self):
        """A crashed plugin's synthetic 'caliper-plugin-error' result is fail-open
        (#211) — it must not be recounted into error_count and flip the verdict
        to REQUEST_CHANGES. Only real findings should block."""
        sarif = _sarif(
            [
                {
                    "ruleId": "caliper-plugin-error",
                    "level": "error",
                    "message": {"text": "plugin osv-scanner crashed: timeout"},
                }
            ]
        )
        review = sarif_to_review(sarif, diff_files=set())

        assert review.event == "COMMENT"
        assert review.comments == []

    def test_no_locations_skips_inline(self):
        sarif = _sarif(
            [
                {
                    "ruleId": "no-loc",
                    "level": "warning",
                    "message": {"text": "no location"},
                    "locations": [],
                }
            ]
        )
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert len(review.comments) == 0
        assert review.event == "COMMENT"


class TestParseHunkRanges:
    def test_single_hunk(self):
        patch = "@@ -1,3 +1,5 @@\n+added\n context\n"
        ranges = parse_hunk_ranges(patch)
        assert ranges == [(1, 5)]

    def test_multiple_hunks(self):
        patch = "@@ -1,3 +1,4 @@\n context\n+added\n@@ -20,3 +21,6 @@\n context\n+more\n"
        ranges = parse_hunk_ranges(patch)
        assert ranges == [(1, 4), (21, 26)]

    def test_no_hunks(self):
        assert parse_hunk_ranges("") == []
        assert parse_hunk_ranges("no hunks here") == []

    def test_single_line_hunk(self):
        patch = "@@ -5,0 +5 @@\n+single line\n"
        ranges = parse_hunk_ranges(patch)
        assert ranges == [(5, 5)]


class TestLineInHunks:
    def test_line_inside_hunk(self):
        assert line_in_hunks(3, [(1, 5)]) is True

    def test_line_at_hunk_boundary(self):
        assert line_in_hunks(1, [(1, 5)]) is True
        assert line_in_hunks(5, [(1, 5)]) is True

    def test_line_outside_hunk(self):
        assert line_in_hunks(6, [(1, 5)]) is False
        assert line_in_hunks(0, [(1, 5)]) is False

    def test_line_in_second_hunk(self):
        assert line_in_hunks(25, [(1, 5), (20, 30)]) is True

    def test_empty_hunks(self):
        assert line_in_hunks(1, []) is False


class TestSarifToReviewWithHunks:
    def test_finding_on_valid_hunk_line_becomes_inline(self):
        sarif = _sarif([_finding(file="src/app.py", line=3, level="error")])
        diff_hunks = {"src/app.py": [(1, 10)]}
        review = sarif_to_review(sarif, diff_files={"src/app.py"}, diff_hunks=diff_hunks)

        assert len(review.comments) == 1
        assert review.comments[0].line == 3

    def test_finding_outside_hunk_goes_to_summary(self):
        sarif = _sarif([_finding(file="src/app.py", line=50, level="error")])
        diff_hunks = {"src/app.py": [(1, 10)]}
        review = sarif_to_review(sarif, diff_files={"src/app.py"}, diff_hunks=diff_hunks)

        assert len(review.comments) == 0
        assert len(review.outside_diff) == 1

    def test_no_hunks_provided_falls_back_to_file_check(self):
        sarif = _sarif([_finding(file="src/app.py", line=50, level="error")])
        review = sarif_to_review(sarif, diff_files={"src/app.py"})

        assert len(review.comments) == 1

    def test_smart_comment_has_rule_and_action(self):
        sarif = _sarif(
            [
                _finding(
                    file="src/app.py",
                    line=5,
                    level="error",
                    rule="sql-injection",
                    msg="User input concatenated into SQL query",
                )
            ]
        )
        diff_hunks = {"src/app.py": [(1, 10)]}
        review = sarif_to_review(sarif, diff_files={"src/app.py"}, diff_hunks=diff_hunks)

        body = review.comments[0].body
        assert "sql-injection" in body
        assert "error" in body
        assert "User input concatenated" in body

    def test_smart_comment_includes_fix_hint_when_available(self):
        sarif_data = _sarif(
            [
                {
                    "ruleId": "hardcoded-secret",
                    "level": "error",
                    "message": {"text": "Hardcoded password detected"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {"startLine": 5},
                            }
                        }
                    ],
                    "fixes": [
                        {
                            "description": {"text": "Use environment variable instead"},
                        }
                    ],
                }
            ]
        )
        diff_hunks = {"src/app.py": [(1, 10)]}
        review = sarif_to_review(sarif_data, diff_files={"src/app.py"}, diff_hunks=diff_hunks)

        body = review.comments[0].body
        assert "environment variable" in body.lower()


# ---------------------------------------------------------------------------
# Subprocess exception handling — get_pr_diff_files, get_pr_diff_hunks, post_review
# ---------------------------------------------------------------------------


from caliper.core.pr_review import (  # noqa: E402
    PRReview,
    get_pr_diff_files,
    post_review,
)


class TestGetPrDiffFilesExceptions:
    """get_pr_diff_files must not propagate subprocess errors."""

    def test_timeout_expired_returns_empty_set(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("gh", 30)
            result = get_pr_diff_files("owner/repo", 42)
            assert result == set()

    def test_file_not_found_returns_empty_set(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("gh not found")
            result = get_pr_diff_files("owner/repo", 42)
            assert result == set()


class TestGetPrDiffHunksExceptions:
    """get_pr_diff_hunks must not propagate subprocess errors."""

    def test_timeout_expired_returns_empty_dict(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("gh", 30)
            result = get_pr_diff_hunks("owner/repo", 42)
            assert result == {}

    def test_file_not_found_returns_empty_dict(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("gh not found")
            result = get_pr_diff_hunks("owner/repo", 42)
            assert result == {}


class TestPostReviewExceptions:
    """post_review must not propagate subprocess errors."""

    def test_timeout_expired_returns_false(self):
        review = PRReview(body="test", event="COMMENT")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("gh", 30)
            result = post_review("owner/repo", 42, review)
            assert result is False

    def test_file_not_found_returns_false(self):
        review = PRReview(body="test", event="COMMENT")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("gh not found")
            result = post_review("owner/repo", 42, review)
            assert result is False


class TestGetPrDiffHunks:
    """Tests for get_pr_diff_hunks JSON error handling."""

    def test_invalid_json_returns_empty_dict(self) -> None:
        """Malformed JSON from gh CLI must not crash — return empty dict."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="{invalid json",
                stderr="",
            )
            result = get_pr_diff_hunks("owner/repo", 123)
            assert result == {}

    def test_empty_stdout_returns_empty_dict(self) -> None:
        """Empty stdout must not crash — return empty dict."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )
            result = get_pr_diff_hunks("owner/repo", 123)
            assert result == {}

    def test_valid_json_returns_hunks(self) -> None:
        """Valid JSON from gh CLI returns parsed hunks."""
        files_json = json.dumps(
            [
                {
                    "filename": "src/app.py",
                    "patch": "@@ -1,3 +1,4 @@\n line1\n line2\n+new line\n line3",
                }
            ]
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=files_json,
                stderr="",
            )
            result = get_pr_diff_hunks("owner/repo", 123)
            assert "src/app.py" in result


# ---------------------------------------------------------------------------
# Property-based tests (#225 / #259) — Hypothesis domains for the hunk parser
# ---------------------------------------------------------------------------


class TestProperties:
    """Property domains for PR hunk parsing and SARIF→review conversion.

    Domains (per DPS-12):
      - SAFETY: parsers never raise on arbitrary untrusted diff/SARIF input.
      - INVARIANT (Determinism): same input → same output.
      - INVARIANT: empty input → empty output.
    """

    @given(patch=garbage_text(max_size=300))
    def test_parse_hunk_ranges_never_raises(self, patch: str) -> None:
        """SAFETY: arbitrary patch text never crashes the hunk parser."""
        ranges = parse_hunk_ranges(patch)
        assert isinstance(ranges, list)
        for start, end in ranges:
            assert start >= 0
            assert end >= start or end == start

    @given(patch=garbage_text(max_size=300))
    def test_parse_hunk_ranges_deterministic(self, patch: str) -> None:
        """INVARIANT (Determinism): re-parsing yields the identical ranges."""
        assert parse_hunk_ranges(patch) == parse_hunk_ranges(patch)

    @given(
        old_start=st.integers(min_value=0, max_value=10_000),
        old_len=st.integers(min_value=0, max_value=500),
        new_start=st.integers(min_value=0, max_value=10_000),
        new_len=st.integers(min_value=1, max_value=500),
    )
    def test_parse_hunk_ranges_well_formed_header_round_trips(
        self, old_start: int, old_len: int, new_start: int, new_len: int
    ) -> None:
        """INVARIANT: a well-formed header parses to exactly its +side range."""
        patch = f"@@ -{old_start},{old_len} +{new_start},{new_len} @@\n context\n"
        assert parse_hunk_ranges(patch) == [(new_start, new_start + new_len - 1)]

    @given(line=st.integers())
    def test_line_in_hunks_empty_hunks_always_false(self, line: int) -> None:
        """INVARIANT: no line is ever inside an empty hunk list."""
        assert line_in_hunks(line, []) is False

    @given(
        line=st.integers(min_value=-1000, max_value=100_000),
        hunks=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=10_000),
                st.integers(min_value=0, max_value=10_000),
            ),
            max_size=20,
        ),
    )
    def test_line_in_hunks_matches_range_semantics(
        self, line: int, hunks: list[tuple[int, int]]
    ) -> None:
        """INVARIANT: membership is exactly 'within any inclusive range'."""
        expected = any(start <= line <= end for start, end in hunks)
        assert line_in_hunks(line, hunks) == expected

    @given(
        results=st.lists(
            st.fixed_dictionaries(
                {
                    "ruleId": garbage_text(max_size=30),
                    "level": st.sampled_from(["error", "warning", "note", ""]),
                    "message": st.fixed_dictionaries({"text": garbage_text(max_size=80)}),
                }
            ),
            max_size=10,
        )
    )
    def test_sarif_to_review_never_raises_and_empty_diff_has_no_inline_comments(
        self, results: list[dict]
    ) -> None:
        """SAFETY + INVARIANT: arbitrary SARIF results never crash the
        converter, and with no files in the diff there are never inline
        comments."""
        sarif = _sarif(results)
        review = sarif_to_review(sarif, diff_files=set())
        assert review.comments == []
        assert review.event in ("REQUEST_CHANGES", "COMMENT")

    @given(patch=garbage_text(max_size=200))
    def test_sarif_to_review_sentinels_never_block(self, patch: str) -> None:
        """SAFETY (fail-open, #211): degraded-plugin sentinel results never
        produce a REQUEST_CHANGES verdict, whatever the surrounding text."""
        results = [
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": patch},
            }
            for rule_id in ("caliper-plugin-error", "caliper-truncated")
        ]
        review = sarif_to_review(_sarif(results), diff_files=set())
        assert review.event == "COMMENT"
