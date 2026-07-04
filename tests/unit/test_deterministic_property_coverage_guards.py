"""Deterministic static guard for missing Hypothesis property tests (Issue #259).

Bug: The parsing modules for dependency diffs, PR hunk parsing, and manifest
     discovery are tested only with fixed example inputs.  Boundary invariants —
     such as "parsing never crashes on arbitrary UTF-8 input" or "empty inputs
     always return empty results" — are not captured by property-based tests.

Evidence:
  - tests/unit/test_diff.py         — no @given decorator
  - tests/unit/test_pr_review.py    — no @given decorator
  - tests/unit/test_manifest_discovery.py — no @given decorator

Fix: Add Hypothesis @given-decorated tests to each of the above files covering at
     least the SAFETY property "parser never raises on arbitrary string input" and
     the INVARIANT property "empty input returns empty output".

Parent bug: #225 / Epic: #146.
Status: enforcing — all three test files carry @given property tests; this
guard now fails hard if any of them regresses to example-only coverage.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TESTS = _REPO / "tests" / "unit"

_PROPERTY_TEST_FILES = {
    "test_diff.py": _TESTS / "test_diff.py",
    "test_pr_review.py": _TESTS / "test_pr_review.py",
    "test_manifest_discovery.py": _TESTS / "test_manifest_discovery.py",
}


def _read_source(path: Path) -> str:
    assert path.exists(), f"Expected test file not found: {path}"
    content = path.read_text(encoding="utf-8")
    assert len(content) > 50, f"Test file is suspiciously short: {path}"
    return content


def test_259_test_diff_has_hypothesis_property_tests() -> None:
    """tests/unit/test_diff.py must contain at least one @given-decorated test.

    The diff parser in diff.py handles free-form text from git diffs.  It should
    have a SAFETY property test: for any arbitrary string input, the parser must
    not raise an exception.  It should also have an INVARIANT: empty diff → empty
    result.  These require Hypothesis @given.
    """
    src = _read_source(_PROPERTY_TEST_FILES["test_diff.py"])
    assert "@given" in src, (
        "BUG #259: tests/unit/test_diff.py has no @given-decorated property tests. "
        "Add Hypothesis property tests covering at least: "
        "(1) SAFETY — parser never raises on arbitrary string input, "
        "(2) INVARIANT — empty string input returns empty result."
    )


def test_259_test_pr_review_has_hypothesis_property_tests() -> None:
    """tests/unit/test_pr_review.py must contain at least one @given-decorated test.

    The PR hunk parser in pr_review.py processes raw GitHub webhook diff payloads.
    Property tests should verify: arbitrary hunk text never crashes the parser,
    and a diff with no changed files yields no findings.
    """
    src = _read_source(_PROPERTY_TEST_FILES["test_pr_review.py"])
    assert "@given" in src, (
        "BUG #259: tests/unit/test_pr_review.py has no @given-decorated property tests. "
        "Add Hypothesis property tests covering at least: "
        "(1) SAFETY — hunk parser never raises on arbitrary diff text, "
        "(2) INVARIANT — empty hunk list yields empty package list."
    )


def test_259_test_manifest_discovery_has_hypothesis_property_tests() -> None:
    """tests/unit/test_manifest_discovery.py must contain at least one @given test.

    manifest_discovery.py walks arbitrary file trees and classifies manifests.
    Property tests should verify: any file path is classified or skipped — never
    crashes — and the classifier is deterministic for the same input.
    """
    src = _read_source(_PROPERTY_TEST_FILES["test_manifest_discovery.py"])
    assert "@given" in src, (
        "BUG #259: tests/unit/test_manifest_discovery.py has no @given-decorated "
        "property tests. "
        "Add Hypothesis property tests covering at least: "
        "(1) SAFETY — path classifier never raises on arbitrary path strings, "
        "(2) INVARIANT — same path always produces the same classification."
    )
