"""Tests for caliper.core.taskfit_validator — strict 8-dimension gate."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.taskfit_validator import (
    DimensionScore,
    Recommendation,
    ValidationResult,
    validate_taskfit_response,
)

VALID_RESPONSE = """\
NECESSITY:    PASS — Standard library does not cover this use case.
MINIMALITY:   PASS — Narrow single-purpose library with no extras.
MAINTENANCE:  CONCERN — Last release was 14 months ago.
SECURITY:     PASS — Signed releases, SECURITY.md present.
EXPOSURE:     CONCERN — Processes untrusted HTTP input in runtime.
BLAST_RADIUS: PASS — 3 transitive dependencies.
ALTERNATIVES: FAIL — Approved alternative httpx already exists.
BEHAVIORAL:   PASS — No install scripts or native extensions.

RECOMMENDATION: REVIEW — Package is functional but an approved alternative exists.
"""

MISSING_RECOMMENDATION = """\
NECESSITY:    PASS — Needed.
MINIMALITY:   PASS — Minimal.
MAINTENANCE:  PASS — Active.
SECURITY:     PASS — Good.
EXPOSURE:     PASS — Low risk.
BLAST_RADIUS: PASS — Small.
ALTERNATIVES: PASS — None available.
BEHAVIORAL:   PASS — Clean.
"""

MISSING_DIMENSIONS = """\
NECESSITY:    PASS — Needed.
MINIMALITY:   PASS — Minimal.

RECOMMENDATION: APPROVE — Looks good.
"""

DUPLICATE_DIMENSION = """\
NECESSITY:    PASS — First.
NECESSITY:    FAIL — Second.
MINIMALITY:   PASS — Ok.
MAINTENANCE:  PASS — Ok.
SECURITY:     PASS — Ok.
EXPOSURE:     PASS — Ok.
BLAST_RADIUS: PASS — Ok.
ALTERNATIVES: PASS — Ok.
BEHAVIORAL:   PASS — Ok.

RECOMMENDATION: APPROVE — Fine.
"""

INVALID_SCORE = """\
NECESSITY:    MAYBE — Not sure.
MINIMALITY:   PASS — Ok.
MAINTENANCE:  PASS — Ok.
SECURITY:     PASS — Ok.
EXPOSURE:     PASS — Ok.
BLAST_RADIUS: PASS — Ok.
ALTERNATIVES: PASS — Ok.
BEHAVIORAL:   PASS — Ok.

RECOMMENDATION: APPROVE — Fine.
"""


class TestValidResponse:
    def test_valid_response_parses_all_dimensions(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        assert result.valid is True
        assert result.assessment is not None
        assert len(result.assessment.dimensions) == 8

    def test_valid_response_scores_correct(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        a = result.assessment
        assert a.dimension("NECESSITY").score == DimensionScore.PASS
        assert a.dimension("MAINTENANCE").score == DimensionScore.CONCERN
        assert a.dimension("ALTERNATIVES").score == DimensionScore.FAIL

    def test_valid_response_recommendation(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        assert result.assessment.recommendation == Recommendation.REVIEW

    def test_valid_response_counts(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        a = result.assessment
        assert a.pass_count == 5
        assert a.concern_count == 2
        assert a.fail_count == 1

    def test_valid_response_rationale_captured(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        alt = result.assessment.dimension("ALTERNATIVES")
        assert "httpx" in alt.rationale

    def test_valid_response_preserves_raw_text(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        assert result.assessment.raw_text == VALID_RESPONSE


class TestInvalidResponses:
    def test_empty_string_rejected(self) -> None:
        result = validate_taskfit_response("")
        assert result.valid is False
        assert any("Empty" in e.message for e in result.errors)

    def test_none_like_whitespace_rejected(self) -> None:
        result = validate_taskfit_response("   \n\n  ")
        assert result.valid is False

    def test_missing_recommendation_rejected(self) -> None:
        result = validate_taskfit_response(MISSING_RECOMMENDATION)
        assert result.valid is False
        assert any(e.field == "RECOMMENDATION" for e in result.errors)

    def test_missing_dimensions_rejected(self) -> None:
        result = validate_taskfit_response(MISSING_DIMENSIONS)
        assert result.valid is False
        missing_fields = {e.field for e in result.errors if "Missing" in e.message}
        assert "MAINTENANCE" in missing_fields
        assert "SECURITY" in missing_fields
        assert "EXPOSURE" in missing_fields

    def test_duplicate_dimension_rejected(self) -> None:
        result = validate_taskfit_response(DUPLICATE_DIMENSION)
        assert result.valid is False
        assert any("Duplicate" in e.message for e in result.errors)

    def test_invalid_score_treated_as_missing(self) -> None:
        result = validate_taskfit_response(INVALID_SCORE)
        assert result.valid is False
        assert any(e.field == "NECESSITY" for e in result.errors)

    def test_random_prose_rejected(self) -> None:
        result = validate_taskfit_response(
            "This package looks fine to me. I recommend approving it."
        )
        assert result.valid is False
        assert len(result.errors) >= 8


class TestRejectionGuidance:
    def test_guidance_includes_expected_format(self) -> None:
        result = validate_taskfit_response("")
        guidance = result.rejection_guidance()
        assert "Expected format" in guidance
        assert "NECESSITY" in guidance
        assert "RECOMMENDATION" in guidance

    def test_valid_response_has_no_guidance(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        assert result.rejection_guidance() == ""

    def test_error_summary_lists_all_errors(self) -> None:
        result = validate_taskfit_response(MISSING_DIMENSIONS)
        summary = result.error_summary()
        assert "MAINTENANCE" in summary
        assert "SECURITY" in summary


class TestDimensionLookup:
    def test_dimension_lookup_by_name(self) -> None:
        result = validate_taskfit_response(VALID_RESPONSE)
        assert result.assessment.dimension("NECESSITY") is not None
        assert result.assessment.dimension("NONEXISTENT") is None


class TestDashVariants:
    """The validator should accept em-dash, en-dash, and hyphen as separators."""

    def test_hyphen_separator(self) -> None:
        text = VALID_RESPONSE.replace("—", "-")
        result = validate_taskfit_response(text)
        assert result.valid is True

    def test_en_dash_separator(self) -> None:
        text = VALID_RESPONSE.replace("—", "–")
        result = validate_taskfit_response(text)
        assert result.valid is True


class TestPropertyBased:
    @given(
        scores=st.lists(
            st.sampled_from(["PASS", "CONCERN", "FAIL"]),
            min_size=8,
            max_size=8,
        ),
        rec=st.sampled_from(["APPROVE", "REVIEW", "REJECT"]),
    )
    @settings(max_examples=200)
    def test_any_valid_combination_parses(self, scores: list[str], rec: str) -> None:
        """Any combination of valid scores + valid recommendation must parse."""
        dims = [
            "NECESSITY",
            "MINIMALITY",
            "MAINTENANCE",
            "SECURITY",
            "EXPOSURE",
            "BLAST_RADIUS",
            "ALTERNATIVES",
            "BEHAVIORAL",
        ]
        lines = [f"{d}: {s} — test rationale" for d, s in zip(dims, scores, strict=True)]
        lines.append("")
        lines.append(f"RECOMMENDATION: {rec} — test summary")
        text = "\n".join(lines)

        result = validate_taskfit_response(text)
        assert result.valid is True
        assert result.assessment.recommendation == Recommendation(rec)
        assert len(result.assessment.dimensions) == 8

    @given(
        missing_count=st.integers(min_value=1, max_value=7),
    )
    @settings(max_examples=100)
    def test_missing_dimensions_always_rejected(self, missing_count: int) -> None:
        """Removing any N dimensions from a valid response must fail validation."""
        dims = [
            "NECESSITY",
            "MINIMALITY",
            "MAINTENANCE",
            "SECURITY",
            "EXPOSURE",
            "BLAST_RADIUS",
            "ALTERNATIVES",
            "BEHAVIORAL",
        ]
        kept = dims[: 8 - missing_count]
        lines = [f"{d}: PASS — ok" for d in kept]
        lines.append("")
        lines.append("RECOMMENDATION: APPROVE — fine")
        text = "\n".join(lines)

        result = validate_taskfit_response(text)
        assert result.valid is False
        assert len(result.errors) >= missing_count

    @given(
        rationale=st.text(
            min_size=1,
            max_size=100,
            alphabet=st.characters(
                whitelist_categories=("L", "N", "P", "Z"),
            ),
        ),
    )
    @settings(max_examples=200)
    def test_arbitrary_rationale_text_accepted(self, rationale: str) -> None:
        """Any non-empty rationale text should be accepted in a valid response."""
        dims = [
            "NECESSITY",
            "MINIMALITY",
            "MAINTENANCE",
            "SECURITY",
            "EXPOSURE",
            "BLAST_RADIUS",
            "ALTERNATIVES",
            "BEHAVIORAL",
        ]
        safe = rationale.replace("\n", " ").strip()
        if not safe:
            return
        lines = [f"{d}: PASS — {safe}" for d in dims]
        lines.append("")
        lines.append(f"RECOMMENDATION: APPROVE — {safe}")
        text = "\n".join(lines)

        result = validate_taskfit_response(text)
        assert result.valid is True
        for dim in result.assessment.dimensions:
            assert dim.rationale

    @given(
        scores=st.lists(
            st.sampled_from(["PASS", "CONCERN", "FAIL"]),
            min_size=8,
            max_size=8,
        ),
    )
    @settings(max_examples=200)
    def test_fail_count_matches_actual_fails(self, scores: list[str]) -> None:
        """The fail_count property must match the actual FAIL scores."""
        dims = [
            "NECESSITY",
            "MINIMALITY",
            "MAINTENANCE",
            "SECURITY",
            "EXPOSURE",
            "BLAST_RADIUS",
            "ALTERNATIVES",
            "BEHAVIORAL",
        ]
        lines = [f"{d}: {s} — reason" for d, s in zip(dims, scores, strict=True)]
        lines.append("")
        lines.append("RECOMMENDATION: REVIEW — summary")
        text = "\n".join(lines)

        result = validate_taskfit_response(text)
        assert result.valid is True
        expected_fails = scores.count("FAIL")
        assert result.assessment.fail_count == expected_fails
        assert result.assessment.concern_count == scores.count("CONCERN")
        assert result.assessment.pass_count == scores.count("PASS")

    @given(data=st.text(min_size=0, max_size=500))
    @settings(max_examples=200)
    def test_random_text_never_crashes(self, data: str) -> None:
        """The validator must never raise on any input — always returns a result."""
        result = validate_taskfit_response(data)
        assert isinstance(result, ValidationResult)
        assert isinstance(result.valid, bool)
        if not result.valid:
            assert len(result.errors) > 0
