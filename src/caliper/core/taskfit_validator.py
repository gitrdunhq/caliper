"""Task-fit LLM response validator — strict 8-dimension gate.
# tested-by: tests/unit/test_taskfit_validator.py

Parses and validates the structured output from the task-fit LLM advisory.
Rejects malformed responses with specific guidance on what failed.
The LLM must produce all 8 dimensions plus a recommendation line.
No partial credit — all or nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

import structlog

logger = structlog.get_logger(__name__)

REQUIRED_DIMENSIONS = (
    "NECESSITY",
    "MINIMALITY",
    "MAINTENANCE",
    "SECURITY",
    "EXPOSURE",
    "BLAST_RADIUS",
    "ALTERNATIVES",
    "BEHAVIORAL",
)

VALID_SCORES = frozenset({"PASS", "CONCERN", "FAIL"})
VALID_RECOMMENDATIONS = frozenset({"APPROVE", "REVIEW", "REJECT"})


class DimensionScore(StrEnum):
    PASS = "PASS"
    CONCERN = "CONCERN"
    FAIL = "FAIL"


class Recommendation(StrEnum):
    APPROVE = "APPROVE"
    REVIEW = "REVIEW"
    REJECT = "REJECT"


@dataclass(frozen=True)
class DimensionResult:
    name: str
    score: DimensionScore
    rationale: str


@dataclass(frozen=True)
class TaskFitAssessment:
    dimensions: tuple[DimensionResult, ...]
    recommendation: Recommendation
    recommendation_rationale: str
    raw_text: str

    @property
    def fail_count(self) -> int:
        return sum(1 for d in self.dimensions if d.score == DimensionScore.FAIL)

    @property
    def concern_count(self) -> int:
        return sum(1 for d in self.dimensions if d.score == DimensionScore.CONCERN)

    @property
    def pass_count(self) -> int:
        return sum(1 for d in self.dimensions if d.score == DimensionScore.PASS)

    def dimension(self, name: str) -> DimensionResult | None:
        for d in self.dimensions:
            if d.name == name:
                return d
        return None


@dataclass
class ValidationError:
    field: str
    message: str


@dataclass
class ValidationResult:
    valid: bool
    assessment: TaskFitAssessment | None = None
    errors: list[ValidationError] = field(default_factory=list)

    def error_summary(self) -> str:
        if not self.errors:
            return "No errors."
        lines = [f"- {e.field}: {e.message}" for e in self.errors]
        return "\n".join(lines)

    def rejection_guidance(self) -> str:
        if self.valid:
            return ""
        parts = [
            "LLM response rejected by task-fit validator.",
            "",
            "Errors:",
            self.error_summary(),
            "",
            "Expected format:",
            "```",
            "NECESSITY:    [PASS|CONCERN|FAIL] — [rationale]",
            "MINIMALITY:   [PASS|CONCERN|FAIL] — [rationale]",
            "MAINTENANCE:  [PASS|CONCERN|FAIL] — [rationale]",
            "SECURITY:     [PASS|CONCERN|FAIL] — [rationale]",
            "EXPOSURE:     [PASS|CONCERN|FAIL] — [rationale]",
            "BLAST_RADIUS: [PASS|CONCERN|FAIL] — [rationale]",
            "ALTERNATIVES: [PASS|CONCERN|FAIL] — [rationale]",
            "BEHAVIORAL:   [PASS|CONCERN|FAIL] — [rationale]",
            "",
            "RECOMMENDATION: [APPROVE|REVIEW|REJECT] — [rationale]",
            "```",
        ]
        return "\n".join(parts)


_DIM_RE = re.compile(
    r"^([A-Z_]+):\s*(PASS|CONCERN|FAIL)\s*[—\-–]\s*(.+)$",
    re.MULTILINE,
)

_REC_RE = re.compile(
    r"^RECOMMENDATION:\s*(APPROVE|REVIEW|REJECT)\s*[—\-–]\s*(.+)$",
    re.MULTILINE,
)


def validate_taskfit_response(raw_text: str) -> ValidationResult:
    """Parse and validate an LLM task-fit response.

    Returns a ValidationResult with either a valid TaskFitAssessment
    or a list of specific errors explaining what failed.
    """
    if not raw_text or not raw_text.strip():
        return ValidationResult(
            valid=False,
            errors=[ValidationError("response", "Empty response from LLM.")],
        )

    errors: list[ValidationError] = []
    dimensions: list[DimensionResult] = []
    found_dims: set[str] = set()

    for match in _DIM_RE.finditer(raw_text):
        name = match.group(1).strip()
        score_str = match.group(2).strip()
        rationale = match.group(3).strip()

        if name not in REQUIRED_DIMENSIONS:
            continue

        if name in found_dims:
            errors.append(ValidationError(name, f"Duplicate dimension: {name}"))
            continue

        found_dims.add(name)
        dimensions.append(
            DimensionResult(
                name=name,
                score=DimensionScore(score_str),
                rationale=rationale,
            )
        )

    missing = set(REQUIRED_DIMENSIONS) - found_dims
    for dim in sorted(missing):
        errors.append(ValidationError(dim, f"Missing required dimension: {dim}"))

    rec_match = _REC_RE.search(raw_text)
    if rec_match is None:
        errors.append(
            ValidationError(
                "RECOMMENDATION",
                "Missing RECOMMENDATION line. "
                "Expected: RECOMMENDATION: [APPROVE|REVIEW|REJECT] — [rationale]",
            )
        )
        recommendation = None
        rec_rationale = ""
    else:
        recommendation = Recommendation(rec_match.group(1).strip())
        rec_rationale = rec_match.group(2).strip()

    if errors:
        logger.warning(
            "taskfit_validation_failed",
            error_count=len(errors),
            errors=[e.message for e in errors],
        )
        return ValidationResult(valid=False, errors=errors)

    ordered = sorted(dimensions, key=lambda d: REQUIRED_DIMENSIONS.index(d.name))

    assessment = TaskFitAssessment(
        dimensions=tuple(ordered),
        recommendation=recommendation,
        recommendation_rationale=rec_rationale,
        raw_text=raw_text,
    )

    logger.info(
        "taskfit_validation_passed",
        pass_count=assessment.pass_count,
        concern_count=assessment.concern_count,
        fail_count=assessment.fail_count,
        recommendation=assessment.recommendation.value,
    )

    return ValidationResult(valid=True, assessment=assessment)
