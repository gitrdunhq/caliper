"""DetectorFinding model for bug detector findings.
# tested-by: tests/unit/detectors/test_framework.py

Defines the DetectorFinding model and conversion to core Finding model.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator

from caliper.core.models import Finding, FindingCategory, FindingSeverity
from caliper.detectors.categories import CATEGORY_TO_FINDING, DetectorCategory


class DetectorFinding(BaseModel):
    """A finding from a deterministic bug detector."""

    model_config = ConfigDict(populate_by_name=True, use_enum_values=False)

    detector_id: str  # CAL-001 format
    detector_name: str
    category: DetectorCategory
    severity: FindingSeverity
    file_path: str
    line_number: int
    column: int | None = None
    message: str
    snippet: str | None = None  # Code context
    issue_reference: str | None = None  # GitHub issue #
    fix_hint: str | None = None
    confidence: float = 1.0  # 0.0-1.0

    @field_validator("line_number")
    @classmethod
    def validate_line_number(cls, v: int) -> int:
        """Validate line_number is positive."""
        if v < 1:
            raise ValueError(f"line_number must be >= 1, got {v}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Validate confidence is in range [0.0, 1.0]."""
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {v}")
        return v

    def to_finding(self) -> Finding:
        """Convert to core Finding model for scanner integration.

        Maps detector-specific fields to the core Finding model according
        to ADR-DET-003:
        - detector_id -> source_tool
        - category -> FindingCategory via CATEGORY_TO_FINDING
        - message -> description
        - issue_reference -> advisory_id
        - confidence -> confidence
        """
        return Finding(
            severity=self.severity,
            category=CATEGORY_TO_FINDING.get(self.category, FindingCategory.behavioral),
            description=self.message,
            source_tool=self.detector_id,
            package_name="caliper",
            version="",
            advisory_id=self.issue_reference,
            confidence=self.confidence,
        )
