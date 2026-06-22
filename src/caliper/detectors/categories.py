"""Detector categories for bug classification.
# tested-by: tests/unit/detectors/test_framework.py

Maps detector categories to FindingCategory values for scanner integration.
"""

from __future__ import annotations

import enum

from caliper.core.models import FindingCategory


class DetectorCategory(enum.StrEnum):
    """Bug detector categories."""

    security = "security"
    reliability = "reliability"
    performance = "performance"
    configuration = "configuration"
    process = "process"
    documentation = "documentation"
    integration = "integration"


# Mapping from DetectorCategory to FindingCategory for conversion
CATEGORY_TO_FINDING: dict[DetectorCategory, FindingCategory] = {
    DetectorCategory.security: FindingCategory.security,
    DetectorCategory.reliability: FindingCategory.behavioral,
    DetectorCategory.performance: FindingCategory.behavioral,
    DetectorCategory.configuration: FindingCategory.behavioral,
    DetectorCategory.process: FindingCategory.code_smell,
    DetectorCategory.documentation: FindingCategory.code_smell,
    DetectorCategory.integration: FindingCategory.behavioral,
}
