"""Detector for high cardinality metric labels (#166).
# tested-by: tests/unit/detectors/metrics/test_high_cardinality.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors.ast_utils import (
    find_function_calls,
    parse_file_safe,
)
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector
from eedom.detectors.registry import DetectorRegistry


@DetectorRegistry.register
class HighCardinalityMetricsDetector(BugDetector):
    """Detects metric labels with high cardinality values.

    Metrics issue: Using high-cardinality values (user_id, request_id, email,
    timestamp) as metric labels can cause memory exhaustion and slow queries.

    GitHub: #166
    """

    # High cardinality label names to detect
    HIGH_CARDINALITY_LABELS = (
        "user_id",
        "userid",
        "request_id",
        "requestid",
        "session_id",
        "sessionid",
        "email",
        "timestamp",
        "ts",
        "uuid",
        "id",
        "ip",
        "ip_address",
        "trace_id",
        "span_id",
    )

    # Low cardinality labels that are safe
    LOW_CARDINALITY_LABELS = (
        "method",
        "status",
        "endpoint",
        "service",
        "region",
        "version",
        "environment",
        "env",
    )

    @property
    def detector_id(self) -> str:
        return "EED-015"

    @property
    def name(self) -> str:
        return "High Cardinality Metric Labels"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for high cardinality metric labels."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find Counter, Histogram, Gauge instantiations with labels
        for metric_type in ("Counter", "Histogram", "Gauge", "Summary"):
            for call, lineno in find_function_calls(tree, f"*{metric_type}"):
                high_card_labels = self._get_high_cardinality_labels(call)

                for label in high_card_labels:
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message=(
                                    f"Metric uses high-cardinality label '{label}' - can cause memory exhaustion"
                                ),
                                issue_reference="#166",
                                fix_hint=(
                                    f"Remove '{label}' from labels or use low-cardinality alternative"
                                ),
                            )
                        )

        # Check for .labels() calls with high cardinality values
        for call, lineno in find_function_calls(tree, "*.labels"):
            high_card_labels = self._get_high_cardinality_label_kwargs(call)

            for label in high_card_labels:
                if self._should_report_finding(file_path, lineno):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=lineno,
                            message=f"Metric observation uses high-cardinality label '{label}'",
                            issue_reference="#166",
                            fix_hint=f"Do not use '{label}' as a label - consider logging instead",
                        )
                    )

        return findings

    def _get_high_cardinality_labels(self, call: ast.Call) -> list[str]:
        """Get high cardinality label names from metric constructor."""
        high_card_labels = []

        for keyword in call.keywords:
            if keyword.arg == "labelnames" or keyword.arg == "labels":
                if isinstance(keyword.value, (ast.List, ast.Tuple)):
                    for elt in keyword.value.elts:
                        label_name = self._get_string_content(elt)
                        if label_name and self._is_high_cardinality(label_name):
                            high_card_labels.append(label_name)

        return high_card_labels

    def _get_high_cardinality_label_kwargs(self, call: ast.Call) -> list[str]:
        """Get high cardinality label names from .labels() call."""
        high_card_labels = []

        for keyword in call.keywords:
            if self._is_high_cardinality(keyword.arg):
                high_card_labels.append(keyword.arg)

        return high_card_labels

    def _is_high_cardinality(self, label: str) -> bool:
        """Check if label name indicates high cardinality."""
        label_lower = label.lower()

        # First check if it's explicitly low cardinality
        for low_card in self.LOW_CARDINALITY_LABELS:
            if low_card in label_lower:
                return False

        # Check for high cardinality patterns
        for high_card in self.HIGH_CARDINALITY_LABELS:
            if high_card in label_lower:
                return True

        return False

    def _get_string_content(self, node: ast.AST) -> str | None:
        """Extract string content from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
