"""JWTAudienceDetector - Detects JWT tokens without audience claim.
# tested-by: tests/unit/detectors/test_deterministic_jwt_guards.py

GitHub issues: #175, #209
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import find_function_calls, parse_file_safe
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class JWTAudienceDetector(BugDetector):
    """Detects jwt.encode() calls without 'aud' claim in payload.

    Security issue: JWTs without an audience claim are vulnerable to
    token replay attacks across different services.

    GitHub: #175, #209
    """

    @property
    def detector_id(self) -> str:
        return "CAL-001"

    @property
    def name(self) -> str:
        return "JWT Missing Audience Claim"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*auth*.py", "*jwt*.py", "*.py")

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for jwt.encode() calls without 'aud' claim."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find all jwt.encode calls
        for call, lineno in find_function_calls(tree, "jwt.encode"):
            if not self._has_audience_claim(call):
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=lineno,
                        message="jwt.encode() missing 'aud' claim in payload",
                        issue_reference="#175, #209",
                        fix_hint="Add 'aud': '<audience>' to payload dict",
                    )
                )

        return findings

    def _has_audience_claim(self, call_node) -> bool:
        """Check if jwt.encode call has 'aud' in payload dict.

        Args:
            call_node: ast.Call node for jwt.encode()

        Returns:
            True if 'aud' key is present in payload dict
        """
        import ast

        # jwt.encode(payload, key, ...) - first arg is payload
        if not call_node.args:
            return False

        payload = call_node.args[0]

        # Check if payload is a dict literal
        if isinstance(payload, ast.Dict):
            # Check if 'aud' key exists
            for key in payload.keys:
                if isinstance(key, ast.Constant) and key.value == "aud":
                    return True
            return False

        # Payload is a variable - can't analyze statically
        # Return True to avoid false positives (we only flag known issues)
        return True
