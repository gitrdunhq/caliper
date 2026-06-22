"""SecretStrDetector - Detects secrets using plain str instead of SecretStr.
# tested-by: tests/unit/detectors/test_deterministic_security_guards.py

GitHub issues: #227, #261
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.ast_utils import is_plain_type
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


@register_detector
class SecretStrDetector(BugDetector):
    """Detects secret-eligible fields using plain str instead of SecretStr.

    Security issue: Secrets stored as plain strings may be logged or
    exposed in tracebacks. Pydantic's SecretStr provides masking.

    GitHub: #227, #261
    """

    # Patterns that suggest secret/credential field names
    SECRET_PATTERNS = [
        r"api[_-]?key",
        r"credential",
        r"dsn",
        r"password",
        r"private[_-]?key",
        r"secret",
        r"token",
        r"auth[_-]?token",
    ]

    @property
    def detector_id(self) -> str:
        return "EED-004"

    @property
    def name(self) -> str:
        return "Secret Should Use SecretStr"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*config*.py", "*settings*.py", "*publisher*.py", "*.py")

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for secret fields using plain str."""

        content = file_path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []

        for node in ast.walk(tree):
            # Check annotated assignments: api_key: str
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and self._is_secret_name(node.target.id)
                and is_plain_type(node.annotation, "str")
            ):
                var_name = node.target.id
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        message=f"'{var_name}' should be SecretStr instead of str",
                        snippet=self._get_line(content, node.lineno),
                        issue_reference="#227, #261",
                        fix_hint=f"Change '{var_name}: str' to '{var_name}: SecretStr'",
                    )
                )

            # Bare assignment of a string literal to a secret-named var: api_key = "..."
            # (a hardcoded secret stored as plain str — was a false negative).
            elif (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and self._is_secret_name(node.targets[0].id)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                var_name = node.targets[0].id
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        message=f"'{var_name}' should be SecretStr instead of str",
                        snippet=self._get_line(content, node.lineno),
                        issue_reference="#227, #261",
                        fix_hint=f"Wrap '{var_name}' in SecretStr instead of a plain str literal",
                    )
                )

        return findings

    def _is_secret_name(self, name: str) -> bool:
        """Check if variable name suggests it holds a secret."""
        name_lower = name.lower()
        return any(re.search(pattern, name_lower) for pattern in self.SECRET_PATTERNS)

    def _get_line(self, content: str, lineno: int) -> str | None:
        """Get specific line from content."""
        lines = content.split("\n")
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return None
