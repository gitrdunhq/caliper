"""Detector for config merges that may drop telemetry (#262).
# tested-by: tests/unit/detectors/config/test_config_merge.py
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
class ConfigMergeDetector(BugDetector):
    """Detects configuration merges that may drop telemetry settings.

    Configuration issue: Merging configs with dict unpacking can silently drop
    keys like 'telemetry' that exist only in the base config.

    GitHub: #262
    """

    # Telemetry-related keys that should be preserved
    TELEMETRY_KEYS = (
        "telemetry",
        "metrics",
        "tracing",
        "observability",
        "monitoring",
        "logging",
        "log_level",
    )

    @property
    def detector_id(self) -> str:
        return "EED-013"

    @property
    def name(self) -> str:
        return "Config Merge Dropping Telemetry"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.configuration

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.low

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py", "*.yaml", "*.yml", "*.json")

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for config merge patterns that drop telemetry."""
        if file_path.suffix not in (".py", ".yaml", ".yml", ".json"):
            return []

        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find dict unpacking merge patterns: {**base, **override}
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                if self._is_dangerous_merge(node):
                    lineno = getattr(node, "lineno", 1)
                    if self._should_report_finding(file_path, lineno):
                        findings.append(
                            DetectorFinding(
                                detector_id=self.detector_id,
                                detector_name=self.name,
                                category=self.category,
                                severity=self.severity,
                                file_path=str(file_path),
                                line_number=lineno,
                                message="Dict merge may drop telemetry settings from base config",
                                issue_reference="#262",
                                fix_hint=(
                                    "Use collections.ChainMap or explicitly preserve telemetry keys"
                                ),
                            )
                        )

        # Find dict.update() calls that might drop keys
        for call, lineno in find_function_calls(tree, "*.update"):
            if self._is_update_on_config(call):
                if self._should_report_finding(file_path, lineno):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=lineno,
                            message="Config update may overwrite telemetry settings",
                            issue_reference="#262",
                            fix_hint="Merge carefully preserving telemetry keys or use ChainMap",
                        )
                    )

        return findings

    def _is_dangerous_merge(self, node: ast.Dict) -> bool:
        """Check if dict literal with unpacking is a dangerous merge."""
        # Look for {**base, **override} pattern
        has_unpacking = False
        for key in node.keys:
            if key is None:  # None key indicates dict unpacking (**dict)
                has_unpacking = True
                break

        if not has_unpacking:
            return False

        # Check if keys look like config-related
        for key in node.keys:
            if key is not None:
                key_str = self._get_key_name(key)
                if key_str and self._is_config_key(key_str):
                    return True

        return has_unpacking

    def _is_update_on_config(self, call: ast.Call) -> bool:
        """Check if update() is called on what looks like a config dict."""
        if isinstance(call.func, ast.Attribute):
            obj_name = self._get_object_name(call.func.value)
            if obj_name:
                config_indicators = ("config", "cfg", "settings", "opts", "options")
                return any(ind in obj_name.lower() for ind in config_indicators)
        return False

    def _get_object_name(self, node: ast.AST) -> str | None:
        """Extract object name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _get_key_name(self, node: ast.AST) -> str | None:
        """Extract key name from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _is_config_key(self, key: str) -> bool:
        """Check if key looks like a config key."""
        config_keys = (
            "debug",
            "env",
            "environment",
            "host",
            "port",
            "url",
            "endpoint",
            "timeout",
        )
        return any(k in key.lower() for k in config_keys)
