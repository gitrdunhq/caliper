"""ScannerPlugin adapter for DeterministicScanner (CAL-001..022).
# tested-by: tests/unit/test_deterministic_review_plugin.py

DeterministicScanner (``caliper.detectors.scanner``) satisfies the core
``ScannerPort`` used by the dependency-diff pipeline (``evaluate()``), but its
own docstring says it is meant for the ``review`` command (ADR-DET-006) — the
``ANALYZERS`` registry, a sibling tier ``detectors`` may not import directly.
This adapter lives in composition (which may import any tier) and bridges the
two: it wraps DeterministicScanner behind the ``ScannerPlugin`` contract and
registers itself with ``ANALYZERS`` so ``caliper review`` picks it up.
"""

from __future__ import annotations

from pathlib import Path

import structlog

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.repo_config import DetectorsConfig, load_repo_config
from caliper.detectors._registry import discover_detectors, get_all_detectors
from caliper.detectors.profiles import DEFAULT_PROFILE, resolve_detector_ids
from caliper.detectors.scanner import DeterministicScanner
from caliper.plugins import ANALYZERS

logger = structlog.get_logger(__name__)


def _select_detectors(repo_path: Path) -> tuple[list[str], list[str]]:
    """(detector ids, profiles used) from ``.caliper.yaml``; fail-open to the default profile."""
    try:
        cfg = load_repo_config(repo_path).detectors
    except (ValueError, OSError):
        cfg = DetectorsConfig()
    discover_detectors()
    known = {d.detector_id for d in get_all_detectors()}
    try:
        return (
            resolve_detector_ids(cfg.profiles, enable=cfg.enable, disable=cfg.disable, known=known),
            list(cfg.profiles),
        )
    except ValueError as exc:
        logger.warning(
            "detectors.profile_config_invalid", error=str(exc), msg="using default profile"
        )
        return (
            resolve_detector_ids([DEFAULT_PROFILE], enable=[], disable=[], known=known),
            [DEFAULT_PROFILE],
        )


class DeterministicPlugin(ScannerPlugin):
    """Runs the AST bug detectors (CAL-001..022) selected by ``detectors.profiles``."""

    @property
    def name(self) -> str:
        return "deterministic"

    @property
    def description(self) -> str:
        return "Deterministic AST bug detectors (CAL-001..022; default profile = general bugs)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return bool(files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        detector_ids, profiles = _select_detectors(repo_path)
        scan_result = DeterministicScanner(specific_detectors=detector_ids).scan(repo_path)
        findings = [
            {
                "id": f"{f.source_tool}:{f.file_path}:{f.line_number}",
                "severity": str(f.severity),
                "message": f.description,
                "file": f.file_path or "",
                "line": f.line_number or 0,
                "rule_id": f.source_tool,
                "category": str(f.category),
            }
            for f in scan_result.findings
        ]
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings), "profiles": profiles, "detectors": detector_ids},
        )


@ANALYZERS.register("deterministic")
def build_deterministic_plugin() -> DeterministicPlugin:
    return DeterministicPlugin()
