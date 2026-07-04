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

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.detectors.scanner import DeterministicScanner
from caliper.plugins import ANALYZERS


class DeterministicPlugin(ScannerPlugin):
    """Runs all 22 AST-based bug detectors (CAL-001..022) as a review plugin."""

    @property
    def name(self) -> str:
        return "deterministic"

    @property
    def description(self) -> str:
        return "Deterministic AST bug detectors (CAL-001..022)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return bool(files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        scan_result = DeterministicScanner().scan(repo_path)
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
            summary={"total": len(findings)},
        )


@ANALYZERS.register("deterministic")
def build_deterministic_plugin() -> DeterministicPlugin:
    return DeterministicPlugin()
