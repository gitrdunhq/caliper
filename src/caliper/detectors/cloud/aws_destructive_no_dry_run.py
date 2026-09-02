"""Detector for destructive AWS calls with no dry-run guard (#499).
# tested-by: tests/unit/detectors/cloud/test_aws_destructive_no_dry_run.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import has_import, parse_file_safe
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class AwsDestructiveNoDryRunDetector(BugDetector):
    """Detects destructive boto3/botocore method calls in modules with no dry-run guard.

    Reliability issue: a cleanup script whose first execution deletes,
    terminates, deregisters, or purges real resources has no preview path.
    A module-wide ``DRY_RUN`` switch (env var, flag, or ``DryRun=`` keyword)
    is the conventional guard; its absence anywhere in the module is the signal.

    GitHub: #499
    """

    # Module import gate: only boto3/botocore files are considered.
    AWS_IMPORT_PATTERNS = ("boto3", "boto3.*", "botocore", "botocore.*")

    # Method-name prefixes that are destructive when they start the attribute.
    DESTRUCTIVE_PREFIXES = ("delete_", "terminate_", "deregister_", "purge_")

    # Exact method names that are destructive without a shared prefix.
    DESTRUCTIVE_NAMES = frozenset({"remove_tags", "disassociate_address"})

    # Any identifier or string containing one of these (lowercased) is a guard.
    GUARD_TOKENS = ("dry_run", "dryrun", "dry-run")

    @property
    def detector_id(self) -> str:
        return "CAL-024"

    @property
    def name(self) -> str:
        return "Destructive AWS Call Without Dry-Run Guard"

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
        """Analyze file for destructive AWS calls with no dry-run guard.

        Fail-open: any parse, decode, or IO failure yields no findings.
        """
        try:
            return self._detect(file_path)
        except Exception:  # noqa: BLE001 - fail-open by design
            return []

    def _detect(self, file_path: Path) -> list[DetectorFinding]:
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        if not self._imports_aws_sdk(tree):
            return []

        if self._module_has_dry_run_guard(tree):
            return []

        findings: list[DetectorFinding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            method = node.func.attr
            if not self._is_destructive(method):
                continue
            lineno = node.lineno
            if not self._should_report_finding(file_path, lineno):
                continue
            findings.append(
                DetectorFinding(
                    detector_id=self.detector_id,
                    detector_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    file_path=str(file_path),
                    line_number=lineno,
                    message=(
                        f"{method}() has no dry-run guard - the first run will "
                        "delete for real with no preview path"
                    ),
                    issue_reference="#499",
                    fix_hint="Add a DRY_RUN env switch that logs the target and skips the call",
                )
            )

        findings.sort(key=lambda f: (f.line_number, f.message))
        return findings

    def _imports_aws_sdk(self, tree: ast.AST) -> bool:
        """True when the module imports boto3 or botocore (any form)."""
        return any(has_import(tree, pattern) for pattern in self.AWS_IMPORT_PATTERNS)

    def _is_destructive(self, method: str) -> bool:
        """True when the attribute name is a destructive AWS method."""
        if method in self.DESTRUCTIVE_NAMES:
            return True
        return method.startswith(self.DESTRUCTIVE_PREFIXES)

    def _module_has_dry_run_guard(self, tree: ast.AST) -> bool:
        """True when any identifier or string in the module mentions dry-run.

        Position-independent: a guard anywhere in the module silences every
        finding, since a module-wide switch is the conventional shape.
        """
        for node in ast.walk(tree):
            for text in self._identifier_texts(node):
                lowered = text.lower()
                if any(token in lowered for token in self.GUARD_TOKENS):
                    return True
        return False

    @staticmethod
    def _identifier_texts(node: ast.AST) -> tuple[str, ...]:
        """Extract every name-like string a node carries."""
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            return (node.attr,)
        if isinstance(node, ast.arg):
            return (node.arg,)
        if isinstance(node, ast.keyword) and node.arg is not None:
            return (node.arg,)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return (node.value,)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return (node.name,)
        return ()
