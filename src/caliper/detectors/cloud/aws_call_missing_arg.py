"""Detector for AWS API calls missing a required-in-practice argument (#499).
# tested-by: tests/unit/detectors/cloud/test_aws_call_missing_arg.py
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
class AwsCallMissingArgDetector(BugDetector):
    """Detects boto3/botocore calls that omit an argument the API accepts as optional but
    which is required in practice.

    Reliability issue: the SDK signature lets the call through, so nothing fails
    at call time - the consequence surfaces later (recovery points that never
    expire, log groups that retain forever, objects written unencrypted).

    GitHub: #499
    """

    # Module import gate: only boto3/botocore files are considered.
    AWS_IMPORT_PATTERNS = ("boto3", "boto3.*", "botocore", "botocore.*")

    # Method name -> keyword arguments that are required in practice.
    REQUIRED_KWARGS: dict[str, tuple[str, ...]] = {
        "start_backup_job": ("Lifecycle",),
        "start_copy_job": ("Lifecycle",),
        "put_object": ("ServerSideEncryption",),
    }

    # Consequence text per (method, argument) for the finding message.
    CONSEQUENCES: dict[tuple[str, str], str] = {
        ("start_backup_job", "Lifecycle"): "the recovery point never expires",
        ("start_copy_job", "Lifecycle"): "the copied recovery point never expires",
        ("put_object", "ServerSideEncryption"): "the object is written unencrypted",
    }

    # Method -> companion call whose presence anywhere in the module silences it.
    MODULE_SILENCERS: dict[str, str] = {
        "put_object": "put_bucket_encryption",
        "create_log_group": "put_retention_policy",
    }

    LOG_GROUP_METHOD = "create_log_group"
    LOG_GROUP_COMPANION = "put_retention_policy"

    @property
    def detector_id(self) -> str:
        return "CAL-025"

    @property
    def name(self) -> str:
        return "AWS API Call Missing Required-In-Practice Argument"

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
        """Analyze file for AWS calls missing a required-in-practice argument.

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

        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        ]
        called_methods = {call.func.attr for call in calls}

        findings: list[DetectorFinding] = []
        for call in calls:
            method = call.func.attr
            silencer = self.MODULE_SILENCERS.get(method)
            if silencer is not None and silencer in called_methods:
                continue
            if self._has_kwargs_splat(call):
                continue

            if method == self.LOG_GROUP_METHOD:
                message = (
                    f"{method}() with no {self.LOG_GROUP_COMPANION}() call in the module - "
                    "the log group retains events forever"
                )
                fix_hint = (
                    f"Call {self.LOG_GROUP_COMPANION}(logGroupName=..., retentionInDays=...) "
                    f"after {method}()"
                )
                findings.extend(self._finding(file_path, call.lineno, message, fix_hint))
                continue

            for argument in self.REQUIRED_KWARGS.get(method, ()):
                if self._has_keyword(call, argument):
                    continue
                consequence = self.CONSEQUENCES.get(
                    (method, argument), "the call silently misbehaves"
                )
                message = f"{method}() is missing {argument} - {consequence}"
                fix_hint = f"Pass {argument}=... to {method}()"
                findings.extend(self._finding(file_path, call.lineno, message, fix_hint))

        findings.sort(key=lambda f: (f.line_number, f.message))
        return findings

    def _finding(
        self, file_path: Path, lineno: int, message: str, fix_hint: str
    ) -> list[DetectorFinding]:
        """Build a finding for ``lineno`` unless a ``# noqa`` on that line suppresses it."""
        if not self._should_report_finding(file_path, lineno):
            return []
        return [
            DetectorFinding(
                detector_id=self.detector_id,
                detector_name=self.name,
                category=self.category,
                severity=self.severity,
                file_path=str(file_path),
                line_number=lineno,
                message=message,
                issue_reference="#499",
                fix_hint=fix_hint,
            )
        ]

    def _imports_aws_sdk(self, tree: ast.AST) -> bool:
        """True when the module imports boto3 or botocore (any form)."""
        return any(has_import(tree, pattern) for pattern in self.AWS_IMPORT_PATTERNS)

    @staticmethod
    def _has_kwargs_splat(call: ast.Call) -> bool:
        """True when the call carries ``**kwargs`` - the argument set is unknowable."""
        return any(keyword.arg is None for keyword in call.keywords)

    @staticmethod
    def _has_keyword(call: ast.Call, argument: str) -> bool:
        """True when ``argument`` is passed explicitly as a keyword."""
        return any(keyword.arg == argument for keyword in call.keywords)
