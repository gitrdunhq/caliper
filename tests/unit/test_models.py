"""Tests for caliper.core.models — core data models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError


class TestEnumValidation:
    """Enum fields reject invalid string values."""

    def test_operating_mode_rejects_invalid(self) -> None:
        from caliper.core.models import OperatingMode

        with pytest.raises(ValueError):
            OperatingMode("enforce")

    def test_operating_mode_accepts_valid(self) -> None:
        from caliper.core.models import OperatingMode

        assert OperatingMode("monitor").value == "monitor"
        assert OperatingMode("advise").value == "advise"

    def test_scan_result_status_rejects_invalid(self) -> None:
        from caliper.core.models import ScanResultStatus

        with pytest.raises(ValueError):
            ScanResultStatus("unknown")

    def test_decision_verdict_accepts_all_valid(self) -> None:
        from caliper.core.models import DecisionVerdict

        valid = ["approve", "reject", "needs_review", "approve_with_constraints"]
        for v in valid:
            assert DecisionVerdict(v).value == v

    def test_finding_severity_rejects_invalid(self) -> None:
        from caliper.core.models import FindingSeverity

        with pytest.raises(ValueError):
            FindingSeverity("extreme")

    def test_finding_category_accepts_all_valid(self) -> None:
        from caliper.core.models import FindingCategory

        valid = [
            "vulnerability",
            "license",
            "malicious",
            "malware",
            "age",
            "transitive_count",
            "behavioral",
            "code_smell",
            "security",
        ]
        for v in valid:
            assert FindingCategory(v).value == v


class TestNormalizeSeverity:
    """normalize_severity handles upstream tool severity formats."""

    def test_standard_values_pass_through(self) -> None:
        from caliper.core.models import FindingSeverity, normalize_severity

        for val in ("critical", "high", "medium", "low", "info"):
            assert normalize_severity(val) == FindingSeverity(val)

    def test_semgrep_error_maps_to_critical(self) -> None:
        from caliper.core.models import FindingSeverity, normalize_severity

        assert normalize_severity("ERROR") == FindingSeverity.critical

    def test_semgrep_warning_maps_to_medium(self) -> None:
        from caliper.core.models import FindingSeverity, normalize_severity

        assert normalize_severity("WARNING") == FindingSeverity.medium

    def test_uppercase_variants_normalized(self) -> None:
        from caliper.core.models import FindingSeverity, normalize_severity

        assert normalize_severity("CRITICAL") == FindingSeverity.critical
        assert normalize_severity("HIGH") == FindingSeverity.high
        assert normalize_severity("MEDIUM") == FindingSeverity.medium
        assert normalize_severity("LOW") == FindingSeverity.low
        assert normalize_severity("INFO") == FindingSeverity.info

    def test_moderate_maps_to_medium(self) -> None:
        from caliper.core.models import FindingSeverity, normalize_severity

        assert normalize_severity("moderate") == FindingSeverity.medium
        assert normalize_severity("MODERATE") == FindingSeverity.medium

    def test_note_maps_to_info(self) -> None:
        from caliper.core.models import FindingSeverity, normalize_severity

        assert normalize_severity("note") == FindingSeverity.info
        assert normalize_severity("NOTE") == FindingSeverity.info

    def test_unknown_value_falls_back_to_info(self) -> None:
        from caliper.core.models import FindingSeverity, normalize_severity

        assert normalize_severity("bananas") == FindingSeverity.info
        assert normalize_severity("") == FindingSeverity.info

    def test_request_type_rejects_invalid(self) -> None:
        from caliper.core.models import RequestType

        with pytest.raises(ValueError):
            RequestType("delete")


class TestFinding:
    """Finding model validation and serialization."""

    @staticmethod
    def _make_finding(**overrides: object) -> dict:
        defaults = {
            "severity": "high",
            "category": "vulnerability",
            "description": "CVE-2024-1234 in requests",
            "source_tool": "osv-scanner",
            "package_name": "requests",
            "version": "2.31.0",
        }
        defaults.update(overrides)
        return defaults

    def test_finding_round_trip_json(self) -> None:
        from caliper.core.models import Finding

        data = self._make_finding(advisory_id="CVE-2024-1234", confidence=0.95)
        finding = Finding.model_validate(data)
        dumped = finding.model_dump(mode="json")
        restored = Finding.model_validate(dumped)

        assert restored.severity.value == "high"
        assert restored.category.value == "vulnerability"
        assert restored.description == "CVE-2024-1234 in requests"
        assert restored.source_tool == "osv-scanner"
        assert restored.advisory_id == "CVE-2024-1234"
        assert restored.confidence == 0.95

    def test_finding_optional_fields_default_none(self) -> None:
        from caliper.core.models import Finding

        finding = Finding.model_validate(self._make_finding())
        assert finding.advisory_id is None
        assert finding.advisory_url is None
        assert finding.license_id is None
        assert finding.confidence is None

    def test_finding_rejects_invalid_severity(self) -> None:
        from caliper.core.models import Finding

        with pytest.raises(ValidationError):
            Finding.model_validate(self._make_finding(severity="extreme"))


class TestScanResult:
    """ScanResult model validation and serialization."""

    def test_scan_result_defaults(self) -> None:
        from caliper.core.models import ScanResult

        result = ScanResult.model_validate(
            {
                "tool_name": "trivy",
                "status": "success",
                "duration_seconds": 12.5,
            }
        )
        assert result.findings == []
        assert result.raw_output_path is None
        assert result.message is None

    def test_scan_result_round_trip(self) -> None:
        from caliper.core.models import ScanResult

        data = {
            "tool_name": "trivy",
            "status": "success",
            "findings": [
                {
                    "severity": "critical",
                    "category": "vulnerability",
                    "description": "RCE in lib",
                    "source_tool": "trivy",
                    "package_name": "lib",
                    "version": "1.0.0",
                }
            ],
            "raw_output_path": "/evidence/trivy.json",
            "duration_seconds": 45.3,
        }
        result = ScanResult.model_validate(data)
        dumped = result.model_dump(mode="json")
        restored = ScanResult.model_validate(dumped)

        assert restored.tool_name == "trivy"
        assert restored.status.value == "success"
        assert len(restored.findings) == 1
        assert restored.findings[0].severity.value == "critical"
        assert restored.duration_seconds == 45.3


class TestReviewRequest:
    """ReviewRequest model with UUID auto-generation and datetime."""

    @staticmethod
    def _make_request(**overrides: object) -> dict:
        defaults = {
            "request_type": "new_package",
            "ecosystem": "pypi",
            "package_name": "requests",
            "target_version": "2.32.0",
            "team": "platform",
            "operating_mode": "monitor",
        }
        defaults.update(overrides)
        return defaults

    def test_uuid_auto_generated(self) -> None:
        from caliper.core.models import ReviewRequest

        req = ReviewRequest.model_validate(self._make_request())
        assert isinstance(req.request_id, uuid.UUID)

    def test_created_at_auto_generated(self) -> None:
        from caliper.core.models import ReviewRequest

        req = ReviewRequest.model_validate(self._make_request())
        assert isinstance(req.created_at, datetime)
        # Should be recent (within last 10 seconds)
        delta = datetime.now(UTC) - req.created_at
        assert delta.total_seconds() < 10

    def test_default_scope_is_runtime(self) -> None:
        from caliper.core.models import ReviewRequest

        req = ReviewRequest.model_validate(self._make_request())
        assert req.scope == "runtime"

    def test_optional_fields_default_none(self) -> None:
        from caliper.core.models import ReviewRequest

        req = ReviewRequest.model_validate(self._make_request())
        assert req.current_version is None
        assert req.pr_url is None
        assert req.pr_number is None
        assert req.repo_name is None
        assert req.commit_sha is None
        assert req.use_case is None

    def test_round_trip_json(self) -> None:
        from caliper.core.models import ReviewRequest

        req = ReviewRequest.model_validate(
            self._make_request(
                pr_url="https://github.com/org/repo/pull/42",
                pr_number=42,
                current_version="2.31.0",
            )
        )
        dumped = req.model_dump(mode="json")
        restored = ReviewRequest.model_validate(dumped)

        assert restored.request_id == req.request_id
        assert restored.package_name == "requests"
        assert restored.pr_number == 42
        assert restored.operating_mode.value == "monitor"


class TestPolicyEvaluation:
    """PolicyEvaluation model."""

    def test_policy_evaluation_defaults(self) -> None:
        from caliper.core.models import PolicyEvaluation

        pe = PolicyEvaluation.model_validate(
            {
                "decision": "approve",
                "triggered_rules": ["license-check"],
                "policy_bundle_version": "1.2.0",
            }
        )
        assert pe.constraints == []
        assert pe.note is None

    def test_policy_evaluation_round_trip(self) -> None:
        from caliper.core.models import PolicyEvaluation

        data = {
            "decision": "approve_with_constraints",
            "triggered_rules": ["cve-check", "license-check"],
            "constraints": ["Requires security team sign-off"],
            "policy_bundle_version": "2.0.0",
            "note": "Approved conditionally",
        }
        pe = PolicyEvaluation.model_validate(data)
        dumped = pe.model_dump(mode="json")
        restored = PolicyEvaluation.model_validate(dumped)

        assert restored.decision.value == "approve_with_constraints"
        assert len(restored.triggered_rules) == 2
        assert restored.constraints == ["Requires security team sign-off"]


class TestReviewDecision:
    """ReviewDecision — the aggregate root with business logic."""

    @staticmethod
    def _make_decision(
        operating_mode: str = "monitor",
        verdict: str = "reject",
    ) -> dict:
        return {
            "request": {
                "request_type": "new_package",
                "ecosystem": "pypi",
                "package_name": "evil-package",
                "target_version": "0.1.0",
                "team": "platform",
                "operating_mode": operating_mode,
            },
            "decision": verdict,
            "findings": [
                {
                    "severity": "critical",
                    "category": "malicious",
                    "description": "Known malware package",
                    "source_tool": "osv-scanner",
                    "package_name": "evil-package",
                    "version": "0.1.0",
                }
            ],
            "scan_results": [
                {
                    "tool_name": "osv-scanner",
                    "status": "success",
                    "duration_seconds": 5.0,
                }
            ],
            "policy_evaluation": {
                "decision": verdict,
                "triggered_rules": ["malware-block"],
                "policy_bundle_version": "1.0.0",
            },
            "pipeline_duration_seconds": 25.0,
        }

    def test_uuid_auto_generated(self) -> None:
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(self._make_decision())
        assert isinstance(decision.decision_id, uuid.UUID)

    def test_created_at_auto_generated(self) -> None:
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(self._make_decision())
        assert isinstance(decision.created_at, datetime)

    def test_monitor_mode_never_comments_or_marks_unstable(self) -> None:
        """In monitor mode, the system logs only — no PR comment, no build unstable."""
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(
            self._make_decision(operating_mode="monitor", verdict="reject")
        )
        assert decision.should_comment is False
        assert decision.should_mark_unstable is False

    def test_advise_mode_reject_comments_and_marks_unstable(self) -> None:
        """In advise mode with a reject verdict, both comment and mark unstable."""
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(
            self._make_decision(operating_mode="advise", verdict="reject")
        )
        assert decision.should_comment is True
        assert decision.should_mark_unstable is True

    def test_advise_mode_approve_no_comment_no_unstable(self) -> None:
        """In advise mode with approve, no comment or unstable marking needed."""
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(
            self._make_decision(operating_mode="advise", verdict="approve")
        )
        assert decision.should_comment is False
        assert decision.should_mark_unstable is False

    def test_advise_mode_needs_review_comments_and_marks_unstable(self) -> None:
        """In advise mode with needs_review, comment and mark unstable."""
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(
            self._make_decision(operating_mode="advise", verdict="needs_review")
        )
        assert decision.should_comment is True
        assert decision.should_mark_unstable is True

    def test_advise_mode_approve_with_constraints_comments_no_unstable(self) -> None:
        """In advise mode with approve_with_constraints, comment but don't mark unstable."""
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(
            self._make_decision(operating_mode="advise", verdict="approve_with_constraints")
        )
        assert decision.should_comment is True
        assert decision.should_mark_unstable is False

    def test_round_trip_json(self) -> None:
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(self._make_decision())
        dumped = decision.model_dump(mode="json")
        restored = ReviewDecision.model_validate(dumped)

        assert restored.decision_id == decision.decision_id
        assert restored.decision.value == "reject"
        assert len(restored.findings) == 1
        assert restored.pipeline_duration_seconds == 25.0

    def test_default_optional_fields(self) -> None:
        from caliper.core.models import ReviewDecision

        decision = ReviewDecision.model_validate(self._make_decision())
        assert decision.evidence_bundle_path is None
        assert decision.memo_text is None


class TestBypassRecord:
    """BypassRecord model."""

    def test_bypass_record_auto_fields(self) -> None:
        from caliper.core.models import BypassRecord

        record = BypassRecord.model_validate(
            {
                "request_id": str(uuid.uuid4()),
                "bypass_type": "security_exception",
                "invoked_by": "alice@example.com",
                "reason": "Approved by security team for internal-only use",
            }
        )
        assert isinstance(record.bypass_id, uuid.UUID)
        assert isinstance(record.timestamp, datetime)

    def test_bypass_record_round_trip(self) -> None:
        from caliper.core.models import BypassRecord

        req_id = uuid.uuid4()
        record = BypassRecord.model_validate(
            {
                "request_id": str(req_id),
                "bypass_type": "manager_override",
                "invoked_by": "bob@example.com",
                "reason": "Needed for demo deadline",
            }
        )
        dumped = record.model_dump(mode="json")
        restored = BypassRecord.model_validate(dumped)

        assert restored.bypass_id == record.bypass_id
        assert restored.request_id == req_id
        assert restored.bypass_type == "manager_override"
        assert restored.invoked_by == "bob@example.com"
