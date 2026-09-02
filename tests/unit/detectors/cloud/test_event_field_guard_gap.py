"""Tests for the event-field-guard-gap detector (CAL-026, #499).
# tested-by: tests/unit/detectors/cloud/test_event_field_guard_gap.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.event_field_guard_gap import (
    EventFieldGuardGapDetector,
)

DETECTOR_ID = "CAL-026"
DETECTOR_NAME = "Event Field Guard Omits Field Passed To AWS Call"


def _write(tmp_path: Path, code: str, name: str = "handler.py") -> Path:
    """Write dedented ``code`` so that its first source line is line 1."""
    target = tmp_path / name
    target.write_text(textwrap.dedent(code).lstrip("\n"))
    return target


@pytest.fixture
def detector() -> EventFieldGuardGapDetector:
    return EventFieldGuardGapDetector()


# The real-world shape from the #499 review: ``backup_vault_name`` is read from
# the event, left out of the guard, and then passed to ``start_backup_job``.
# ``backup_vault_name = detail.get(...)`` sits on line 10.
GUARD_GAP_CODE = """
    import boto3

    backup = boto3.client("backup")


    def lambda_handler(event, context):
        detail = event.get("detail", {})
        resource_arn = detail.get("resourceArn")
        job_id = detail.get("backupJobId")
        backup_vault_name = detail.get("backupVaultName")
        if not all([resource_arn, job_id]):
            return {"status": "skipped"}
        backup.start_backup_job(
            BackupVaultName=backup_vault_name,
            ResourceArn=resource_arn,
            IdempotencyToken=job_id,
        )
    """


class TestMetadata:
    """Identity contract for CAL-026."""

    def test_detector_id(self, detector):
        assert detector.detector_id == DETECTOR_ID

    def test_name(self, detector):
        assert detector.name == DETECTOR_NAME

    def test_category_is_reliability(self, detector):
        assert detector.category == DetectorCategory.reliability

    def test_severity_is_medium(self, detector):
        assert detector.severity == FindingSeverity.medium

    def test_targets_python_only(self, detector):
        assert detector.target_files == ("*.py",)


class TestGuardGap:
    """A ``.get()`` variable omitted from the guard and passed to a call fires."""

    def test_omitted_keyword_value_fires_at_assignment_line(self, detector, tmp_path):
        path = _write(tmp_path, GUARD_GAP_CODE)

        findings = detector.detect(path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == DETECTOR_ID
        assert finding.detector_name == DETECTOR_NAME
        assert finding.category == DetectorCategory.reliability
        assert finding.severity == FindingSeverity.medium
        assert finding.file_path == str(path)
        assert finding.line_number == 10
        assert finding.issue_reference == "#499"

    def test_guard_written_as_tuple_fires(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                job_id = detail.get("backupJobId")
                backup_vault_name = detail.get("backupVaultName")
                if not all((resource_arn, job_id)):
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    ResourceArn=resource_arn,
                    IdempotencyToken=job_id,
                )
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 10

    def test_omitted_positional_argument_fires(self, detector, tmp_path):
        code = """
            import boto3

            sns = boto3.client("sns")


            def handler(event, context):
                topic_arn = event.get("topicArn")
                message = event.get("message")
                if not all([topic_arn]):
                    return None
                sns.publish(topic_arn, message)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 8
        assert "message" in findings[0].message
        assert "publish" in findings[0].message

    def test_two_omitted_variables_fire_in_line_order(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")
                job_id = detail.get("backupJobId")
                iam_role_arn = detail.get("iamRoleArn")
                if not all([resource_arn, job_id]):
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    ResourceArn=resource_arn,
                    IamRoleArn=iam_role_arn,
                    IdempotencyToken=job_id,
                )
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [9, 11]
        assert {f.detector_id for f in findings} == {DETECTOR_ID}
        assert "backup_vault_name" in findings[0].message
        assert "iam_role_arn" in findings[1].message

    def test_message_names_variable_method_and_guard(self, detector, tmp_path):
        path = _write(tmp_path, GUARD_GAP_CODE)

        findings = detector.detect(path)

        assert len(findings) == 1
        message = findings[0].message
        assert "backup_vault_name" in message
        assert "start_backup_job" in message
        assert "guard" in message.lower()
        assert "ParamValidationError" in message

    def test_fix_hint_names_variable_and_all_guard(self, detector, tmp_path):
        path = _write(tmp_path, GUARD_GAP_CODE)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].fix_hint == "Add `backup_vault_name` to the all([...]) guard"

    def test_from_botocore_import_counts_as_gate(self, detector, tmp_path):
        code = """
            from botocore.exceptions import ClientError


            def handler(event, context, client):
                queue_url = event.get("queueUrl")
                body = event.get("body")
                if not all([queue_url]):
                    return None
                try:
                    client.send_message(QueueUrl=queue_url, MessageBody=body)
                except ClientError:
                    raise
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 6


class TestNegativeCases:
    """Spec-listed cases that must produce no finding."""

    def test_every_get_variable_in_guard(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                job_id = detail.get("backupJobId")
                backup_vault_name = detail.get("backupVaultName")
                if not all([resource_arn, job_id, backup_vault_name]):
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    ResourceArn=resource_arn,
                    IdempotencyToken=job_id,
                )
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_omitted_variable_never_passed_to_a_call(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                job_id = detail.get("backupJobId")
                backup_vault_name = detail.get("backupVaultName")
                if not all([resource_arn, job_id]):
                    return {"status": "skipped"}
                print(backup_vault_name)
                backup.start_backup_job(
                    ResourceArn=resource_arn,
                    IdempotencyToken=job_id,
                )
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_omitted_variable_only_passed_to_a_get_call(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                vault_key = detail.get("vaultKey")
                if not all([resource_arn]):
                    return {"status": "skipped"}
                vault_name = VAULTS.get(vault_key)
                backup.start_backup_job(ResourceArn=resource_arn)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_no_all_guard_in_function(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")
                if not resource_arn:
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    ResourceArn=resource_arn,
                )
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_guard_and_call_in_different_functions(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def validate(event):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")
                if not all([resource_arn]):
                    return None
                return detail


            def submit(event):
                detail = event.get("detail", {})
                backup_vault_name = detail.get("backupVaultName")
                backup.start_backup_job(BackupVaultName=backup_vault_name)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_non_boto3_file_is_ignored(self, detector, tmp_path):
        code = """
            import requests


            def handler(event, context):
                url = event.get("url")
                token = event.get("token")
                if not all([url]):
                    return None
                requests.post(url, headers=token)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_variable_passed_only_before_the_guard(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")
            logs = boto3.client("logs")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")
                logs.put_log_events(logEvents=backup_vault_name)
                if not all([resource_arn]):
                    return {"status": "skipped"}
                backup.start_backup_job(ResourceArn=resource_arn)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_empty_boto3_file_has_no_findings(self, detector, tmp_path):
        path = _write(tmp_path, "import boto3\n")

        assert detector.detect(path) == []


class TestNoqaSuppression:
    """``# noqa`` on the assignment line silences the detector."""

    def test_noqa_with_detector_code_suppresses(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")  # noqa: CAL-026
                if not all([resource_arn]):
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    ResourceArn=resource_arn,
                )
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_noqa_suppresses(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")  # noqa
                if not all([resource_arn]):
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    ResourceArn=resource_arn,
                )
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")  # noqa: CAL-012
                if not all([resource_arn]):
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    ResourceArn=resource_arn,
                )
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 9

    def test_noqa_only_suppresses_its_own_line(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def lambda_handler(event, context):
                detail = event.get("detail", {})
                resource_arn = detail.get("resourceArn")
                backup_vault_name = detail.get("backupVaultName")  # noqa: CAL-026
                iam_role_arn = detail.get("iamRoleArn")
                if not all([resource_arn]):
                    return {"status": "skipped"}
                backup.start_backup_job(
                    BackupVaultName=backup_vault_name,
                    IamRoleArn=iam_role_arn,
                    ResourceArn=resource_arn,
                )
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [10]


class TestProperties:
    """Formal properties (DPS-12)."""

    def test_determinism_same_file_same_findings(self, detector, tmp_path):
        """Determinism / INVARIANT: same input -> identical findings on repeat."""
        path = _write(tmp_path, GUARD_GAP_CODE)

        first = detector.detect(path)
        second = detector.detect(path)

        assert len(first) == 1
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_unparseable_file(self, detector, tmp_path):
        """Availability / LIVENESS: a syntax error never raises, returns []."""
        path = tmp_path / "broken.py"
        path.write_text("import boto3\ndef handler(event, context):\n    if not all([\n")

        assert detector.detect(path) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability / LIVENESS: a nonexistent path never raises, returns []."""
        assert detector.detect(tmp_path / "does_not_exist.py") == []

    def test_fail_open_on_binary_content(self, detector, tmp_path):
        """Availability / LIVENESS: undecodable bytes never raise, return []."""
        path = tmp_path / "blob.py"
        path.write_bytes(b"\x00\xff\xfe import boto3 \x00 all([")

        assert detector.detect(path) == []
