"""Tests for the AWS-call-missing-required-in-practice-argument detector (CAL-025, #499).
# tested-by: tests/unit/detectors/cloud/test_aws_call_missing_arg.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.aws_call_missing_arg import AwsCallMissingArgDetector

DETECTOR_ID = "CAL-025"
DETECTOR_NAME = "AWS API Call Missing Required-In-Practice Argument"


def _write(tmp_path: Path, code: str, name: str = "handler.py") -> Path:
    """Write dedented ``code`` so that its first source line is line 1."""
    target = tmp_path / name
    target.write_text(textwrap.dedent(code).lstrip("\n"))
    return target


@pytest.fixture
def detector() -> AwsCallMissingArgDetector:
    return AwsCallMissingArgDetector()


class TestMetadata:
    """Identity contract for CAL-025."""

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

    def test_required_kwargs_table_pins_backup_and_s3_entries(self):
        table = AwsCallMissingArgDetector.REQUIRED_KWARGS

        assert table["start_backup_job"] == ("Lifecycle",)
        assert table["start_copy_job"] == ("Lifecycle",)
        assert table["put_object"] == ("ServerSideEncryption",)


class TestBackupLifecycle:
    """``start_backup_job``/``start_copy_job`` without ``Lifecycle`` fire once."""

    def test_start_backup_job_without_lifecycle_fires_at_call_line(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")
            backup.start_backup_job(
                BackupVaultName="v",
                ResourceArn="arn:aws:ec2:us-east-1:1:volume/vol-1",
                IamRoleArn="arn:aws:iam::1:role/r",
            )
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == DETECTOR_ID
        assert finding.detector_name == DETECTOR_NAME
        assert finding.category == DetectorCategory.reliability
        assert finding.severity == FindingSeverity.medium
        assert finding.file_path == str(path)
        assert finding.line_number == 4
        assert finding.issue_reference == "#499"

    def test_start_copy_job_without_lifecycle_fires_at_call_line(self, detector, tmp_path):
        code = """
            import boto3


            def copy(client, arn):
                return client.start_copy_job(
                    RecoveryPointArn=arn,
                    SourceBackupVaultName="a",
                    DestinationBackupVaultArn="b",
                    IamRoleArn="r",
                )
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].detector_id == DETECTOR_ID
        assert findings[0].line_number == 5

    def test_message_and_fix_hint_name_argument_and_method(self, detector, tmp_path):
        code = """
            import boto3

            boto3.client("backup").start_backup_job(BackupVaultName="v")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert "start_backup_job" in findings[0].message
        assert "Lifecycle" in findings[0].message
        assert "Lifecycle" in findings[0].fix_hint

    def test_two_offending_calls_produce_two_findings(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")


            def run(arn):
                backup.list_backup_jobs()
                backup.start_backup_job(BackupVaultName="v", ResourceArn=arn)
                backup.start_copy_job(RecoveryPointArn=arn)
                return backup.describe_backup_job(BackupJobId="j")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [8, 9]
        assert {f.detector_id for f in findings} == {DETECTOR_ID}

    def test_lifecycle_present_is_silent(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")
            backup.start_backup_job(
                BackupVaultName="v",
                ResourceArn="arn",
                IamRoleArn="r",
                Lifecycle={"DeleteAfterDays": 35},
            )
            backup.start_copy_job(RecoveryPointArn="arn", Lifecycle={"DeleteAfterDays": 35})
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_kwargs_splat_in_call_is_silent(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")
            params = {"Lifecycle": {"DeleteAfterDays": 35}}
            backup.start_backup_job(BackupVaultName="v", **params)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []


class TestLogGroupRetention:
    """``create_log_group`` fires only when the module never sets a retention policy."""

    def test_create_log_group_without_retention_fires_at_call_line(self, detector, tmp_path):
        code = """
            import boto3

            logs = boto3.client("logs")


            def ensure(name):
                logs.create_log_group(logGroupName=name)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].detector_id == DETECTOR_ID
        assert findings[0].line_number == 7
        assert "create_log_group" in findings[0].message
        assert "put_retention_policy" in findings[0].message
        assert "put_retention_policy" in findings[0].fix_hint

    def test_put_retention_policy_after_call_silences(self, detector, tmp_path):
        code = """
            import boto3

            logs = boto3.client("logs")


            def ensure(name):
                logs.create_log_group(logGroupName=name)
                logs.put_retention_policy(logGroupName=name, retentionInDays=30)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_put_retention_policy_before_call_silences(self, detector, tmp_path):
        code = """
            import boto3

            logs = boto3.client("logs")


            def set_retention(name):
                logs.put_retention_policy(logGroupName=name, retentionInDays=30)


            def ensure(name):
                logs.create_log_group(logGroupName=name)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []


class TestPutObjectEncryption:
    """``put_object`` without ``ServerSideEncryption`` fires unless the bucket is encrypted."""

    def test_put_object_without_sse_fires_at_call_line(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_object(Bucket="b", Key="k", Body=b"x")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].detector_id == DETECTOR_ID
        assert findings[0].line_number == 4
        assert "put_object" in findings[0].message
        assert "ServerSideEncryption" in findings[0].message
        assert "ServerSideEncryption" in findings[0].fix_hint

    def test_sse_present_is_silent(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_object(Bucket="b", Key="k", Body=b"x", ServerSideEncryption="AES256")
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_put_bucket_encryption_after_call_silences(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_object(Bucket="b", Key="k", Body=b"x")
            s3.put_bucket_encryption(
                Bucket="b",
                ServerSideEncryptionConfiguration={"Rules": []},
            )
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_put_bucket_encryption_before_call_silences(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_bucket_encryption(Bucket="b", ServerSideEncryptionConfiguration={})


            def upload(key, body):
                s3.put_object(Bucket="b", Key=key, Body=body)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_kwargs_splat_in_put_object_is_silent(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            extra = {"ServerSideEncryption": "AES256"}
            s3.put_object(Bucket="b", Key="k", Body=b"x", **extra)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []


class TestGate:
    """Only files importing boto3/botocore are inspected."""

    def test_non_boto3_file_is_silent(self, detector, tmp_path):
        code = """
            class Backup:
                def start_backup_job(self, **kw):
                    pass


            class Store:
                def put_object(self, **kw):
                    pass


            Backup().start_backup_job(BackupVaultName="v")
            Store().put_object(Bucket="b", Key="k")
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_from_import_boto3_counts_as_gate(self, detector, tmp_path):
        code = """
            from boto3 import client

            client("backup").start_backup_job(BackupVaultName="v")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 3

    def test_botocore_import_counts_as_gate(self, detector, tmp_path):
        code = """
            import botocore.session

            session = botocore.session.get_session()
            s3 = session.create_client("s3")
            s3.put_object(Bucket="b", Key="k", Body=b"x")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_from_botocore_import_counts_as_gate(self, detector, tmp_path):
        code = """
            from botocore.exceptions import ClientError


            def run(client):
                try:
                    client.start_copy_job(RecoveryPointArn="arn")
                except ClientError:
                    raise
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 6

    def test_receiver_is_not_checked(self, detector, tmp_path):
        code = """
            import boto3


            def run(anything):
                anything.nested.client.start_backup_job(BackupVaultName="v")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5


class TestNegativeCases:
    """Spec-listed cases that must produce no finding."""

    def test_non_matching_method_names_are_silent(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")
            backup.start_restore_job(RecoveryPointArn="arn")
            backup.describe_backup_job(BackupJobId="j")
            boto3.client("s3").put_object_acl(Bucket="b", Key="k")
            boto3.client("s3").get_object(Bucket="b", Key="k")
            boto3.client("logs").create_log_stream(logGroupName="g", logStreamName="s")
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_function_with_table_name_is_not_a_method_call(self, detector, tmp_path):
        code = """
            import boto3


            def put_object(bucket, key):
                return boto3.client("s3").head_object(Bucket=bucket, Key=key)


            put_object("b", "k")
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_empty_boto3_file_has_no_findings(self, detector, tmp_path):
        path = _write(tmp_path, "import boto3\n")

        assert detector.detect(path) == []


class TestNoqaSuppression:
    """``# noqa`` on the call line silences the detector."""

    def test_noqa_with_detector_code_suppresses(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_object(Bucket="b", Key="k", Body=b"x")  # noqa: CAL-025
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_noqa_suppresses(self, detector, tmp_path):
        code = """
            import boto3

            backup = boto3.client("backup")
            backup.start_backup_job(BackupVaultName="v")  # noqa
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_object(Bucket="b", Key="k", Body=b"x")  # noqa: CAL-024
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_noqa_only_suppresses_its_own_line(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_object(Bucket="b", Key="a", Body=b"x")  # noqa: CAL-025
            s3.put_object(Bucket="b", Key="b", Body=b"x")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [5]


class TestProperties:
    """Formal properties (DPS-12)."""

    def test_determinism_same_file_same_findings(self, detector, tmp_path):
        """Determinism / INVARIANT: same input -> identical findings on repeat."""
        code = """
            import boto3

            backup = boto3.client("backup")
            backup.start_backup_job(BackupVaultName="v")
            boto3.client("logs").create_log_group(logGroupName="g")
            boto3.client("s3").put_object(Bucket="b", Key="k", Body=b"x")
            """
        path = _write(tmp_path, code)

        first = detector.detect(path)
        second = detector.detect(path)

        assert len(first) == 3
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_unparseable_file(self, detector, tmp_path):
        """Availability / LIVENESS: a syntax error never raises, returns []."""
        path = tmp_path / "broken.py"
        path.write_text("import boto3\nclient.start_backup_job(BackupVaultName=\n")

        assert detector.detect(path) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability / LIVENESS: a nonexistent path never raises, returns []."""
        assert detector.detect(tmp_path / "does_not_exist.py") == []

    def test_fail_open_on_binary_content(self, detector, tmp_path):
        """Availability / LIVENESS: undecodable bytes never raise, return []."""
        path = tmp_path / "blob.py"
        path.write_bytes(b"\x00\xff\xfe import boto3 \x00 put_object(")

        assert detector.detect(path) == []
