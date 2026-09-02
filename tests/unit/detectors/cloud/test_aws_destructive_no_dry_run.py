"""Tests for the destructive-AWS-call-without-dry-run detector (CAL-024, #499).
# tested-by: tests/unit/detectors/cloud/test_aws_destructive_no_dry_run.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.aws_destructive_no_dry_run import (
    AwsDestructiveNoDryRunDetector,
)

DETECTOR_ID = "CAL-024"


def _write(tmp_path: Path, code: str, name: str = "cleanup.py") -> Path:
    """Write dedented ``code`` so that its first source line is line 1."""
    target = tmp_path / name
    target.write_text(textwrap.dedent(code).lstrip("\n"))
    return target


@pytest.fixture
def detector() -> AwsDestructiveNoDryRunDetector:
    return AwsDestructiveNoDryRunDetector()


class TestMetadata:
    """Identity contract for CAL-024."""

    def test_detector_id(self, detector):
        assert detector.detector_id == DETECTOR_ID

    def test_name(self, detector):
        assert detector.name == "Destructive AWS Call Without Dry-Run Guard"

    def test_category_is_reliability(self, detector):
        assert detector.category == DetectorCategory.reliability

    def test_severity_is_medium(self, detector):
        assert detector.severity == FindingSeverity.medium

    def test_targets_python_only(self, detector):
        assert detector.target_files == ("*.py",)


class TestDestructivePrefixes:
    """Every destructive method-name prefix fires exactly once at the call line."""

    @pytest.mark.parametrize(
        "method",
        [
            "delete_bucket",
            "terminate_instances",
            "deregister_image",
            "purge_queue",
        ],
    )
    def test_each_prefix_fires_once_at_call_line(self, detector, tmp_path, method):
        code = f"""
            import boto3

            client = boto3.client("ec2")
            client.{method}(Id="abc")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == DETECTOR_ID
        assert finding.detector_name == "Destructive AWS Call Without Dry-Run Guard"
        assert finding.category == DetectorCategory.reliability
        assert finding.severity == FindingSeverity.medium
        assert finding.file_path == str(path)
        assert finding.line_number == 4
        assert finding.issue_reference == "#499"

    @pytest.mark.parametrize("method", ["remove_tags", "disassociate_address"])
    def test_named_methods_fire_once_at_call_line(self, detector, tmp_path, method):
        code = f"""
            import boto3


            def run():
                ec2 = boto3.client("ec2")
                ec2.{method}(Resources=["i-1"])
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].detector_id == DETECTOR_ID
        assert findings[0].line_number == 6

    def test_message_names_method_and_warns_no_preview(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.delete_object(Bucket="b", Key="k")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        message = findings[0].message
        assert "delete_object" in message
        assert "first run" in message.lower()
        assert "preview" in message.lower()
        assert (
            findings[0].fix_hint
            == "Add a DRY_RUN env switch that logs the target and skips the call"
        )

    def test_one_finding_per_call_with_exact_lines(self, detector, tmp_path):
        code = """
            import boto3

            ec2 = boto3.client("ec2")
            s3 = boto3.client("s3")


            def cleanup(bucket, instance):
                ec2.describe_instances()
                s3.delete_object(Bucket=bucket, Key="a")
                s3.delete_object(Bucket=bucket, Key="b")
                ec2.terminate_instances(InstanceIds=[instance])
                return ec2.list_tags()
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [9, 10, 11]
        assert {f.detector_id for f in findings} == {DETECTOR_ID}

    def test_resource_style_call_on_attribute_chain_fires(self, detector, tmp_path):
        code = """
            import boto3

            table = boto3.resource("dynamodb").Table("t")
            table.meta.client.delete_table(TableName="t")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_from_import_boto3_counts_as_gate(self, detector, tmp_path):
        code = """
            from boto3 import client

            client("s3").delete_bucket(Bucket="b")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 3

    def test_botocore_import_counts_as_gate(self, detector, tmp_path):
        code = """
            import botocore.session

            session = botocore.session.get_session()
            client = session.create_client("ec2")
            client.terminate_instances(InstanceIds=["i-1"])
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
                    client.deregister_task_definition(taskDefinition="x")
                except ClientError:
                    pass
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5


class TestGuardsSilence:
    """Any dry-run identifier anywhere in the module silences the detector."""

    def test_module_level_dry_run_name_silences(self, detector, tmp_path):
        code = """
            import os

            import boto3

            DRY_RUN = os.environ.get("DRY_RUN", "true")


            def cleanup(bucket):
                s3 = boto3.client("s3")
                s3.delete_bucket(Bucket=bucket)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_lowercase_dry_run_local_name_silences(self, detector, tmp_path):
        code = """
            import boto3


            def cleanup(bucket, dry_run=True):
                s3 = boto3.client("s3")
                if dry_run:
                    return
                s3.delete_bucket(Bucket=bucket)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_dryrun_attribute_name_silences(self, detector, tmp_path):
        code = """
            import boto3


            def cleanup(settings, ec2):
                if settings.dryRun:
                    return
                ec2.terminate_instances(InstanceIds=["i-1"])
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_dry_run_in_string_constant_silences(self, detector, tmp_path):
        code = """
            import os

            import boto3


            def cleanup(queue_url):
                if os.environ.get("MODE") == "dry-run":
                    return
                boto3.client("sqs").purge_queue(QueueUrl=queue_url)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_dry_run_keyword_on_call_silences(self, detector, tmp_path):
        code = """
            import boto3

            ec2 = boto3.client("ec2")
            ec2.terminate_instances(InstanceIds=["i-1"], DryRun=True)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_guard_anywhere_in_module_silences_all_calls(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.delete_object(Bucket="b", Key="1")
            s3.delete_object(Bucket="b", Key="2")


            def is_dry_run() -> bool:
                return True
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []


class TestNegativeCases:
    """Spec-listed cases that must produce no finding."""

    def test_no_boto3_import_ignores_delete_call(self, detector, tmp_path):
        code = """
            class Store:
                def delete_item(self, key):
                    pass


            foo = Store()
            foo.delete_item("k")
            foo.terminate_instances()
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_boto3_file_with_only_read_calls(self, detector, tmp_path):
        code = """
            import boto3

            ec2 = boto3.client("ec2")
            ec2.describe_instances()
            ec2.describe_images(Owners=["self"])
            boto3.client("s3").list_buckets()
            boto3.client("s3").list_objects_v2(Bucket="b")
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_boto3_file_with_non_destructive_writes(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.put_object(Bucket="b", Key="k", Body=b"x")
            s3.create_bucket(Bucket="b")
            boto3.client("ec2").create_tags(Resources=["i-1"], Tags=[])
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_prefix_must_be_at_start_of_method_name(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.get_delete_marker(Bucket="b")
            s3.batch_delete_things(Bucket="b")
            s3.undelete_object(Bucket="b")
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_function_named_delete_is_not_a_method_call(self, detector, tmp_path):
        code = """
            import boto3


            def delete_bucket(name):
                return boto3.client("s3").head_bucket(Bucket=name)


            delete_bucket("b")
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
            s3.delete_bucket(Bucket="b")  # noqa: CAL-024
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_noqa_suppresses(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.delete_bucket(Bucket="b")  # noqa
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.delete_bucket(Bucket="b")  # noqa: CAL-012
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_noqa_only_suppresses_its_own_line(self, detector, tmp_path):
        code = """
            import boto3

            s3 = boto3.client("s3")
            s3.delete_bucket(Bucket="a")  # noqa: CAL-024
            s3.delete_bucket(Bucket="b")
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

            ec2 = boto3.client("ec2")
            ec2.terminate_instances(InstanceIds=["i-1"])
            ec2.deregister_image(ImageId="ami-1")
            boto3.client("sqs").purge_queue(QueueUrl="q")
            """
        path = _write(tmp_path, code)

        first = detector.detect(path)
        second = detector.detect(path)

        assert len(first) == 3
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_unparseable_file(self, detector, tmp_path):
        """Availability / LIVENESS: a syntax error never raises, returns []."""
        path = tmp_path / "broken.py"
        path.write_text("import boto3\nclient.delete_bucket(Bucket=\n")

        assert detector.detect(path) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability / LIVENESS: a nonexistent path never raises, returns []."""
        assert detector.detect(tmp_path / "does_not_exist.py") == []

    def test_fail_open_on_binary_content(self, detector, tmp_path):
        """Availability / LIVENESS: undecodable bytes never raise, return []."""
        path = tmp_path / "blob.py"
        path.write_bytes(b"\x00\xff\xfe import boto3 \x00 delete_bucket(")

        assert detector.detect(path) == []
