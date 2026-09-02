"""Tests for Lambda Handler Swallows Exceptions detector (CAL-023, #499).
# tested-by: tests/unit/detectors/cloud/test_lambda_swallowed_exception.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.lambda_swallowed_exception import (
    LambdaSwallowedExceptionDetector,
)


def _write(tmp_path: Path, code: str, name: str = "handler.py") -> Path:
    target = tmp_path / name
    target.write_text(code, encoding="utf-8")
    return target


class TestLambdaSwallowedExceptionDetector:
    """Tests for LambdaSwallowedExceptionDetector (CAL-023)."""

    @pytest.fixture
    def detector(self):
        return LambdaSwallowedExceptionDetector()

    # -- identity ---------------------------------------------------------

    def test_detector_metadata(self, detector):
        """Detector identity matches the spec."""
        assert detector.detector_id == "CAL-023"
        assert detector.name == "Lambda Handler Swallows Exceptions"
        assert detector.category == DetectorCategory.reliability
        assert detector.severity == FindingSeverity.high
        assert detector.target_files == ("*.py",)

    # -- positive cases ---------------------------------------------------

    def test_detects_lambda_handler_except_exception_with_return(self, detector, tmp_path):
        """`lambda_handler` catching Exception and returning is reported at the except line."""
        code = """\
import boto3


def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception as exc:
        print(exc)
        return {"statusCode": 500}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == "CAL-023"
        assert finding.detector_name == "Lambda Handler Swallows Exceptions"
        assert finding.category == DetectorCategory.reliability
        assert finding.severity == FindingSeverity.high
        assert finding.line_number == 7
        assert finding.issue_reference == "#499"
        assert finding.fix_hint == (
            "Log and re-raise, or return only after emitting a failure signal (metric/DLQ)"
        )

    def test_message_names_function_and_success_consequence(self, detector, tmp_path):
        """Message names the handler and explains the invocation is reported as a success."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception:
        return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        message = findings[0].message
        assert "lambda_handler" in message
        assert "success" in message.lower()
        assert "retries" in message.lower()
        assert "destinations" in message.lower()
        assert "Errors" in message

    def test_detects_handler_named_handler(self, detector, tmp_path):
        """A top-level `handler` function is treated as a Lambda handler."""
        code = """\
def handler(evt, ctx):
    try:
        do_work(evt)
    except Exception:
        return {"ok": True}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-023"
        assert findings[0].line_number == 4
        assert "handler" in findings[0].message

    def test_detects_handler_by_event_context_signature(self, detector, tmp_path):
        """Any top-level def whose first two params are (event, context) is a handler."""
        code = """\
def process_records(event, context):
    try:
        do_work(event)
    except Exception:
        return "done"
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "process_records" in findings[0].message

    def test_detects_bare_except_with_return(self, detector, tmp_path):
        """A bare `except:` that returns is reported."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except:
        return {"statusCode": 200}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_base_exception_with_return(self, detector, tmp_path):
        """`except BaseException` that returns is reported."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except BaseException:
        return {"statusCode": 200}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_nested_try_inside_handler(self, detector, tmp_path):
        """A swallowing except nested deep inside the handler body is still found."""
        code = """\
def lambda_handler(event, context):
    for record in event["Records"]:
        if record:
            try:
                do_work(record)
            except Exception:
                return {"statusCode": 200}
    return {"statusCode": 200}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 6

    def test_detects_return_nested_inside_except_body(self, detector, tmp_path):
        """A `return` nested under an `if` inside the except body still counts as swallowing."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception as exc:
        if isinstance(exc, ValueError):
            return {"statusCode": 400}
        log(exc)
        return {"statusCode": 500}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_one_finding_per_offending_except_clause(self, detector, tmp_path):
        """Two swallowing except clauses in one handler yield two findings at their own lines."""
        code = """\
def lambda_handler(event, context):
    try:
        first(event)
    except Exception:
        return {"step": 1}
    try:
        second(event)
    except Exception:
        return {"step": 2}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 2
        assert sorted(f.line_number for f in findings) == [4, 8]
        assert {f.detector_id for f in findings} == {"CAL-023"}

    def test_only_offending_clause_reported_among_siblings(self, detector, tmp_path):
        """Only the broad, swallowing clause fires; a narrow sibling does not."""
        code = """\
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    try:
        do_work(event)
    except ClientError:
        return {"statusCode": 502}
    except Exception:
        return {"statusCode": 500}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 9

    def test_reports_file_path_of_scanned_file(self, detector, tmp_path):
        """The finding carries the path of the file that was scanned."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception:
        return None
"""
        target = _write(tmp_path, code)
        findings = detector.detect(target)

        assert len(findings) == 1
        assert findings[0].file_path == str(target)

    # -- negative cases ---------------------------------------------------

    def test_ignores_except_that_reraises_bare(self, detector, tmp_path):
        """No finding when the except body re-raises with a bare `raise`."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception as exc:
        log(exc)
        raise
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_that_reraises_from(self, detector, tmp_path):
        """No finding when the except body raises a wrapped exception (`raise X from e`)."""
        code = """\
class HandlerError(Exception):
    pass


def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception as exc:
        raise HandlerError("failed") from exc
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_with_both_return_and_raise(self, detector, tmp_path):
        """No finding when the except body contains a `raise` anywhere, even beside a `return`."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception as exc:
        if is_retryable(exc):
            raise
        return {"statusCode": 400}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_with_no_return(self, detector, tmp_path):
        """No finding when the except body neither raises nor returns."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception as exc:
        log(exc)
    return {"statusCode": 200}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_narrow_client_error(self, detector, tmp_path):
        """No finding when the except catches a narrow type (ClientError)."""
        code = """\
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    try:
        do_work(event)
    except ClientError:
        return {"statusCode": 502}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_narrow_key_error(self, detector, tmp_path):
        """No finding when the except catches a narrow builtin type (KeyError)."""
        code = """\
def lambda_handler(event, context):
    try:
        return event["body"]
    except KeyError:
        return {"statusCode": 400}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_non_handler_by_name_and_params(self, detector, tmp_path):
        """No finding in a function named `helper` with params `(a, b)`."""
        code = """\
def helper(a, b):
    try:
        do_work(a, b)
    except Exception:
        return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_swallowing_except_in_non_handler_function(self, detector, tmp_path):
        """An except-with-return in a non-handler is not reported even when a handler exists."""
        code = """\
def load_config(path, defaults):
    try:
        return read(path)
    except Exception:
        return defaults


def lambda_handler(event, context):
    cfg = load_config("x", {})
    return {"statusCode": 200, "cfg": cfg}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_handler_with_no_try(self, detector, tmp_path):
        """No finding when the handler has no try/except at all."""
        code = """\
def lambda_handler(event, context):
    do_work(event)
    return {"statusCode": 200}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_event_context_in_wrong_positions(self, detector, tmp_path):
        """Params `(context, event)` do not match the `(event, context)` signature rule."""
        code = """\
def run(context, event):
    try:
        do_work(event)
    except Exception:
        return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_nested_handler_named_function(self, detector, tmp_path):
        """A `lambda_handler` that is not top-level (nested def) is not a Lambda handler."""
        code = """\
def make():
    def lambda_handler(event, context):
        try:
            do_work(event)
        except Exception:
            return None
    return lambda_handler
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_method_named_handler_in_class(self, detector, tmp_path):
        """A method named `handler` inside a class is not a top-level def."""
        code = """\
class Service:
    def handler(self, event, context):
        try:
            do_work(event)
        except Exception:
            return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_non_python_target(self, detector, tmp_path):
        """Target file pattern is Python only."""
        assert detector.target_files == ("*.py",)

    # -- suppression ------------------------------------------------------

    def test_noqa_on_except_line_suppresses_finding(self, detector, tmp_path):
        """`# noqa: CAL-023` on the except line suppresses the finding."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception:  # noqa: CAL-023
        return {"statusCode": 200}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        """A noqa for a different detector id leaves the CAL-023 finding intact."""
        code = """\
def lambda_handler(event, context):
    try:
        do_work(event)
    except Exception:  # noqa: CAL-012
        return {"statusCode": 200}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_noqa_suppresses_only_annotated_clause(self, detector, tmp_path):
        """Suppression is per line: the un-annotated sibling clause still fires."""
        code = """\
def lambda_handler(event, context):
    try:
        first(event)
    except Exception:  # noqa: CAL-023
        return {"step": 1}
    try:
        second(event)
    except Exception:
        return {"step": 2}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 8


class TestProperties:
    """Formal property tests for CAL-023 (DPS-12)."""

    @pytest.fixture
    def detector(self):
        return LambdaSwallowedExceptionDetector()

    def test_determinism_same_file_same_findings(self, detector, tmp_path):
        """Determinism (INVARIANT): scanning the same file twice yields identical findings."""
        code = """\
def lambda_handler(event, context):
    try:
        first(event)
    except Exception:
        return {"step": 1}
    try:
        second(event)
    except:
        return {"step": 2}
"""
        target = _write(tmp_path, code)

        first = detector.detect(target)
        second = detector.detect(target)

        assert len(first) == 2
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_syntax_error(self, detector, tmp_path):
        """Availability (LIVENESS): an unparseable file never raises and yields no findings."""
        target = _write(tmp_path, "def lambda_handler(event, context:\n    try\n")

        assert detector.detect(target) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability (LIVENESS): a nonexistent path never raises and yields no findings."""
        assert detector.detect(tmp_path / "does_not_exist.py") == []

    def test_fail_open_on_binary_content(self, detector, tmp_path):
        """Availability (LIVENESS): undecodable bytes never raise and yield no findings."""
        target = tmp_path / "blob.py"
        target.write_bytes(b"\x00\xff\xfe\x80def lambda_handler(")

        assert detector.detect(target) == []
