"""Tests for Delete Or Rollback Path Swallows Failure detector (CAL-029, #499).
# tested-by: tests/unit/detectors/cloud/test_delete_path_swallows_failure.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.delete_path_swallows_failure import (
    DeletePathSwallowsFailureDetector,
)

_FIX_HINT = "Re-raise, or return a failure result the caller checks"


def _write(tmp_path: Path, code: str, name: str = "cleanup.py") -> Path:
    target = tmp_path / name
    target.write_text(code, encoding="utf-8")
    return target


class TestDeletePathSwallowsFailureDetector:
    """Tests for DeletePathSwallowsFailureDetector (CAL-029)."""

    @pytest.fixture
    def detector(self):
        return DeletePathSwallowsFailureDetector()

    # -- identity ---------------------------------------------------------

    def test_detector_metadata(self, detector):
        """Detector identity matches the spec."""
        assert detector.detector_id == "CAL-029"
        assert detector.name == "Delete Or Rollback Path Swallows Failure"
        assert detector.category == DetectorCategory.reliability
        assert detector.severity == FindingSeverity.medium
        assert detector.target_files == ("*.py",)

    # -- positive cases: function-name forms -------------------------------

    def test_detects_delete_prefix_with_pass(self, detector, tmp_path):
        """`delete_x` catching Exception with `pass` is reported at the except line."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == "CAL-029"
        assert finding.detector_name == "Delete Or Rollback Path Swallows Failure"
        assert finding.category == DetectorCategory.reliability
        assert finding.severity == FindingSeverity.medium
        assert finding.line_number == 4
        assert finding.issue_reference == "#499"
        assert finding.fix_hint == _FIX_HINT

    def test_message_names_function_and_success_consequence(self, detector, tmp_path):
        """Message names the function, mentions the delete/rollback path, and says success."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        message = findings[0].message
        assert "delete_bucket" in message
        assert "delete/rollback path" in message
        assert "success" in message.lower()

    def test_detects_remove_prefix(self, detector, tmp_path):
        """`remove_x` is a delete path."""
        code = """\
def remove_volume(vol_id):
    try:
        ec2.delete_volume(VolumeId=vol_id)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "remove_volume" in findings[0].message

    def test_detects_rollback_prefix(self, detector, tmp_path):
        """`rollback_x` is a rollback path."""
        code = """\
def rollback_migration(step):
    try:
        step.undo()
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "rollback_migration" in findings[0].message

    def test_detects_cleanup_bare_name(self, detector, tmp_path):
        """A function named exactly `cleanup` is a delete path."""
        code = """\
def cleanup():
    try:
        shutil.rmtree(workdir)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "cleanup" in findings[0].message

    def test_detects_teardown_bare_name(self, detector, tmp_path):
        """A function named exactly `teardown` is a delete path."""
        code = """\
def teardown():
    try:
        stack.destroy()
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "teardown" in findings[0].message

    def test_detects_purge_prefix(self, detector, tmp_path):
        """`purge_x` is a delete path."""
        code = """\
def purge_queue(url):
    try:
        sqs.purge_queue(QueueUrl=url)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "purge_queue" in findings[0].message

    def test_detects_deprovision_prefix(self, detector, tmp_path):
        """`deprovision_x` is a delete path."""
        code = """\
def deprovision_tenant(tenant_id):
    try:
        api.deprovision(tenant_id)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "deprovision_tenant" in findings[0].message

    def test_detects_delete_method_on_class(self, detector, tmp_path):
        """A method `def delete(self, ...)` on a class is a delete path."""
        code = """\
class Resource:
    def delete(self, force=False):
        try:
            self.client.delete(self.id)
        except Exception:
            pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 5
        assert "delete" in findings[0].message

    def test_detects_async_delete_function(self, detector, tmp_path):
        """An `async def delete_x` is a delete path."""
        code = """\
async def delete_session(session_id):
    try:
        await store.delete(session_id)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "delete_session" in findings[0].message

    def test_detects_rollback_infix(self, detector, tmp_path):
        """A name containing `_rollback_` in the middle is a rollback path."""
        code = """\
def run_rollback_step(step):
    try:
        step.undo()
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "run_rollback_step" in findings[0].message

    def test_detects_delete_infix(self, detector, tmp_path):
        """A name containing `_delete_` in the middle is a delete path."""
        code = """\
def do_delete_now(key):
    try:
        store.pop(key)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4
        assert "do_delete_now" in findings[0].message

    def test_detects_case_insensitive_prefix(self, detector, tmp_path):
        """The name prefix match is case-insensitive."""
        code = """\
def DeleteStack(name):
    try:
        cfn.delete_stack(StackName=name)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    # -- positive cases: swallowing body forms ----------------------------

    def test_detects_body_only_logger_warning(self, detector, tmp_path):
        """An except whose only statement is `logger.warning(...)` swallows."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        logger.warning("delete failed: %s", exc)
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_body_only_print(self, detector, tmp_path):
        """An except whose only statement is a bare `print(...)` swallows."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        print(exc)
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_body_return_none(self, detector, tmp_path):
        """An except that does `return None` swallows."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_body_return_true(self, detector, tmp_path):
        """An except that does `return True` swallows (and lies about success)."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        return True
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_body_return_empty_dict(self, detector, tmp_path):
        """An except that does `return {}` swallows."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        return {}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_body_return_status_dict(self, detector, tmp_path):
        """An except that returns a populated dict such as `{"status": "ok"}` swallows."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        return {"status": "ok"}
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_body_log_then_return_none(self, detector, tmp_path):
        """Logging followed by `return None` is still a swallow."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        logger.error("delete failed: %s", exc)
        return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    # -- positive cases: broad exception forms ----------------------------

    def test_detects_bare_except(self, detector, tmp_path):
        """A bare `except:` counts as broad."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_base_exception(self, detector, tmp_path):
        """`except BaseException` counts as broad."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except BaseException:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_detects_tuple_containing_exception(self, detector, tmp_path):
        """`except (Exception, ValueError):` counts as broad because the tuple holds Exception."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except (Exception, ValueError):
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    # -- positive cases: multiplicity and location ------------------------

    def test_one_finding_per_offending_except_in_line_order(self, detector, tmp_path):
        """Two swallowing except clauses in one delete path yield two findings in line order."""
        code = """\
def delete_stack(name):
    try:
        cfn.delete_stack(StackName=name)
    except Exception:
        pass
    try:
        s3.delete_bucket(Bucket=name)
    except Exception:
        return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 2
        assert [f.line_number for f in findings] == [4, 8]
        assert {f.detector_id for f in findings} == {"CAL-029"}

    def test_detects_except_nested_in_loop_inside_delete_path(self, detector, tmp_path):
        """A swallowing except nested inside a loop within the function body is still found."""
        code = """\
def delete_objects(keys):
    for key in keys:
        if key:
            try:
                s3.delete_object(Key=key)
            except Exception:
                pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 6

    def test_only_offending_clause_reported_among_siblings(self, detector, tmp_path):
        """Only the broad, swallowing clause fires; a narrow sibling does not."""
        code = """\
from botocore.exceptions import ClientError


def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except ClientError:
        pass
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 9

    def test_reports_file_path_of_scanned_file(self, detector, tmp_path):
        """The finding carries the path of the file that was scanned."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        pass
"""
        target = _write(tmp_path, code)
        findings = detector.detect(target)

        assert len(findings) == 1
        assert findings[0].file_path == str(target)

    # -- negative cases ---------------------------------------------------

    def test_ignores_except_that_reraises_bare(self, detector, tmp_path):
        """No finding when the except body re-raises with a bare `raise`."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        logger.error("delete failed: %s", exc)
        raise
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_that_reraises_from(self, detector, tmp_path):
        """No finding when the except body raises a wrapped exception (`raise X from e`)."""
        code = """\
class DeleteError(Exception):
    pass


def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        raise DeleteError(name) from exc
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_with_raise_beside_return(self, detector, tmp_path):
        """No finding when a `raise` appears anywhere in the except body, even beside a return."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        if is_not_found(exc):
            return None
        raise
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_returning_false(self, detector, tmp_path):
        """No finding when the except returns `False`, a failure result the caller can check."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:
        return False
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_narrow_key_error(self, detector, tmp_path):
        """No finding when the except catches a narrow builtin type (KeyError)."""
        code = """\
def delete_entry(key):
    try:
        del cache[key]
    except KeyError:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_narrow_client_error(self, detector, tmp_path):
        """No finding when the except catches a narrow library type (ClientError)."""
        code = """\
from botocore.exceptions import ClientError


def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except ClientError:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_narrow_tuple_without_exception(self, detector, tmp_path):
        """No finding when the except tuple holds only narrow types (KeyError, ValueError)."""
        code = """\
def delete_entry(key):
    try:
        del cache[key]
    except (KeyError, ValueError):
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_same_body_in_non_delete_function(self, detector, tmp_path):
        """The identical swallowing except in `fetch_item` is not a delete/rollback path."""
        code = """\
def fetch_item(key):
    try:
        return store.get(key)
    except Exception:
        return None
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_calling_mark_failed(self, detector, tmp_path):
        """An except body that calls `mark_failed(...)` signals the failure -> no finding."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        mark_failed(name, exc)
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_calling_self_abort(self, detector, tmp_path):
        """An except body that calls `self.abort()` signals the failure -> no finding."""
        code = """\
class Job:
    def rollback(self):
        try:
            self.undo_all()
        except Exception:
            self.abort()
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_calling_fail_job(self, detector, tmp_path):
        """An except body that calls `fail_job(...)` signals the failure -> no finding."""
        code = """\
def cleanup_workspace(job_id):
    try:
        shutil.rmtree(workdir)
    except Exception as exc:
        logger.error("cleanup failed: %s", exc)
        fail_job(job_id)
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_except_in_nested_def_attributed_to_nested_name(self, detector, tmp_path):
        """An except inside a nested `def` belongs to the nested def, whose name does not match."""
        code = """\
def delete_bucket(name):
    def attempt():
        try:
            client.delete_bucket(Bucket=name)
        except Exception:
            pass
    attempt()
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_nested_def_with_matching_name_is_reported(self, detector, tmp_path):
        """A nested def whose own name matches is reported at its own except line."""
        code = """\
def build(name):
    def delete_it():
        try:
            client.delete_bucket(Bucket=name)
        except Exception:
            pass
    return delete_it
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 5
        assert "delete_it" in findings[0].message

    def test_ignores_delete_path_with_no_try(self, detector, tmp_path):
        """No finding when the delete path has no try/except at all."""
        code = """\
def delete_bucket(name):
    client.delete_bucket(Bucket=name)
    return True
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_except_doing_real_work(self, detector, tmp_path):
        """An except body with non-logging, non-return statements is not treated as a swallow."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception as exc:
        errors.append(exc)
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_ignores_non_python_target(self, detector, tmp_path):
        """Target file pattern is Python only."""
        assert detector.target_files == ("*.py",)

    # -- suppression ------------------------------------------------------

    def test_noqa_on_except_line_suppresses_finding(self, detector, tmp_path):
        """`# noqa: CAL-029` on the except line suppresses the finding."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:  # noqa: CAL-029
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_bare_noqa_suppresses_finding(self, detector, tmp_path):
        """A bare `# noqa` on the except line suppresses the finding."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:  # noqa
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert findings == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        """A noqa for a different detector id leaves the CAL-029 finding intact."""
        code = """\
def delete_bucket(name):
    try:
        client.delete_bucket(Bucket=name)
    except Exception:  # noqa: CAL-023
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_noqa_suppresses_only_annotated_clause(self, detector, tmp_path):
        """Suppression is per line: the un-annotated sibling clause still fires."""
        code = """\
def delete_stack(name):
    try:
        cfn.delete_stack(StackName=name)
    except Exception:  # noqa: CAL-029
        pass
    try:
        s3.delete_bucket(Bucket=name)
    except Exception:
        pass
"""
        findings = detector.detect(_write(tmp_path, code))

        assert len(findings) == 1
        assert findings[0].line_number == 8


class TestProperties:
    """Formal property tests for CAL-029 (DPS-12)."""

    @pytest.fixture
    def detector(self):
        return DeletePathSwallowsFailureDetector()

    def test_determinism_same_file_same_findings(self, detector, tmp_path):
        """Determinism (INVARIANT): scanning the same file twice yields identical findings."""
        code = """\
def delete_stack(name):
    try:
        cfn.delete_stack(StackName=name)
    except Exception:
        pass
    try:
        s3.delete_bucket(Bucket=name)
    except:
        return None
"""
        target = _write(tmp_path, code)

        first = detector.detect(target)
        second = detector.detect(target)

        assert len(first) == 2
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_syntax_error(self, detector, tmp_path):
        """Availability (LIVENESS): an unparseable file never raises and yields no findings."""
        target = _write(tmp_path, "def delete_bucket(name:\n    try\n")

        assert detector.detect(target) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability (LIVENESS): a nonexistent path never raises and yields no findings."""
        assert detector.detect(tmp_path / "does_not_exist.py") == []

    def test_fail_open_on_binary_content(self, detector, tmp_path):
        """Availability (LIVENESS): undecodable bytes never raise and yield no findings."""
        target = tmp_path / "blob.py"
        target.write_bytes(b"\x00\xff\xfe\x80def delete_bucket(")

        assert detector.detect(target) == []
