"""Tests for the numeric-setting-without-range-guard detector (CAL-030, #499).
# tested-by: tests/unit/detectors/cloud/test_unguarded_numeric_setting.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.unguarded_numeric_setting import (
    UnguardedNumericSettingDetector,
)

DETECTOR_ID = "CAL-030"
DETECTOR_NAME = "Numeric Setting Used Without Range Guard"


def _write(tmp_path: Path, code: str, name: str = "settings.py") -> Path:
    """Write dedented ``code`` so that its first source line is line 1."""
    target = tmp_path / name
    target.write_text(textwrap.dedent(code).lstrip("\n"))
    return target


@pytest.fixture
def detector() -> UnguardedNumericSettingDetector:
    return UnguardedNumericSettingDetector()


class TestMetadata:
    """Identity contract for CAL-030."""

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


class TestSourceForms:
    """Each numeric-setting source form fires once at the assignment line."""

    def test_int_of_environ_get_passed_as_keyword(self, detector, tmp_path):
        code = """
            import os


            def run(client):
                timeout = int(os.environ.get("T", "30"))
                return client.fetch(timeout=timeout)
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
        assert finding.line_number == 5
        assert finding.issue_reference == "#499"

    def test_float_of_getenv_passed_positionally(self, detector, tmp_path):
        code = """
            import os


            def page(client):
                limit = float(os.getenv("L"))
                return client.query(limit)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_int_of_subscript(self, detector, tmp_path):
        code = """
            from concurrent.futures import ThreadPoolExecutor


            def build(cfg):
                max_workers = int(cfg["w"])
                return ThreadPoolExecutor(max_workers)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_dict_get_with_numeric_default(self, detector, tmp_path):
        code = """
            def build(cfg, session):
                retries = cfg.get("retries", 3)
                return session.mount(retries=retries)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 2

    def test_int_of_bare_name(self, detector, tmp_path):
        code = """
            def load(value, loader):
                batch_size = int(value)
                return loader.read(batch_size)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 2

    def test_parameter_with_numeric_default_fires_at_def_line(self, detector, tmp_path):
        code = """
            def run(items, timeout=30):
                return fetch_all(items, timeout=timeout)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 1

    def test_float_parameter_default_fires_at_def_line(self, detector, tmp_path):
        code = """
            import time


            def poll(delay=0.5):
                time.sleep(delay)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 4


class TestVocabulary:
    """Every vocabulary token is matched as a case-insensitive substring."""

    @pytest.mark.parametrize(
        "name",
        [
            "timeout",
            "rate_limit",
            "max_connections",
            "min_length",
            "chunk_size",
            "retries",
            "attempts",
            "poll_interval",
            "cache_ttl",
            "delay",
            "batch",
            "workers",
            "concurrency",
            "port",
        ],
    )
    def test_each_token_fires(self, detector, tmp_path, name):
        code = f"""
            def configure(raw, client):
                {name} = int(raw)
                return client.configure({name})
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 2
        assert name in findings[0].message

    def test_match_is_case_insensitive(self, detector, tmp_path):
        code = """
            def configure(raw, client):
                MaxRetries = int(raw)
                return client.configure(MaxRetries)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 2


class TestMessage:
    """Message names the setting and callee; fix hint names the setting."""

    def test_message_names_setting_and_callee(self, detector, tmp_path):
        code = """
            def run(items, timeout=30):
                return fetch_all(items, timeout=timeout)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        message = findings[0].message
        assert (
            message == "`timeout` is used by `fetch_all` without a range check; "
            "a zero, negative, NaN or huge value passes straight through"
        )

    def test_message_names_method_callee(self, detector, tmp_path):
        code = """
            def run(client, raw):
                limit = int(raw)
                return client.query(limit)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        message = findings[0].message
        assert "`limit`" in message
        assert "query" in message
        assert "zero" in message.lower()
        assert "negative" in message.lower()
        assert "nan" in message.lower()

    def test_fix_hint_names_setting_and_finite(self, detector, tmp_path):
        code = """
            def run(client, raw):
                port = int(raw)
                return client.connect(port=port)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].fix_hint == "Validate `port` (finite, positive, bounded) before use"
        assert "finite" in findings[0].fix_hint

    def test_two_unguarded_names_two_findings_in_line_order(self, detector, tmp_path):
        code = """
            def run(client, raw_timeout, raw_limit):
                timeout = int(raw_timeout)
                limit = int(raw_limit)
                return client.fetch(timeout=timeout, limit=limit)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [2, 3]
        assert "`timeout`" in findings[0].message
        assert "`limit`" in findings[1].message
        assert {f.detector_id for f in findings} == {DETECTOR_ID}

    def test_one_finding_per_setting_even_if_passed_twice(self, detector, tmp_path):
        code = """
            def run(client, raw):
                timeout = int(raw)
                client.connect(timeout)
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [2]


class TestGuardsSilence:
    """A range check on the name anywhere in the same function silences."""

    def test_compare_le_zero_with_raise(self, detector, tmp_path):
        code = """
            import os


            def run(client):
                timeout = int(os.environ.get("T", "30"))
                if timeout <= 0:
                    raise ValueError("timeout must be positive")
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_chained_compare_with_not(self, detector, tmp_path):
        code = """
            def page(client, raw):
                limit = int(raw)
                if not 0 < limit <= 100:
                    raise ValueError("limit out of range")
                return client.query(limit)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_compare_in_while_condition(self, detector, tmp_path):
        code = """
            def run(cfg, session):
                retries = cfg.get("retries", 3)
                while retries > 0:
                    session.mount(retries=retries)
                    retries -= 1
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_compare_after_the_call_still_counts(self, detector, tmp_path):
        code = """
            def run(client, raw):
                timeout = int(raw)
                client.fetch(timeout=timeout)
                if timeout > 60:
                    client.warn("slow")
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_math_isfinite_guard(self, detector, tmp_path):
        code = """
            import math


            def run(client, raw):
                timeout = float(raw)
                if not math.isfinite(timeout):
                    raise ValueError("timeout must be finite")
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_max_clamp(self, detector, tmp_path):
        code = """
            def run(client, raw):
                timeout = int(raw)
                return client.fetch(timeout=max(1, timeout))
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_min_clamp(self, detector, tmp_path):
        code = """
            def page(client, raw):
                limit = int(raw)
                limit = min(limit, 100)
                return client.query(limit)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_parameter_guarded_by_compare(self, detector, tmp_path):
        code = """
            def run(items, timeout=30):
                if timeout <= 0:
                    raise ValueError("bad timeout")
                return fetch_all(items, timeout=timeout)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []


class TestNegativeCases:
    """Spec-listed cases that must produce no finding."""

    def test_name_outside_vocabulary_ignored(self, detector, tmp_path):
        code = """
            def paint(x, canvas):
                color = int(x)
                return canvas.fill(color)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_vocabulary_name_never_passed_to_a_call(self, detector, tmp_path):
        code = """
            import os


            def run():
                timeout = int(os.environ.get("T", "30"))
                return timeout * 2
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_non_numeric_assignment_not_collected(self, detector, tmp_path):
        code = """
            def run(client):
                timeout = fetch_timeout()
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_parameter_without_numeric_default_not_collected(self, detector, tmp_path):
        code = """
            def run(items, timeout):
                return fetch_all(items, timeout=timeout)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_expression_argument_is_not_a_bare_name(self, detector, tmp_path):
        code = """
            def run(client, raw):
                timeout = int(raw)
                return client.fetch(timeout=timeout * 1000)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_guard_in_different_function_does_not_count(self, detector, tmp_path):
        code = """
            def check(timeout):
                if timeout <= 0:
                    raise ValueError("bad timeout")


            def run(client, raw):
                timeout = int(raw)
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [7]

    def test_empty_file_has_no_findings(self, detector, tmp_path):
        path = _write(tmp_path, "import os\n")

        assert detector.detect(path) == []


class TestNoqaSuppression:
    """``# noqa`` on the assignment line silences the detector."""

    def test_noqa_with_detector_code_suppresses(self, detector, tmp_path):
        code = """
            def run(client, raw):
                timeout = int(raw)  # noqa: CAL-030
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_noqa_suppresses(self, detector, tmp_path):
        code = """
            def run(client, raw):
                timeout = int(raw)  # noqa
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        code = """
            def run(client, raw):
                timeout = int(raw)  # noqa: CAL-012
                return client.fetch(timeout=timeout)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 2

    def test_noqa_only_suppresses_its_own_line(self, detector, tmp_path):
        code = """
            def run(client, raw_timeout, raw_limit):
                timeout = int(raw_timeout)  # noqa: CAL-030
                limit = int(raw_limit)
                return client.fetch(timeout=timeout, limit=limit)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [3]


class TestProperties:
    """Formal properties (DPS-12)."""

    def test_determinism_same_file_same_findings(self, detector, tmp_path):
        """Determinism / INVARIANT: same input -> identical findings on repeat."""
        code = """
            import os


            def run(client, cfg):
                timeout = int(os.environ.get("T", "30"))
                retries = cfg.get("retries", 3)
                port = int(cfg["port"])
                return client.connect(port, timeout=timeout, retries=retries)
            """
        path = _write(tmp_path, code)

        first = detector.detect(path)
        second = detector.detect(path)

        assert len(first) == 3
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_unparseable_file(self, detector, tmp_path):
        """Availability / LIVENESS: a syntax error never raises, returns []."""
        path = tmp_path / "broken.py"
        path.write_text("def run(client):\n    timeout = int(\n")

        assert detector.detect(path) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability / LIVENESS: a nonexistent path never raises, returns []."""
        assert detector.detect(tmp_path / "does_not_exist.py") == []

    def test_fail_open_on_binary_content(self, detector, tmp_path):
        """Availability / LIVENESS: undecodable bytes never raise, return []."""
        path = tmp_path / "blob.py"
        path.write_bytes(b"\x00\xff\xfe timeout = int( \x00 fetch(")

        assert detector.detect(path) == []
