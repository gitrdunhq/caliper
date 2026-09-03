"""Tests for the blocking-call-inside-async-function detector (CAL-028, #499).
# tested-by: tests/unit/detectors/cloud/test_blocking_call_in_async.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.blocking_call_in_async import (
    BlockingCallInAsyncDetector,
)

DETECTOR_ID = "CAL-028"
DETECTOR_NAME = "Blocking Call Inside Async Function"


def _write(tmp_path: Path, code: str, name: str = "service.py") -> Path:
    """Write dedented ``code`` so that its first source line is line 1."""
    target = tmp_path / name
    target.write_text(textwrap.dedent(code).lstrip("\n"))
    return target


@pytest.fixture
def detector() -> BlockingCallInAsyncDetector:
    return BlockingCallInAsyncDetector()


class TestMetadata:
    """Identity contract for CAL-028."""

    def test_detector_id(self, detector):
        assert detector.detector_id == DETECTOR_ID

    def test_name(self, detector):
        assert detector.name == DETECTOR_NAME

    def test_category_is_reliability(self, detector):
        assert detector.category == DetectorCategory.reliability

    def test_severity_is_high(self, detector):
        assert detector.severity == FindingSeverity.high

    def test_targets_python_only(self, detector):
        assert detector.target_files == ("*.py",)


class TestBlockingCallees:
    """Every blocking callee family fires exactly once at the call line."""

    def test_time_sleep_fires_with_full_finding_contract(self, detector, tmp_path):
        code = """
            import time


            async def worker():
                time.sleep(1)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == DETECTOR_ID
        assert finding.detector_name == DETECTOR_NAME
        assert finding.category == DetectorCategory.reliability
        assert finding.severity == FindingSeverity.high
        assert finding.file_path == str(path)
        assert finding.line_number == 5
        assert finding.issue_reference == "#499"

    def test_bare_sleep_fires_when_imported_from_time(self, detector, tmp_path):
        code = """
            from time import sleep


            async def worker():
                sleep(1)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_requests_get_fires(self, detector, tmp_path):
        code = """
            import requests


            async def fetch(url):
                return requests.get(url)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_requests_session_post_fires(self, detector, tmp_path):
        code = """
            import requests


            async def send(url, payload):
                return requests.Session().post(url, json=payload)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_urllib_urlopen_fires(self, detector, tmp_path):
        code = """
            import urllib.request


            async def fetch(url):
                with urllib.request.urlopen(url) as resp:
                    return resp.read()
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    @pytest.mark.parametrize("method", ["run", "check_output"])
    def test_subprocess_methods_fire(self, detector, tmp_path, method):
        code = f"""
            import subprocess


            async def build():
                return subprocess.{method}(["make"])
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_socket_create_connection_fires(self, detector, tmp_path):
        code = """
            import socket


            async def ping(host):
                return socket.create_connection((host, 80))
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_method_on_module_level_redis_client_fires(self, detector, tmp_path):
        code = """
            import redis

            r = redis.Redis(host="localhost")


            async def read_key(key):
                return r.get(key)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 7

    def test_method_on_function_local_sqlite_connection_fires(self, detector, tmp_path):
        code = """
            import sqlite3


            async def load(path):
                conn = sqlite3.connect(path)
                return conn.execute("select 1")
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [6]

    def test_two_offending_calls_yield_two_findings_in_line_order(self, detector, tmp_path):
        code = """
            import time

            import requests


            async def sync_then_fetch(url):
                time.sleep(0.5)
                data = requests.get(url)
                return data
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [7, 8]
        assert {f.detector_id for f in findings} == {DETECTOR_ID}

    def test_message_names_callee_and_function_and_event_loop(self, detector, tmp_path):
        code = """
            import time


            async def worker():
                time.sleep(1)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        message = findings[0].message
        assert "time.sleep" in message
        assert "worker" in message
        assert "event loop" in message.lower()
        assert "asyncio.to_thread" in findings[0].fix_hint

    def test_nested_async_def_is_reported_under_its_own_name(self, detector, tmp_path):
        code = """
            import time


            async def outer():
                async def inner():
                    time.sleep(1)

                await inner()
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 6
        assert "inner" in findings[0].message
        assert "outer" not in findings[0].message


class TestNegativeCases:
    """Spec-listed cases that must produce no finding."""

    def test_same_calls_inside_plain_def_are_ignored(self, detector, tmp_path):
        code = """
            import subprocess
            import time

            import requests


            def worker(url):
                time.sleep(1)
                requests.get(url)
                subprocess.run(["make"])
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_asyncio_sleep_is_not_blocking(self, detector, tmp_path):
        code = """
            import asyncio


            async def worker():
                await asyncio.sleep(1)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_sleep_without_time_import_is_ignored(self, detector, tmp_path):
        code = """
            async def worker(sleep):
                sleep(1)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_awaited_async_http_client_is_ignored(self, detector, tmp_path):
        code = """
            import httpx


            async def fetch(url):
                async with httpx.AsyncClient() as client:
                    return await client.get(url)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_asyncio_create_subprocess_is_ignored(self, detector, tmp_path):
        code = """
            import asyncio


            async def build():
                proc = await asyncio.create_subprocess_exec("make")
                await proc.wait()
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_requests_inside_nested_sync_def_is_ignored(self, detector, tmp_path):
        code = """
            import requests


            async def fetch(url):
                def do_get():
                    return requests.get(url)

                return do_get
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_asyncio_to_thread_wrapper_is_exempt(self, detector, tmp_path):
        code = """
            import asyncio

            import requests


            async def fetch(url):
                return await asyncio.to_thread(requests.get, url)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_loop_run_in_executor_wrapper_is_exempt(self, detector, tmp_path):
        code = """
            import asyncio
            import time


            async def pause():
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, time.sleep, 1)
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_empty_async_function_has_no_findings(self, detector, tmp_path):
        code = """
            async def noop():
                return None
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []


class TestNoqaSuppression:
    """``# noqa`` on the call line silences the detector."""

    def test_noqa_with_detector_code_suppresses(self, detector, tmp_path):
        code = """
            import time


            async def worker():
                time.sleep(1)  # noqa: CAL-028
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_bare_noqa_suppresses(self, detector, tmp_path):
        code = """
            import time


            async def worker():
                time.sleep(1)  # noqa
            """
        path = _write(tmp_path, code)

        assert detector.detect(path) == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        code = """
            import time


            async def worker():
                time.sleep(1)  # noqa: CAL-012
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 5

    def test_noqa_only_suppresses_its_own_line(self, detector, tmp_path):
        code = """
            import time


            async def worker():
                time.sleep(1)  # noqa: CAL-028
                time.sleep(2)
            """
        path = _write(tmp_path, code)

        findings = detector.detect(path)

        assert [f.line_number for f in findings] == [6]


class TestProperties:
    """Formal properties (DPS-12)."""

    def test_determinism_same_file_same_findings(self, detector, tmp_path):
        """Determinism / INVARIANT: same input -> identical findings on repeat."""
        code = """
            import subprocess
            import time

            import requests


            async def worker(url):
                time.sleep(1)
                requests.get(url)
                subprocess.run(["make"])
            """
        path = _write(tmp_path, code)

        first = detector.detect(path)
        second = detector.detect(path)

        assert len(first) == 3
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_unparseable_file(self, detector, tmp_path):
        """Availability / LIVENESS: a syntax error never raises, returns []."""
        path = tmp_path / "broken.py"
        path.write_text("import time\nasync def worker(:\n    time.sleep(\n")

        assert detector.detect(path) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability / LIVENESS: a nonexistent path never raises, returns []."""
        assert detector.detect(tmp_path / "does_not_exist.py") == []

    def test_fail_open_on_binary_content(self, detector, tmp_path):
        """Availability / LIVENESS: undecodable bytes never raise, return []."""
        path = tmp_path / "blob.py"
        path.write_bytes(b"\x00\xff\xfe async def \x00 time.sleep(")

        assert detector.detect(path) == []
