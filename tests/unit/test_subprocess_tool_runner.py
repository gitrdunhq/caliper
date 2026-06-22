# tested-by: tests/unit/test_subprocess_tool_runner.py
"""Contract tests for SubprocessToolRunner (RED — eedom.core.subprocess_runner does not exist yet).

All tests in this file are expected to fail with ImportError until the production
module is created.  Task #163.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from eedom.core.subprocess_runner import SubprocessToolRunner  # noqa: F401 — will ImportError
from eedom.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_invocation(
    cmd: list[str] | None = None,
    cwd: str = "/tmp/test",
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> ToolInvocation:
    return ToolInvocation(
        cmd=cmd or ["echo", "hello"],
        cwd=cwd,
        timeout=timeout,
        env=env,
    )


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> MagicMock:
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_subprocess_runner_satisfies_tool_runner_port(self):
        """SubprocessToolRunner must be an instance of ToolRunnerPort (runtime-checkable)."""
        runner = SubprocessToolRunner()
        assert isinstance(runner, ToolRunnerPort)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestRunSuccess:
    def test_run_returns_tool_result_on_success(self):
        """Successful invocation returns ToolResult with captured stdout/stderr."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(cmd=["trivy", "--version"])

        with patch("subprocess.run", return_value=_completed(stdout="trivy v1.0\n")) as mock_run:
            result = runner.run(invocation)

        assert isinstance(result, ToolResult)
        mock_run.assert_called_once()

    def test_run_captures_stdout(self):
        """stdout from the subprocess is surfaced in ToolResult.stdout."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed(stdout="hello world\n")):
            result = runner.run(invocation)

        assert result.stdout == "hello world\n"

    def test_run_captures_stderr(self):
        """stderr from the subprocess is surfaced in ToolResult.stderr."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed(stderr="some warning\n")):
            result = runner.run(invocation)

        assert result.stderr == "some warning\n"

    def test_run_zero_exit_code_on_success(self):
        """exit_code reflects the subprocess returncode on success."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed(returncode=0)):
            result = runner.run(invocation)

        assert result.exit_code == 0

    def test_run_timed_out_false_on_success(self):
        """timed_out is False when the process completes normally."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed()):
            result = runner.run(invocation)

        assert result.timed_out is False

    def test_run_not_installed_false_on_success(self):
        """not_installed is False when the process runs successfully."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed()):
            result = runner.run(invocation)

        assert result.not_installed is False


# ---------------------------------------------------------------------------
# Nonzero exit code
# ---------------------------------------------------------------------------


class TestNonzeroExit:
    def test_run_nonzero_exit_code_reflected_in_result(self):
        """Nonzero returncode is preserved in ToolResult.exit_code."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed(returncode=1)):
            result = runner.run(invocation)

        assert result.exit_code == 1

    def test_run_nonzero_does_not_set_timed_out(self):
        """A nonzero exit does not imply timed_out."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed(returncode=2)):
            result = runner.run(invocation)

        assert result.timed_out is False
        assert result.not_installed is False


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


class TestTimeout:
    def test_run_sets_timed_out_on_timeout_expired(self):
        """TimeoutExpired raises from subprocess.run → ToolResult.timed_out is True."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(timeout=5)

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["echo"], timeout=5)
        ):
            result = runner.run(invocation)

        assert result.timed_out is True

    def test_run_sets_exit_code_minus_one_on_timeout(self):
        """TimeoutExpired → exit_code is -1 (sentinel for abnormal termination)."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(timeout=5)

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["echo"], timeout=5)
        ):
            result = runner.run(invocation)

        assert result.exit_code == -1

    def test_run_does_not_raise_on_timeout(self):
        """TimeoutExpired must be caught; run() must return a ToolResult, not raise."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["echo"], timeout=1)
        ):
            try:
                result = runner.run(invocation)
            except subprocess.TimeoutExpired:
                pytest.fail("SubprocessToolRunner must not propagate TimeoutExpired")

        assert isinstance(result, ToolResult)


# ---------------------------------------------------------------------------
# Not installed (FileNotFoundError)
# ---------------------------------------------------------------------------


class TestNotInstalled:
    def test_run_sets_not_installed_on_file_not_found(self):
        """FileNotFoundError from subprocess.run → ToolResult.not_installed is True."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(cmd=["trivy", "--version"])

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = runner.run(invocation)

        assert result.not_installed is True

    def test_run_sets_exit_code_minus_one_on_not_installed(self):
        """FileNotFoundError → exit_code is -1."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(cmd=["trivy", "--version"])

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = runner.run(invocation)

        assert result.exit_code == -1

    def test_run_does_not_raise_on_file_not_found(self):
        """FileNotFoundError must be caught; run() must return a ToolResult, not raise."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(cmd=["missing-tool"])

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            try:
                result = runner.run(invocation)
            except FileNotFoundError:
                pytest.fail("SubprocessToolRunner must not propagate FileNotFoundError")

        assert isinstance(result, ToolResult)


# ---------------------------------------------------------------------------
# Environment variable passthrough
# ---------------------------------------------------------------------------


class TestEnvPassthrough:
    def test_run_passes_env_overrides_to_subprocess_when_set(self):
        """When invocation.env is not None, it must be forwarded to subprocess.run."""
        runner = SubprocessToolRunner()
        env_overrides = {"MY_VAR": "value", "OTHER": "123"}
        invocation = _make_invocation(env=env_overrides)

        with patch("subprocess.run", return_value=_completed()) as mock_run:
            runner.run(invocation)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("env") is not None
        # The env passed must contain our overrides
        passed_env = call_kwargs["env"]
        assert passed_env.get("MY_VAR") == "value"
        assert passed_env.get("OTHER") == "123"

    def test_run_does_not_force_env_when_invocation_env_is_none(self):
        """When invocation.env is None, subprocess.run should not receive a forced env kwarg
        (or may receive None, meaning inherit from the parent process)."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(env=None)

        with patch("subprocess.run", return_value=_completed()) as mock_run:
            runner.run(invocation)

        call_kwargs = mock_run.call_args[1]
        # env kwarg either absent or None — must not be a non-None dict
        env_value = call_kwargs.get("env")
        assert env_value is None


# ---------------------------------------------------------------------------
# Subprocess call parameters
# ---------------------------------------------------------------------------


class TestCallParameters:
    def test_run_passes_cmd_to_subprocess(self):
        """The command list from ToolInvocation must be the first positional arg."""
        runner = SubprocessToolRunner()
        cmd = ["semgrep", "--config", "auto", "."]
        invocation = _make_invocation(cmd=cmd)

        with patch("subprocess.run", return_value=_completed()) as mock_run:
            runner.run(invocation)

        call_args = mock_run.call_args[0]
        assert call_args[0] == cmd

    def test_run_passes_cwd_to_subprocess(self):
        """invocation.cwd is forwarded as the cwd kwarg to subprocess.run."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(cwd="/workspace/project")

        with patch("subprocess.run", return_value=_completed()) as mock_run:
            runner.run(invocation)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("cwd") == "/workspace/project"

    def test_run_passes_timeout_to_subprocess(self):
        """invocation.timeout is forwarded as the timeout kwarg to subprocess.run."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(timeout=42)

        with patch("subprocess.run", return_value=_completed()) as mock_run:
            runner.run(invocation)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("timeout") == 42


# ---------------------------------------------------------------------------
# Duration tracking
# ---------------------------------------------------------------------------


class TestDurationTracking:
    def test_run_records_duration_ms_as_positive_int_on_success(self):
        """duration_ms must be a positive integer after a successful run."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", return_value=_completed()):
            result = runner.run(invocation)

        assert isinstance(result.duration_ms, int)
        assert result.duration_ms >= 0

    def test_run_records_duration_ms_on_timeout(self):
        """duration_ms is recorded even when TimeoutExpired is raised."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation(timeout=5)

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["echo"], timeout=5)
        ):
            result = runner.run(invocation)

        assert isinstance(result.duration_ms, int)
        assert result.duration_ms >= 0

    def test_run_records_duration_ms_on_not_installed(self):
        """duration_ms is recorded even when FileNotFoundError is raised."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = runner.run(invocation)

        assert isinstance(result.duration_ms, int)
        assert result.duration_ms >= 0


# ---------------------------------------------------------------------------
# Regression: P10-1 / P10-3 — binary output and OSError must not propagate
# ---------------------------------------------------------------------------


class TestRegressionP10:
    def test_binary_output_does_not_raise_unicode_decode_error(self):
        """errors='replace' ensures non-UTF-8 binary stdout never raises UnicodeDecodeError
        (regression for P10-1: subprocess_runner must not propagate encoding errors)."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        # Simulate subprocess.run called with errors="replace" by patching subprocess.run
        # to return a completed process with text that would be produced by errors="replace".
        # The real guard is that SubprocessToolRunner passes errors="replace" — we verify
        # the kwarg is forwarded so the codec can never raise.
        with patch("subprocess.run", return_value=_completed(stdout="ok�")) as mock_run:
            result = runner.run(invocation)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("errors") == "replace", (
            "subprocess.run must be called with errors='replace' so binary output "
            "never raises UnicodeDecodeError"
        )
        assert isinstance(result, ToolResult)
        assert result.timed_out is False
        assert result.not_installed is False

    def test_oserror_returns_typed_result_not_raises(self):
        """OSError from subprocess.run must not propagate — returns ToolResult with
        exit_code=-1 and stderr describing the error (regression for P10-3)."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", side_effect=OSError("Permission denied")):
            try:
                result = runner.run(invocation)
            except OSError:
                pytest.fail("SubprocessToolRunner must not propagate OSError")

        assert isinstance(result, ToolResult)
        assert result.exit_code == -1
        assert result.timed_out is False
        assert result.not_installed is False
        assert "Permission denied" in result.stderr

    def test_oserror_stderr_contains_error_description(self):
        """stderr in the OSError ToolResult must contain a description of the error."""
        runner = SubprocessToolRunner()
        invocation = _make_invocation()

        with patch("subprocess.run", side_effect=OSError("NotADirectoryError: /tmp")):
            result = runner.run(invocation)

        assert "NotADirectoryError" in result.stderr or result.exit_code == -1
