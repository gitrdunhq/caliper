"""Contract tests for ToolInvocation, ToolResult, and ToolRunnerPort.
# tested-by: tests/unit/test_tool_runner_port.py

These are RED tests — they define the contract before the implementation exists.
All imports come from caliper.core.tool_runner which does not yet exist.

Task: #162 — Define ToolInvocation, ToolResult, and ToolRunnerPort
"""

from __future__ import annotations


class TestToolInvocationConstruction:
    """ToolInvocation dataclass can be constructed with the required fields."""

    def test_construct_with_required_fields(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        inv = ToolInvocation(cmd=["trivy", "fs", "."], cwd="/repo", timeout=60)

        assert inv.cmd == ["trivy", "fs", "."]
        assert inv.cwd == "/repo"
        assert inv.timeout == 60

    def test_env_defaults_to_none(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        inv = ToolInvocation(cmd=["opa", "eval"], cwd="/tmp/repo", timeout=10)

        assert inv.env is None

    def test_env_can_be_set(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        env = {"HOME": "/root", "PATH": "/usr/bin"}
        inv = ToolInvocation(
            cmd=["cfn_nag_scan", "--input-path", "template.yaml"], cwd="/repo", timeout=30, env=env
        )

        assert inv.env == {"HOME": "/root", "PATH": "/usr/bin"}

    def test_cmd_is_list_of_strings(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        inv = ToolInvocation(cmd=["binary", "--flag", "value"], cwd="/workspace", timeout=45)

        assert isinstance(inv.cmd, list)
        assert all(isinstance(part, str) for part in inv.cmd)

    def test_timeout_is_int(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        inv = ToolInvocation(cmd=["scanner"], cwd="/repo", timeout=120)

        assert isinstance(inv.timeout, int)
        assert inv.timeout == 120

    def test_cwd_is_string(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        inv = ToolInvocation(cmd=["scanner"], cwd="/some/path", timeout=60)

        assert isinstance(inv.cwd, str)

    def test_single_element_cmd(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        inv = ToolInvocation(cmd=["scanner"], cwd="/repo", timeout=60)

        assert inv.cmd == ["scanner"]

    def test_empty_env_dict_is_distinct_from_none(self) -> None:
        from caliper.core.tool_runner import ToolInvocation

        inv = ToolInvocation(cmd=["scanner"], cwd="/repo", timeout=60, env={})

        assert inv.env == {}
        assert inv.env is not None


class TestToolResultConstruction:
    """ToolResult dataclass captures all outcome states from a tool invocation."""

    def test_construct_success_result(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=0, stdout="output", stderr="")

        assert result.exit_code == 0
        assert result.stdout == "output"
        assert result.stderr == ""

    def test_timed_out_defaults_to_false(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=0, stdout="", stderr="")

        assert result.timed_out is False

    def test_duration_ms_defaults_to_zero(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=0, stdout="", stderr="")

        assert result.duration_ms == 0

    def test_not_installed_defaults_to_false(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=0, stdout="", stderr="")

        assert result.not_installed is False

    def test_nonzero_exit_code_is_preserved(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=1, stdout="", stderr="some error")

        assert result.exit_code == 1
        assert result.stderr == "some error"

    def test_timed_out_result_has_meaningful_state(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=-1, stdout="", stderr="", timed_out=True)

        assert result.timed_out is True
        # A timed-out result is a failure: exit_code should not be 0
        assert result.exit_code != 0

    def test_timed_out_result_preserves_partial_stdout(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=-1, stdout="partial output", stderr="", timed_out=True)

        assert result.stdout == "partial output"
        assert result.timed_out is True

    def test_not_installed_result_has_meaningful_state(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=-1, stdout="", stderr="", not_installed=True)

        assert result.not_installed is True
        # A not-installed result is always a failure
        assert result.exit_code != 0

    def test_not_installed_and_timed_out_are_mutually_independent(self) -> None:
        from caliper.core.tool_runner import ToolResult

        # Both flags can be set — the runner decides their semantics
        result = ToolResult(exit_code=-1, stdout="", stderr="", not_installed=True, timed_out=False)

        assert result.not_installed is True
        assert result.timed_out is False

    def test_duration_ms_is_int(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=0, stdout="ok", stderr="", duration_ms=342)

        assert isinstance(result.duration_ms, int)
        assert result.duration_ms == 342

    def test_stderr_is_preserved(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(exit_code=2, stdout="", stderr="fatal: binary crashed")

        assert result.stderr == "fatal: binary crashed"

    def test_all_fields_set_explicitly(self) -> None:
        from caliper.core.tool_runner import ToolResult

        result = ToolResult(
            exit_code=0,
            stdout="clean",
            stderr="",
            timed_out=False,
            duration_ms=1200,
            not_installed=False,
        )

        assert result.exit_code == 0
        assert result.stdout == "clean"
        assert result.stderr == ""
        assert result.timed_out is False
        assert result.duration_ms == 1200
        assert result.not_installed is False


class TestToolRunnerPortProtocol:
    """ToolRunnerPort is a runtime-checkable Protocol."""

    def test_tool_runner_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.tool_runner import ToolRunnerPort

        # Protocol classes have __protocol_attrs__ or are instances of typing.Protocol
        assert hasattr(ToolRunnerPort, "__protocol_attrs__") or (
            hasattr(typing, "get_protocol_members")
            or ToolRunnerPort.__bases__  # typing.Protocol is in __bases__
        )

    def test_tool_runner_port_is_runtime_checkable(self) -> None:
        from caliper.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

        class FakeRunner:
            def run(self, invocation: ToolInvocation) -> ToolResult:
                return ToolResult(exit_code=0, stdout="", stderr="")

        assert isinstance(FakeRunner(), ToolRunnerPort)

    def test_object_without_run_does_not_satisfy_protocol(self) -> None:
        from caliper.core.tool_runner import ToolRunnerPort

        class NotARunner:
            def execute(self) -> None:
                pass

        assert not isinstance(NotARunner(), ToolRunnerPort)

    def test_run_method_is_in_protocol_interface(self) -> None:
        from caliper.core.tool_runner import ToolRunnerPort

        assert hasattr(ToolRunnerPort, "run")


class TestFakeToolRunner:
    """A fake ToolRunner can fulfill the ToolRunnerPort Protocol."""

    def test_fake_runner_returns_success_result(self) -> None:
        from caliper.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

        class FakeRunner:
            def run(self, invocation: ToolInvocation) -> ToolResult:
                return ToolResult(exit_code=0, stdout="ok", stderr="")

        runner = FakeRunner()
        assert isinstance(runner, ToolRunnerPort)

        inv = ToolInvocation(cmd=["trivy", "fs", "."], cwd="/repo", timeout=60)
        result = runner.run(inv)

        assert result.exit_code == 0
        assert result.stdout == "ok"

    def test_fake_runner_returns_timed_out_result(self) -> None:
        from caliper.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

        class TimeoutRunner:
            def run(self, invocation: ToolInvocation) -> ToolResult:
                return ToolResult(exit_code=-1, stdout="", stderr="", timed_out=True)

        runner = TimeoutRunner()
        assert isinstance(runner, ToolRunnerPort)

        inv = ToolInvocation(cmd=["slow-tool"], cwd="/repo", timeout=1)
        result = runner.run(inv)

        assert result.timed_out is True
        assert result.exit_code == -1

    def test_fake_runner_returns_not_installed_result(self) -> None:
        from caliper.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

        class MissingBinaryRunner:
            def run(self, invocation: ToolInvocation) -> ToolResult:
                return ToolResult(exit_code=-1, stdout="", stderr="", not_installed=True)

        runner = MissingBinaryRunner()
        assert isinstance(runner, ToolRunnerPort)

        inv = ToolInvocation(
            cmd=["cfn_nag_scan", "--input-path", "t.yaml"], cwd="/repo", timeout=60
        )
        result = runner.run(inv)

        assert result.not_installed is True

    def test_fake_runner_receives_invocation_fields(self) -> None:
        from caliper.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

        received: list[ToolInvocation] = []

        class CapturingRunner:
            def run(self, invocation: ToolInvocation) -> ToolResult:
                received.append(invocation)
                return ToolResult(exit_code=0, stdout="captured", stderr="")

        runner = CapturingRunner()
        assert isinstance(runner, ToolRunnerPort)

        inv = ToolInvocation(
            cmd=["opa", "eval", "-d", "policies/"],
            cwd="/workspace",
            timeout=10,
            env={"OPA_LOG_LEVEL": "error"},
        )
        runner.run(inv)

        assert len(received) == 1
        assert received[0].cmd == ["opa", "eval", "-d", "policies/"]
        assert received[0].cwd == "/workspace"
        assert received[0].timeout == 10
        assert received[0].env == {"OPA_LOG_LEVEL": "error"}

    def test_fake_runner_can_record_duration(self) -> None:
        from caliper.core.tool_runner import ToolInvocation, ToolResult, ToolRunnerPort

        class TimedRunner:
            def run(self, invocation: ToolInvocation) -> ToolResult:
                return ToolResult(exit_code=0, stdout="done", stderr="", duration_ms=87)

        runner = TimedRunner()
        assert isinstance(runner, ToolRunnerPort)

        result = runner.run(ToolInvocation(cmd=["scanner"], cwd="/repo", timeout=60))

        assert result.duration_ms == 87
