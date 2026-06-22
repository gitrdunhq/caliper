# tested-by: tests/unit/test_subprocess_tool_runner.py
"""SubprocessToolRunner — concrete ToolRunnerPort backed by subprocess.run.

Implements the seam defined in eedom.core.tool_runner so that scanner plugins
never depend on subprocess directly.
"""

from __future__ import annotations

import subprocess
import time

from eedom.core.tool_runner import ToolInvocation, ToolResult


class SubprocessToolRunner:
    """Execute external tools via subprocess.run.

    Satisfies the ToolRunnerPort structural protocol.  All exceptions from
    subprocess are caught and surfaced as typed fields on ToolResult so that
    callers never have to handle raw subprocess exceptions.
    """

    def run(self, invocation: ToolInvocation) -> ToolResult:
        start = time.monotonic()
        try:
            completed = subprocess.run(
                invocation.cmd,
                capture_output=True,
                text=True,
                errors="replace",  # binary/non-UTF-8 tool output must not raise UnicodeDecodeError
                cwd=invocation.cwd,
                timeout=invocation.timeout,
                env=invocation.env,
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            return ToolResult(
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                timed_out=False,
                duration_ms=duration_ms,
                not_installed=False,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ToolResult(
                exit_code=-1,
                stdout="",
                stderr="",
                timed_out=True,
                duration_ms=duration_ms,
                not_installed=False,
            )
        except FileNotFoundError:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ToolResult(
                exit_code=-1,
                stdout="",
                stderr="",
                timed_out=False,
                duration_ms=duration_ms,
                not_installed=True,
            )
        except OSError as exc:
            # PermissionError, NotADirectoryError, ... — degrade, never propagate
            # (the seam's contract is that callers never see a raw subprocess exception).
            duration_ms = int((time.monotonic() - start) * 1000)
            return ToolResult(
                exit_code=-1,
                stdout="",
                stderr=f"subprocess error: {exc}",
                timed_out=False,
                duration_ms=duration_ms,
                not_installed=False,
            )
