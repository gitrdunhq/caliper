# tested-by: tests/unit/test_tool_runner_port.py
"""ToolInvocation, ToolResult, and ToolRunnerPort contracts.

Defines the seam between scanner plugins and whatever subprocess adapter
actually executes external binaries.  Plugins depend only on this module;
concrete implementations live in the data tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class ToolInvocation:
    """Immutable description of a single external tool call."""

    cmd: list[str]
    cwd: str
    timeout: int
    env: dict[str, str] | None = None


@dataclass
class ToolResult:
    """Outcome captured from a single ToolInvocation."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = field(default=False)
    duration_ms: int = field(default=0)
    not_installed: bool = field(default=False)


@runtime_checkable
class ToolRunnerPort(Protocol):
    """Structural protocol satisfied by any object that can execute a ToolInvocation."""

    def run(self, invocation: ToolInvocation) -> ToolResult: ...
