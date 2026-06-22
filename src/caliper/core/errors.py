"""Centralized error codes and messages for Caliper.
# tested-by: tests/unit/test_plugin_registry.py

Every plugin and runner uses these. Uniform format, greppable codes.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    NOT_INSTALLED = "NOT_INSTALLED"
    TIMEOUT = "TIMEOUT"
    PARSE_ERROR = "PARSE_ERROR"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    BINARY_CRASHED = "BINARY_CRASHED"
    NO_OUTPUT = "NO_OUTPUT"
    SCANNER_DEGRADED = "SCANNER_DEGRADED"
    CONFIG_MISSING = "CONFIG_MISSING"
    INDEX_FAILED = "INDEX_FAILED"
    NETWORK_ERROR = "NETWORK_ERROR"


_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.NOT_INSTALLED: "{tool} not installed",
    ErrorCode.TIMEOUT: "{tool} timed out after {timeout}s",
    ErrorCode.PARSE_ERROR: "{tool} output could not be parsed",
    ErrorCode.PERMISSION_DENIED: "{tool} permission denied",
    ErrorCode.BINARY_CRASHED: "{tool} crashed (exit {exit_code})",
    ErrorCode.NO_OUTPUT: "{tool} produced no output",
    ErrorCode.SCANNER_DEGRADED: "{tool} scanner degraded: {detail}",
    ErrorCode.CONFIG_MISSING: "{tool} config not found at {path}",
    ErrorCode.INDEX_FAILED: "{tool} indexing failed: {detail}",
    ErrorCode.NETWORK_ERROR: "{tool} network error: {detail}",
}


def error_msg(
    code: ErrorCode,
    tool: str,
    **kwargs: str | int,
) -> str:
    template = _MESSAGES.get(code, "{tool}: unknown error")
    return f"[{code}] {template.format(tool=tool, **kwargs)}"
