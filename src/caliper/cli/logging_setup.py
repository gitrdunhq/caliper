"""CLI logging: quiet by default, `-v` or CALIPER_LOG_LEVEL for more.
# tested-by: tests/unit/test_logging_setup.py

structlog was never configured, so every debug event from every plugin went
straight to the terminal. Logs go to stderr so stdout stays a clean report.
"""

from __future__ import annotations

import logging
import sys

import structlog

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "error": logging.ERROR,
}


def resolve_log_level(*, verbose: bool, env: dict[str, str]) -> int:
    """``-v`` wins; else ``CALIPER_LOG_LEVEL``; else WARNING. Unknown values fall back."""
    if verbose:
        return logging.DEBUG
    return _LEVELS.get(env.get("CALIPER_LOG_LEVEL", "").strip().lower(), logging.WARNING)


def _stderr_logger(*_args: object) -> structlog.PrintLogger:
    # Resolve sys.stderr per call, not at configure time: a stream captured
    # by a test runner (CliRunner) is closed afterwards, and a logger pinned to
    # it would raise on every later log line.
    return structlog.PrintLogger(file=sys.stderr)


def configure_logging(level: int) -> None:
    """Route structlog to stderr, filtered at *level*."""
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=_stderr_logger,
        cache_logger_on_first_use=False,
    )
