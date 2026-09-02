"""CLI logging: quiet by default, debug on request.
# tested-by: tests/unit/test_logging_setup.py

A container run printed a `repo_config.not_found` debug line per plugin to
stderr because structlog was never configured; everything at every level went
straight to the terminal.
"""

from __future__ import annotations

import logging

import structlog

from caliper.cli.logging_setup import configure_logging, resolve_log_level


class TestResolveLogLevel:
    def test_default_is_warning(self) -> None:
        assert resolve_log_level(verbose=False, env={}) == logging.WARNING

    def test_verbose_flag_is_debug(self) -> None:
        assert resolve_log_level(verbose=True, env={}) == logging.DEBUG

    def test_env_overrides_default(self) -> None:
        assert resolve_log_level(verbose=False, env={"CALIPER_LOG_LEVEL": "info"}) == logging.INFO
        assert resolve_log_level(verbose=False, env={"CALIPER_LOG_LEVEL": "DEBUG"}) == logging.DEBUG

    def test_flag_beats_env(self) -> None:
        assert resolve_log_level(verbose=True, env={"CALIPER_LOG_LEVEL": "error"}) == logging.DEBUG

    def test_bad_env_value_falls_back_to_warning(self) -> None:
        assert (
            resolve_log_level(verbose=False, env={"CALIPER_LOG_LEVEL": "loud"}) == logging.WARNING
        )


class TestConfigureLogging:
    def test_debug_is_filtered_at_default_level(self, capsys) -> None:
        configure_logging(logging.WARNING)
        log = structlog.get_logger("t")
        log.debug("hidden.event", k=1)
        log.warning("shown.event", k=2)
        err = capsys.readouterr().err
        assert "hidden.event" not in err
        assert "shown.event" in err

    def test_debug_shows_when_verbose(self, capsys) -> None:
        configure_logging(logging.DEBUG)
        structlog.get_logger("t").debug("visible.event")
        assert "visible.event" in capsys.readouterr().err

    def test_logs_go_to_stderr_not_stdout(self, capsys) -> None:
        configure_logging(logging.WARNING)
        structlog.get_logger("t").warning("stderr.only")
        out, err = capsys.readouterr()
        assert "stderr.only" in err and "stderr.only" not in out


def test_logger_follows_current_stderr_not_the_one_at_configure_time(capsys) -> None:
    """A stream captured then closed by a CLI test runner must not break later logging."""
    import io
    import logging
    import sys

    import structlog

    from caliper.cli.logging_setup import configure_logging

    stale = io.StringIO()
    real = sys.stderr
    sys.stderr = stale
    try:
        configure_logging(logging.WARNING)
    finally:
        sys.stderr = real
    stale.close()
    structlog.get_logger().warning("still.alive")  # must not raise ValueError
    assert "still.alive" in capsys.readouterr().err


def test_exceptions_render_as_plain_tracebacks_not_rich(capsys) -> None:
    """exc_info logs must be cheap and greppable: the rich renderer prints boxed
    frames with every local variable, which is slow enough to blow Hypothesis
    deadlines on fail-open parse paths and leaks values into CI logs."""
    import logging

    import structlog

    from caliper.cli.logging_setup import configure_logging

    configure_logging(logging.WARNING)
    try:
        raise ValueError("boom")
    except ValueError:
        structlog.get_logger().warning("parse.failed", exc_info=True)
    err = capsys.readouterr().err
    assert "Traceback (most recent call last)" in err
    assert "ValueError: boom" in err
    assert "❱" not in err and "╭" not in err and "locals" not in err
