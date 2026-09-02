"""Scanner plugins honor CaliperSettings.scanner_timeout and report the real value.
# tested-by: tests/unit/test_plugin_timeouts.py

A whole-repo review on a large monorepo reported ``syft timed out after 0s``
and ``osv-scanner timed out after 0s``: the plugins hard-coded their own
timeouts and passed ``timeout=0`` to the error message. Every subprocess
plugin must take the timeout from settings (so ``CALIPER_SCANNER_TIMEOUT``
raises it for big repos) and say how long it actually waited.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from caliper.core.config import CaliperSettings
from caliper.core.tool_runner import ToolInvocation, ToolResult
from caliper.plugins.ls_lint import LsLintPlugin
from caliper.plugins.osv_scanner import OsvScannerPlugin
from caliper.plugins.syft import SyftPlugin
from caliper.plugins.trivy import TrivyPlugin

_SETTINGS = CaliperSettings(scanner_timeout=7)


def _expired(*args, **kwargs):
    raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 0))


@pytest.mark.parametrize(
    ("plugin_cls", "module", "tool"),
    [
        (SyftPlugin, "caliper.plugins.syft", "syft"),
        (OsvScannerPlugin, "caliper.plugins.osv_scanner", "osv-scanner"),
        (LsLintPlugin, "caliper.plugins.ls_lint", "ls-lint"),
    ],
)
def test_subprocess_plugins_use_and_report_settings_timeout(
    plugin_cls, module: str, tool: str, tmp_path: Path
) -> None:
    with patch(f"{module}.subprocess.run", side_effect=_expired) as run:
        result = plugin_cls(settings=_SETTINGS).run(["package.json"], tmp_path)

    assert run.call_args.kwargs["timeout"] == 7
    assert result.error == f"[TIMEOUT] {tool} timed out after 7s"
    assert result.findings == []


class _TimedOutRunner:
    def __init__(self) -> None:
        self.invocation: ToolInvocation | None = None

    def run(self, invocation: ToolInvocation) -> ToolResult:
        self.invocation = invocation
        return ToolResult(stdout="", stderr="", exit_code=-1, timed_out=True, not_installed=False)


def test_trivy_uses_and_reports_settings_timeout(tmp_path: Path) -> None:
    runner = _TimedOutRunner()
    result = TrivyPlugin(tool_runner=runner, settings=_SETTINGS).run([], tmp_path)

    assert runner.invocation is not None and runner.invocation.timeout == 7
    assert result.error == "[TIMEOUT] trivy timed out after 7s"


def test_default_timeout_comes_from_settings_defaults(monkeypatch) -> None:
    monkeypatch.setenv("CALIPER_SCANNER_TIMEOUT", "300")
    assert SyftPlugin()._timeout == 300
    assert OsvScannerPlugin()._timeout == 300
    assert LsLintPlugin()._timeout == 300
    assert TrivyPlugin()._timeout == 300


class TestOsvSkipsIgnoredDirs:
    """osv-scanner walks the repo itself, so the ignore layer's plain directory
    patterns (tests/, node_modules/, ...) must reach it as exclusions."""

    def test_default_run_excludes_test_dirs(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("CALIPER_INCLUDE_TESTS", raising=False)
        with patch("caliper.plugins.osv_scanner.subprocess.run", side_effect=_expired) as run:
            OsvScannerPlugin(settings=_SETTINGS).run(["package.json"], tmp_path)
        cmd = run.call_args.args[0]
        assert "--experimental-exclude=tests" in cmd
        assert "--experimental-exclude=node_modules" in cmd
        assert not any(a.endswith("*.egg-info") for a in cmd)  # globs are not paths

    def test_include_tests_keeps_test_dirs(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("CALIPER_INCLUDE_TESTS", "1")
        with patch("caliper.plugins.osv_scanner.subprocess.run", side_effect=_expired) as run:
            OsvScannerPlugin(settings=_SETTINGS).run(["package.json"], tmp_path)
        assert "--experimental-exclude=tests" not in run.call_args.args[0]
