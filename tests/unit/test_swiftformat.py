"""Tests for SwiftFormat plugin.
# tested-by: tests/unit/test_swiftformat.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from caliper.core.plugin import PluginCategory
from caliper.core.tool_runner import ToolResult
from caliper.plugins.swiftformat import SwiftFormatPlugin

_REPO = Path("/workspace")
_SWIFT_FILES = ["Sources/App/ViewController.swift", "Sources/App/Service.swift"]
_NON_SWIFT = ["main.py", "package.json"]

# swiftformat --lint writes to stderr, stdout is empty
_NEEDS_FORMAT_STDERR = """\
/workspace/Sources/App/ViewController.swift -- would reformat
/workspace/Sources/App/Service.swift -- would reformat

2 files would be reformatted.
"""

_PARTIAL_STDERR = """\
/workspace/Sources/App/Service.swift -- would reformat

1 file would be reformatted.
"""

_CLEAN_STDERR = "\n0 files would be reformatted.\n"


def _make_result(
    stderr: str, exit_code: int = 0, not_installed: bool = False, timed_out: bool = False
) -> ToolResult:
    return ToolResult(
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        not_installed=not_installed,
        timed_out=timed_out,
    )


def _make_plugin(stderr: str, exit_code: int = 0, **kwargs) -> SwiftFormatPlugin:
    runner = MagicMock()
    runner.run.return_value = _make_result(stderr, exit_code, **kwargs)
    return SwiftFormatPlugin(tool_runner=runner)


class TestSwiftFormatPluginIdentity:
    def test_name(self) -> None:
        assert SwiftFormatPlugin().name == "swiftformat"

    def test_category_is_code(self) -> None:
        assert SwiftFormatPlugin().category == PluginCategory.code

    def test_description_mentions_format(self) -> None:
        assert "format" in SwiftFormatPlugin().description.lower()


class TestSwiftFormatPluginCanRun:
    def test_runs_on_swift_files(self) -> None:
        assert SwiftFormatPlugin().can_run(_SWIFT_FILES, _REPO) is True

    def test_skips_non_swift_files(self) -> None:
        assert SwiftFormatPlugin().can_run(_NON_SWIFT, _REPO) is False

    def test_skips_empty_list(self) -> None:
        assert SwiftFormatPlugin().can_run([], _REPO) is False


class TestSwiftFormatPluginRun:
    def test_clean_returns_no_findings(self) -> None:
        p = _make_plugin(_CLEAN_STDERR, exit_code=0)
        result = p.run(_SWIFT_FILES, _REPO)
        assert result.error == ""
        assert result.findings == []
        assert result.summary.get("files_to_reformat", 0) == 0

    def test_dirty_files_produce_findings(self) -> None:
        p = _make_plugin(_NEEDS_FORMAT_STDERR, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        assert result.error == ""
        assert len(result.findings) == 2

    def test_one_dirty_file_produces_one_finding(self) -> None:
        p = _make_plugin(_PARTIAL_STDERR, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        assert len(result.findings) == 1

    def test_findings_have_info_severity(self) -> None:
        p = _make_plugin(_NEEDS_FORMAT_STDERR, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        for f in result.findings:
            assert f["severity"] == "info"

    def test_findings_include_fix_command_in_message(self) -> None:
        p = _make_plugin(_NEEDS_FORMAT_STDERR, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        for f in result.findings:
            assert "swiftformat" in f["message"].lower()

    def test_file_paths_are_relative(self) -> None:
        p = _make_plugin(_NEEDS_FORMAT_STDERR, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        for f in result.findings:
            assert not f["file"].startswith("/workspace")

    def test_summary_counts_files_to_reformat(self) -> None:
        p = _make_plugin(_NEEDS_FORMAT_STDERR, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        assert result.summary["files_to_reformat"] == 2

    def test_not_installed_returns_error(self) -> None:
        p = _make_plugin("", not_installed=True)
        result = p.run(_SWIFT_FILES, _REPO)
        assert "NOT_INSTALLED" in result.error
        assert result.findings == []

    def test_timeout_returns_error(self) -> None:
        p = _make_plugin("", timed_out=True)
        result = p.run(_SWIFT_FILES, _REPO)
        assert "TIMEOUT" in result.error

    def test_only_swift_files_passed_to_binary(self) -> None:
        runner = MagicMock()
        runner.run.return_value = _make_result(_CLEAN_STDERR)
        p = SwiftFormatPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES + _NON_SWIFT, _REPO)
        cmd = runner.run.call_args[0][0].cmd
        non_swift = [a for a in cmd if a.endswith((".py", ".json"))]
        assert non_swift == []

    def test_passes_lint_flag(self) -> None:
        runner = MagicMock()
        runner.run.return_value = _make_result(_CLEAN_STDERR)
        p = SwiftFormatPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES, _REPO)
        cmd = runner.run.call_args[0][0].cmd
        assert "--lint" in cmd


class TestSwiftFormatPluginRender:
    def test_render_clean_is_empty(self) -> None:
        from caliper.core.plugin import PluginResult

        p = SwiftFormatPlugin()
        assert p.render(PluginResult(plugin_name="swiftformat")) == ""

    def test_render_findings_shows_fix_command(self) -> None:
        from caliper.core.plugin import PluginResult

        p = SwiftFormatPlugin()
        result = PluginResult(
            plugin_name="swiftformat",
            findings=[
                {
                    "file": "Sources/App/Foo.swift",
                    "line": 0,
                    "severity": "info",
                    "message": "Would reformat",
                }
            ],
            summary={"files_to_reformat": 1},
        )
        rendered = p.render(result)
        assert "swiftformat" in rendered
        assert "Foo.swift" in rendered

    def test_render_error_shows_message(self) -> None:
        from caliper.core.plugin import PluginResult

        p = SwiftFormatPlugin()
        result = PluginResult(
            plugin_name="swiftformat", error="[NOT_INSTALLED] swiftformat not installed"
        )
        assert "swiftformat" in p.render(result)
