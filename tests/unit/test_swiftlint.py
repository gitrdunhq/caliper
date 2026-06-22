"""Tests for SwiftLint plugin.
# tested-by: tests/unit/test_swiftlint.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from caliper.core.plugin import PluginCategory
from caliper.core.tool_runner import ToolResult
from caliper.plugins.swiftlint import SwiftLintPlugin

_REPO = Path("/workspace")

_SWIFT_FILES = ["Sources/App/ViewController.swift", "Sources/App/Service.swift"]
_NON_SWIFT_FILES = ["main.py", "package.json", "Dockerfile"]

_FINDINGS_OUTPUT = json.dumps(
    [
        {
            "character": 28,
            "file": "/workspace/Sources/App/ViewController.swift",
            "line": 42,
            "reason": "Force casts should be avoided.",
            "rule_id": "force_cast",
            "severity": "Error",
            "type": "Force Cast",
            "url": "https://realm.github.io/SwiftLint/force_cast.html",
        },
        {
            "character": 10,
            "file": "/workspace/Sources/App/Service.swift",
            "line": 15,
            "reason": "Force tries should be avoided.",
            "rule_id": "force_try",
            "severity": "Error",
            "type": "Force Try",
            "url": "https://realm.github.io/SwiftLint/force_try.html",
        },
        {
            "character": 5,
            "file": "/workspace/Sources/App/ViewController.swift",
            "line": 78,
            "reason": "Use os.Logger instead of print().",
            "rule_id": "no_print",
            "severity": "Warning",
            "type": "No Print",
            "url": "",
        },
    ]
)

_CLEAN_OUTPUT = json.dumps([])


def _tool_result(stdout: str, exit_code: int = 0, not_installed: bool = False) -> ToolResult:
    return ToolResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        not_installed=not_installed,
    )


class TestSwiftLintPluginIdentity:
    def test_name(self) -> None:
        assert SwiftLintPlugin().name == "swiftlint"

    def test_category_is_code(self) -> None:
        assert SwiftLintPlugin().category == PluginCategory.code

    def test_description_mentions_swift(self) -> None:
        assert "swift" in SwiftLintPlugin().description.lower()


class TestSwiftLintPluginCanRun:
    def test_runs_on_swift_files(self) -> None:
        p = SwiftLintPlugin()
        assert p.can_run(_SWIFT_FILES, _REPO) is True

    def test_skips_non_swift_repos(self) -> None:
        p = SwiftLintPlugin()
        assert p.can_run(_NON_SWIFT_FILES, _REPO) is False

    def test_runs_on_mixed_file_list(self) -> None:
        p = SwiftLintPlugin()
        assert p.can_run(_SWIFT_FILES + _NON_SWIFT_FILES, _REPO) is True

    def test_skips_empty_file_list(self) -> None:
        p = SwiftLintPlugin()
        assert p.can_run([], _REPO) is False


class TestSwiftLintPluginRun:
    def _make_plugin(
        self, stdout: str, exit_code: int = 0, not_installed: bool = False
    ) -> SwiftLintPlugin:
        runner = MagicMock()
        runner.run.return_value = _tool_result(stdout, exit_code, not_installed)
        return SwiftLintPlugin(tool_runner=runner)

    def test_clean_scan_returns_no_findings(self) -> None:
        p = self._make_plugin(_CLEAN_OUTPUT, exit_code=0)
        result = p.run(_SWIFT_FILES, _REPO)
        assert result.error == ""
        assert result.findings == []
        assert result.summary.get("violations", 0) == 0

    def test_findings_are_parsed(self) -> None:
        p = self._make_plugin(_FINDINGS_OUTPUT, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        assert result.error == ""
        assert len(result.findings) == 3

    def test_error_findings_map_to_error_severity(self) -> None:
        p = self._make_plugin(_FINDINGS_OUTPUT, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        force_cast = next(f for f in result.findings if f["rule_id"] == "force_cast")
        assert force_cast["severity"] == "error"

    def test_warning_findings_map_to_warning_severity(self) -> None:
        p = self._make_plugin(_FINDINGS_OUTPUT, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        no_print = next(f for f in result.findings if f["rule_id"] == "no_print")
        assert no_print["severity"] == "warning"

    def test_file_paths_are_relative_to_repo(self) -> None:
        p = self._make_plugin(_FINDINGS_OUTPUT, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        for f in result.findings:
            assert not f["file"].startswith(
                "/workspace"
            ), f"Expected relative path, got absolute: {f['file']}"

    def test_summary_counts_violations(self) -> None:
        p = self._make_plugin(_FINDINGS_OUTPUT, exit_code=1)
        result = p.run(_SWIFT_FILES, _REPO)
        assert result.summary["violations"] == 3

    def test_not_installed_returns_error(self) -> None:
        p = self._make_plugin("", not_installed=True)
        result = p.run(_SWIFT_FILES, _REPO)
        assert "NOT_INSTALLED" in result.error
        assert result.findings == []

    def test_timed_out_returns_error(self) -> None:
        runner = MagicMock()
        runner.run.return_value = ToolResult(exit_code=-1, stdout="", stderr="", timed_out=True)
        p = SwiftLintPlugin(tool_runner=runner)
        result = p.run(_SWIFT_FILES, _REPO)
        assert "TIMEOUT" in result.error

    def test_invalid_json_returns_error(self) -> None:
        p = self._make_plugin("not json", exit_code=0)
        result = p.run(_SWIFT_FILES, _REPO)
        assert "PARSE_ERROR" in result.error

    def test_only_swift_files_passed_to_binary(self) -> None:
        runner = MagicMock()
        runner.run.return_value = _tool_result(_CLEAN_OUTPUT)
        p = SwiftLintPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES + _NON_SWIFT_FILES, _REPO)
        cmd = runner.run.call_args[0][0].cmd
        passed_files = [a for a in cmd if a.endswith(".swift")]
        non_swift = [a for a in cmd if a.endswith((".py", ".json"))]
        assert len(passed_files) > 0
        assert non_swift == []

    def test_uses_custom_config_when_present(self, tmp_path: Path) -> None:
        custom_config = tmp_path / ".caliper" / "swiftlint.yml"
        custom_config.parent.mkdir()
        custom_config.write_text("disabled_rules: []\n")
        runner = MagicMock()
        runner.run.return_value = _tool_result(_CLEAN_OUTPUT)
        p = SwiftLintPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES, tmp_path)
        cmd = runner.run.call_args[0][0].cmd
        config_idx = cmd.index("--config")
        assert ".caliper/swiftlint.yml" in cmd[config_idx + 1]

    def test_uses_project_swiftlint_yml_when_present(self, tmp_path: Path) -> None:
        project_config = tmp_path / ".swiftlint.yml"
        project_config.write_text("disabled_rules: []\n")
        runner = MagicMock()
        runner.run.return_value = _tool_result(_CLEAN_OUTPUT)
        p = SwiftLintPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES, tmp_path)
        cmd = runner.run.call_args[0][0].cmd
        config_idx = cmd.index("--config")
        assert str(project_config) in cmd[config_idx + 1]

    def test_dom_override_takes_precedence_over_project_config(self, tmp_path: Path) -> None:
        (tmp_path / ".swiftlint.yml").write_text("disabled_rules: []\n")
        dom_config = tmp_path / ".caliper" / "swiftlint.yml"
        dom_config.parent.mkdir()
        dom_config.write_text("disabled_rules: [force_cast]\n")
        runner = MagicMock()
        runner.run.return_value = _tool_result(_CLEAN_OUTPUT)
        p = SwiftLintPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES, tmp_path)
        cmd = runner.run.call_args[0][0].cmd
        config_idx = cmd.index("--config")
        assert ".caliper/swiftlint.yml" in cmd[config_idx + 1]

    def test_uses_bundled_config_as_last_resort(self) -> None:
        runner = MagicMock()
        runner.run.return_value = _tool_result(_CLEAN_OUTPUT)
        p = SwiftLintPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES, _REPO)
        cmd = runner.run.call_args[0][0].cmd
        config_idx = cmd.index("--config")
        assert "swiftlint" in cmd[config_idx + 1]

    def test_symlinked_project_config_outside_repo_uses_bundled(self, tmp_path: Path) -> None:
        """Symlink inside repo pointing to a config outside repo_path must be rejected."""
        import os

        external = tmp_path.parent / "external_swiftlint.yml"
        external.write_text("disabled_rules: []\n")
        symlink_config = tmp_path / ".swiftlint.yml"
        os.symlink(external, symlink_config)

        runner = MagicMock()
        runner.run.return_value = _tool_result(_CLEAN_OUTPUT)
        p = SwiftLintPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES, tmp_path)
        cmd = runner.run.call_args[0][0].cmd
        config_idx = cmd.index("--config")
        assert "external_swiftlint" not in cmd[config_idx + 1]

    def test_symlinked_dom_config_outside_repo_uses_bundled(self, tmp_path: Path) -> None:
        """Symlink inside .caliper/ pointing outside repo_path must be rejected."""
        import os

        external = tmp_path.parent / "evil_swiftlint.yml"
        external.write_text("disabled_rules: []\n")
        caliper_dir = tmp_path / ".caliper"
        caliper_dir.mkdir()
        os.symlink(external, caliper_dir / "swiftlint.yml")

        runner = MagicMock()
        runner.run.return_value = _tool_result(_CLEAN_OUTPUT)
        p = SwiftLintPlugin(tool_runner=runner)
        p.run(_SWIFT_FILES, tmp_path)
        cmd = runner.run.call_args[0][0].cmd
        config_idx = cmd.index("--config")
        assert "evil_swiftlint" not in cmd[config_idx + 1]


class TestSwiftLintPluginRender:
    def test_render_clean_returns_empty(self) -> None:
        from caliper.core.plugin import PluginResult

        p = SwiftLintPlugin()
        result = PluginResult(plugin_name="swiftlint", findings=[])
        assert p.render(result) == ""

    def test_render_findings_produces_markdown_table(self) -> None:
        from caliper.core.plugin import PluginResult

        p = SwiftLintPlugin()
        result = PluginResult(
            plugin_name="swiftlint",
            findings=[
                {
                    "file": "Sources/App/VC.swift",
                    "line": 10,
                    "rule_id": "force_cast",
                    "severity": "error",
                    "message": "Force casts should be avoided.",
                }
            ],
            summary={"violations": 1},
        )
        rendered = p.render(result)
        assert "force_cast" in rendered
        assert "VC.swift" in rendered

    def test_render_error_shows_error(self) -> None:
        from caliper.core.plugin import PluginResult

        p = SwiftLintPlugin()
        result = PluginResult(
            plugin_name="swiftlint", error="[NOT_INSTALLED] swiftlint not installed"
        )
        rendered = p.render(result)
        assert "swiftlint" in rendered
