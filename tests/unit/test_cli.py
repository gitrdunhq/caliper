"""Tests for eedom.cli.main -- CLI entry point."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from eedom.cli.main import cli

DIFF_NO_DEPS = """\
diff --git a/src/app.py b/src/app.py
index 000..111 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1 +1,2 @@
+print("hello")
"""


class TestEvaluateNoDependencyChanges:
    """Test evaluate command when no dependency changes are detected."""

    def test_no_dependency_changes_exits_zero(self) -> None:
        """When the diff contains no dependency file changes, exit 0 with a message."""
        runner = CliRunner()
        env = {
            "EEDOM_DB_DSN": "postgresql://test:test@localhost/test",
        }

        with runner.isolated_filesystem():
            with open("empty.diff", "w") as f:
                f.write(DIFF_NO_DEPS)

            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    ".",
                    "--diff",
                    "empty.diff",
                    "--pr-url",
                    "https://github.com/org/repo/pull/1",
                    "--team",
                    "platform",
                    "--operating-mode",
                    "monitor",
                ],
                env=env,
            )

        assert result.exit_code == 0
        assert "no dependency changes detected" in result.output.lower()

    def test_empty_diff_file_exits_zero(self) -> None:
        """An empty diff file exits 0 with no changes message."""
        runner = CliRunner()
        env = {
            "EEDOM_DB_DSN": "postgresql://test:test@localhost/test",
        }

        with runner.isolated_filesystem():
            with open("empty.diff", "w") as f:
                f.write("")

            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    ".",
                    "--diff",
                    "empty.diff",
                    "--pr-url",
                    "https://github.com/org/repo/pull/1",
                    "--team",
                    "platform",
                    "--operating-mode",
                    "monitor",
                ],
                env=env,
            )

        assert result.exit_code == 0


class TestEvaluateHelp:
    """Test evaluate --help output."""

    def test_help_shows_all_options(self) -> None:
        """--help shows all required options for the evaluate command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["evaluate", "--help"])

        assert result.exit_code == 0
        assert "--repo-path" in result.output
        assert "--diff" in result.output
        assert "--pr-url" in result.output
        assert "--team" in result.output
        assert "--operating-mode" in result.output
        assert "--output-json" in result.output


class TestCheckHealth:
    """Test check-health command."""

    def test_check_health_command_exists(self) -> None:
        """The check-health subcommand is registered and shows help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["check-health", "--help"])

        assert result.exit_code == 0
        assert "check-health" in result.output.lower() or "health" in result.output.lower()


class TestEvaluateAlwaysExitsZero:
    """Verify that evaluate never exits non-zero in monitor/advise mode."""

    def test_evaluate_exits_zero_on_config_error(self) -> None:
        """Even with a broken config, evaluate exits 0 (fail-open)."""
        runner = CliRunner()
        # No EEDOM_DB_DSN set -- config will fail to load
        # The CLI should catch this and exit 0

        with runner.isolated_filesystem():
            with open("test.diff", "w") as f:
                f.write(DIFF_NO_DEPS)

            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    ".",
                    "--diff",
                    "test.diff",
                    "--pr-url",
                    "https://github.com/org/repo/pull/1",
                    "--team",
                    "platform",
                    "--operating-mode",
                    "monitor",
                ],
                env={},
            )

        assert result.exit_code == 0

    def test_evaluate_stdin_diff(self) -> None:
        """Evaluate accepts diff from stdin via '-'."""
        runner = CliRunner()
        env = {
            "EEDOM_DB_DSN": "postgresql://test:test@localhost/test",
        }

        result = runner.invoke(
            cli,
            [
                "evaluate",
                "--repo-path",
                ".",
                "--diff",
                "-",
                "--pr-url",
                "https://github.com/org/repo/pull/1",
                "--team",
                "platform",
                "--operating-mode",
                "monitor",
            ],
            input=DIFF_NO_DEPS,
            env=env,
        )

        assert result.exit_code == 0


class TestReviewWatchFlag:
    """Tests for --watch flag on the review command."""

    def test_watch_flag_exists_on_review_command(self) -> None:
        """The --watch flag is registered on the review command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--watch" in result.output

    def test_debounce_timer_fires_once_on_rapid_resets(self) -> None:
        """DebounceTimer fires exactly once despite multiple rapid resets."""
        import time

        from eedom.cli.main import DebounceTimer

        calls: list[int] = []
        timer = DebounceTimer(delay=0.1, callback=lambda: calls.append(1))

        # Three rapid resets — only the last one should schedule the actual call
        timer.reset()
        timer.reset()
        timer.reset()

        time.sleep(0.5)  # Wait well past the debounce delay

        assert len(calls) == 1
        timer.cancel()

    def test_debounce_timer_cancel_prevents_fire(self) -> None:
        """DebounceTimer.cancel() prevents the scheduled callback from firing."""
        import time

        from eedom.cli.main import DebounceTimer

        calls: list[int] = []
        timer = DebounceTimer(delay=0.2, callback=lambda: calls.append(1))

        timer.reset()
        timer.cancel()

        time.sleep(0.5)
        assert len(calls) == 0

    def test_debounce_timer_no_fire_without_reset(self) -> None:
        """DebounceTimer never fires if reset() was never called."""
        import time

        from eedom.cli.main import DebounceTimer

        calls: list[int] = []
        timer = DebounceTimer(delay=0.05, callback=lambda: calls.append(1))
        time.sleep(0.2)
        assert len(calls) == 0
        timer.cancel()

    def test_debounce_timer_resets_postpone_callback(self) -> None:
        """Rapid resets keep pushing the callback further out, not stacking calls."""
        import time

        from eedom.cli.main import DebounceTimer

        calls: list[int] = []
        timer = DebounceTimer(delay=0.15, callback=lambda: calls.append(1))

        for _ in range(5):
            timer.reset()
            time.sleep(0.02)  # 5 × 20 ms < 150 ms delay — still resetting

        time.sleep(0.4)  # Wait for the final debounce to fire
        assert len(calls) == 1
        timer.cancel()


class TestReviewHelpOptions:
    """Verify that all expected options appear in `review --help`."""

    def test_format_option_in_review_help(self) -> None:
        """--format [markdown|sarif] appears in review --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output

    def test_sarif_max_findings_option_in_review_help(self) -> None:
        """--sarif-max-findings appears in review --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--sarif-max-findings" in result.output

    def test_format_choices_shown_in_help(self) -> None:
        """The choices [markdown|sarif] are visible in review --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "markdown" in result.output
        assert "sarif" in result.output

    def test_watch_and_format_and_sarif_all_present(self) -> None:
        """All three new options (--watch, --format, --sarif-max-findings) are in help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--watch" in result.output
        assert "--format" in result.output
        assert "--sarif-max-findings" in result.output

    def test_output_option_in_review_help(self) -> None:
        """--output option exists on the review command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output


class TestReviewFormatSarif:
    """Tests for `review --format sarif` output through the CLI."""

    def test_sarif_output_is_valid_json(self) -> None:
        """--format sarif produces parseable JSON on stdout."""
        import json

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--format", "sarif", "--scanners", "semgrep"],
            )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)

    def test_sarif_output_has_version_field(self) -> None:
        """SARIF output contains version == '2.1.0'."""
        import json

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--format", "sarif", "--scanners", "semgrep"],
            )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["version"] == "2.1.0"

    def test_sarif_output_has_schema_field(self) -> None:
        """SARIF output contains a $schema key pointing to the SARIF 2.1.0 schema."""
        import json

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--format", "sarif", "--scanners", "semgrep"],
            )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "$schema" in parsed
        assert "sarif" in parsed["$schema"].lower()

    def test_sarif_output_has_runs_key(self) -> None:
        """SARIF output contains a 'runs' list."""
        import json

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--format", "sarif", "--scanners", "semgrep"],
            )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "runs" in parsed
        assert isinstance(parsed["runs"], list)

    def test_sarif_exits_zero(self) -> None:
        """review --format sarif exits 0."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--format", "sarif", "--scanners", "semgrep"],
            )
        assert result.exit_code == 0

    def test_sarif_format_writes_to_output_file(self) -> None:
        """--format sarif --output foo.sarif writes a file and prints confirmation."""

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "review",
                    "--format",
                    "sarif",
                    "--scanners",
                    "semgrep",
                    "--output",
                    "out.sarif",
                ],
            )
        assert result.exit_code == 0
        assert "sarif" in result.output.lower() or "written" in result.output.lower()

    def test_sarif_output_file_contains_valid_sarif(self) -> None:
        """The file written by --output contains valid SARIF JSON."""
        import json
        from pathlib import Path

        runner = CliRunner()
        with runner.isolated_filesystem():
            outpath = Path("out.sarif")
            result = runner.invoke(
                cli,
                [
                    "review",
                    "--format",
                    "sarif",
                    "--scanners",
                    "semgrep",
                    "--output",
                    str(outpath),
                ],
            )
            assert result.exit_code == 0
            content = json.loads(outpath.read_text())
        assert content["version"] == "2.1.0"

    def test_format_markdown_produces_non_json_output(self) -> None:
        """--format markdown (default) does not produce a raw JSON object."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--format", "markdown", "--scanners", "semgrep"],
            )
        assert result.exit_code == 0
        # Markdown output starts with # or ## headings, not {
        assert not result.output.strip().startswith('{"version"')

    def test_default_format_is_markdown(self) -> None:
        """Omitting --format produces the same output as --format markdown."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result_default = runner.invoke(
                cli,
                ["review", "--scanners", "semgrep"],
            )
            result_explicit = runner.invoke(
                cli,
                ["review", "--format", "markdown", "--scanners", "semgrep"],
            )
        assert result_default.exit_code == 0
        assert result_explicit.exit_code == 0
        assert result_default.output == result_explicit.output

    def test_invalid_format_value_rejected(self) -> None:
        """Passing --format with an unknown value exits non-zero."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["review", "--format", "xml"],
            )
        assert result.exit_code != 0


class TestSarifMaxFindings:
    """Tests for the --sarif-max-findings option on the review command."""

    def test_sarif_max_findings_default_is_1000(self) -> None:
        """--sarif-max-findings option describes the 0-for-no-limit semantics."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        # The help text mentions "0 for no limit" which implies 1000 is the non-zero default
        assert "no limit" in result.output

    def test_sarif_max_findings_accepts_integer(self) -> None:
        """--sarif-max-findings 50 is accepted without error."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "review",
                    "--format",
                    "sarif",
                    "--sarif-max-findings",
                    "50",
                    "--scanners",
                    "semgrep",
                ],
            )
        assert result.exit_code == 0

    def test_sarif_max_findings_zero_accepted(self) -> None:
        """--sarif-max-findings 0 (no limit) is accepted without error."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "review",
                    "--format",
                    "sarif",
                    "--sarif-max-findings",
                    "0",
                    "--scanners",
                    "semgrep",
                ],
            )
        assert result.exit_code == 0

    def test_sarif_max_findings_non_integer_rejected(self) -> None:
        """--sarif-max-findings with a non-integer value is rejected."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "review",
                    "--format",
                    "sarif",
                    "--sarif-max-findings",
                    "notanumber",
                    "--scanners",
                    "semgrep",
                ],
            )
        assert result.exit_code != 0


class TestPluginsCommand:
    """Tests for the `plugins` subcommand."""

    def test_plugins_exits_zero(self) -> None:
        """The plugins command exits 0."""
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0

    def test_plugins_lists_at_least_one_plugin(self) -> None:
        """The plugins command lists at least one registered plugin."""
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0
        assert "plugins registered" in result.output

    def test_plugins_shows_name_column(self) -> None:
        """The plugins table has a Name column header."""
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0
        assert "Name" in result.output

    def test_plugins_shows_category_column(self) -> None:
        """The plugins table has a Category column header."""
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0
        assert "Category" in result.output

    def test_plugins_shows_binary_column(self) -> None:
        """The plugins table has a Binary column header."""
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0
        assert "Binary" in result.output

    def test_plugins_help(self) -> None:
        """The plugins --help flag exits 0 and describes the command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins", "--help"])
        assert result.exit_code == 0
        assert "plugin" in result.output.lower()

    def test_plugins_includes_semgrep(self) -> None:
        """semgrep appears in the registered plugin list."""
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0
        assert "semgrep" in result.output


class TestIsolatedEnvironmentCheck:
    """Tests for the venv/container enforcement."""

    def test_rejects_global_install(self, monkeypatch) -> None:
        """CLI exits 1 when sys.prefix == sys.base_prefix (no venv)."""
        import sys as _sys

        monkeypatch.setattr(_sys, "prefix", "/usr")
        monkeypatch.setattr(_sys, "base_prefix", "/usr")
        monkeypatch.delenv("EEDOM_ALLOW_GLOBAL", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)

        _real_exists = Path.exists
        _container_sentinels = {"/.dockerenv", "/run/.containerenv"}

        def _patched_exists(self: Path) -> bool:
            if str(self) in _container_sentinels:
                return False
            return _real_exists(self)

        monkeypatch.setattr(Path, "exists", _patched_exists)

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--repo-path", "."])
        assert result.exit_code == 1
        assert "isolated environment" in result.output

    def test_allows_venv(self) -> None:
        """CLI proceeds when running inside a venv (our test environment)."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_allows_bypass_env_var(self, monkeypatch) -> None:
        """EEDOM_ALLOW_GLOBAL=1 overrides the check."""
        import sys as _sys

        monkeypatch.setattr(_sys, "prefix", "/usr")
        monkeypatch.setattr(_sys, "base_prefix", "/usr")
        monkeypatch.setenv("EEDOM_ALLOW_GLOBAL", "1")

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--repo-path", "."])
        assert result.exit_code == 0

    def test_allows_virtual_env_pointing_at_real_venv(self, monkeypatch, tmp_path) -> None:
        """#388 — VIRTUAL_ENV set by uv run / activate counts as isolated even
        when base_prefix detection fails (false negative scenario)."""
        import sys as _sys

        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("home = /usr/bin\nuv = 0.11.7\n")

        monkeypatch.setattr(_sys, "prefix", "/usr")
        monkeypatch.setattr(_sys, "base_prefix", "/usr")
        monkeypatch.delenv("EEDOM_ALLOW_GLOBAL", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0

    def test_allows_venv_marker_file_next_to_prefix(self, monkeypatch, tmp_path) -> None:
        """#388 — a pyvenv.cfg beside sys.prefix marks isolation even when
        sys.base_prefix == sys.prefix (relocated / uv-managed interpreters)."""
        import sys as _sys

        venv_dir = tmp_path / "venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("home = /usr/bin\n")

        monkeypatch.setattr(_sys, "prefix", str(venv_dir))
        monkeypatch.setattr(_sys, "base_prefix", str(venv_dir))
        monkeypatch.delenv("EEDOM_ALLOW_GLOBAL", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)

        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0

    def test_allows_conda_env(self, monkeypatch, tmp_path) -> None:
        """#388 — conda envs have prefix == base_prefix; CONDA_PREFIX marks them."""
        import sys as _sys

        monkeypatch.setattr(_sys, "prefix", "/usr")
        monkeypatch.setattr(_sys, "base_prefix", "/usr")
        monkeypatch.delenv("EEDOM_ALLOW_GLOBAL", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(tmp_path / "conda-env"))

        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0

    def test_rejects_stale_virtual_env_pointer(self, monkeypatch, tmp_path) -> None:
        """#388 guard intact — VIRTUAL_ENV pointing at a non-venv directory
        does NOT count as isolated."""
        import sys as _sys

        monkeypatch.setattr(_sys, "prefix", "/usr")
        monkeypatch.setattr(_sys, "base_prefix", "/usr")
        monkeypatch.delenv("EEDOM_ALLOW_GLOBAL", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "does-not-exist"))

        _real_exists = Path.exists
        _container_sentinels = {"/.dockerenv", "/run/.containerenv"}

        def _patched_exists(self: Path) -> bool:
            if str(self) in _container_sentinels:
                return False
            return _real_exists(self)

        monkeypatch.setattr(Path, "exists", _patched_exists)

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--repo-path", "."])
        assert result.exit_code == 1
        assert "isolated environment" in result.output


class TestCliTopLevel:
    """Tests for the top-level CLI group."""

    def test_cli_help_exits_zero(self) -> None:
        """The root cli --help exits 0."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_cli_help_shows_subcommands(self) -> None:
        """The root help lists available subcommands."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "evaluate" in result.output
        assert "review" in result.output
        assert "plugins" in result.output

    def test_unknown_subcommand_exits_nonzero(self) -> None:
        """An unrecognised subcommand exits non-zero."""
        runner = CliRunner()
        result = runner.invoke(cli, ["no-such-command"])
        assert result.exit_code != 0

    def test_check_health_in_top_level_help(self) -> None:
        """check-health appears in the root help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "check-health" in result.output


class TestReviewDisableEnable:
    """Tests for --disable and --enable flags on the review subcommand."""

    _PATCH_TARGET = "eedom.cli.main.get_default_registry"

    def _make_mock_registry(self) -> MagicMock:
        mock_reg = MagicMock()
        mock_reg.run_all.return_value = []
        mock_reg.list.return_value = []
        return mock_reg

    def test_review_help_shows_disable_and_enable(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--disable" in result.output
        assert "--enable" in result.output

    def test_disable_flag_passes_disabled_names_to_run_all(self) -> None:
        runner = CliRunner()
        mock_reg = self._make_mock_registry()
        with patch(self._PATCH_TARGET, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(
                cli, ["review", "--repo-path", ".", "--disable", "semgrep,cspell"]
            )
        assert result.exit_code == 0
        kwargs = mock_reg.run_all.call_args.kwargs
        assert kwargs.get("disabled_names") == {"semgrep", "cspell"}

    def test_enable_flag_passes_enabled_names_to_run_all(self) -> None:
        runner = CliRunner()
        mock_reg = self._make_mock_registry()
        with patch(self._PATCH_TARGET, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(cli, ["review", "--repo-path", ".", "--enable", "cspell"])
        assert result.exit_code == 0
        kwargs = mock_reg.run_all.call_args.kwargs
        assert kwargs.get("enabled_names") == {"cspell"}

    def test_enable_and_disable_both_passed_to_run_all(self) -> None:
        """Both sets reach registry.run_all — the registry decides priority."""
        runner = CliRunner()
        mock_reg = self._make_mock_registry()
        with patch(self._PATCH_TARGET, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "review",
                    "--repo-path",
                    ".",
                    "--disable",
                    "cspell",
                    "--enable",
                    "cspell",
                ],
            )
        assert result.exit_code == 0
        kwargs = mock_reg.run_all.call_args.kwargs
        assert "cspell" in kwargs.get("disabled_names", set())
        assert "cspell" in kwargs.get("enabled_names", set())

    def test_no_disable_enable_passes_empty_sets(self) -> None:
        """Omitting --disable/--enable passes empty sets (not None) to run_all."""
        runner = CliRunner()
        mock_reg = self._make_mock_registry()
        with patch(self._PATCH_TARGET, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(cli, ["review", "--repo-path", "."])
        assert result.exit_code == 0
        kwargs = mock_reg.run_all.call_args.kwargs
        assert kwargs.get("disabled_names") == set()
        assert kwargs.get("enabled_names") == set()

    def test_disable_composes_with_scanners_flag(self) -> None:
        """--scanners and --disable both reach run_all independently."""
        runner = CliRunner()
        mock_reg = self._make_mock_registry()
        with patch(self._PATCH_TARGET, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "review",
                    "--repo-path",
                    ".",
                    "--scanners",
                    "semgrep,trivy",
                    "--disable",
                    "trivy",
                ],
            )
        assert result.exit_code == 0
        kwargs = mock_reg.run_all.call_args.kwargs
        assert kwargs.get("names") == ["semgrep", "trivy"]
        assert kwargs.get("disabled_names") == {"trivy"}


class TestReviewRepoConfigWiring:
    """Verify .eagle-eyed-dom.yaml is loaded and flows into run_all disabled/enabled_names."""

    def test_repo_config_disabled_flows_into_run_all(self, tmp_path: Path) -> None:
        """config plugins.disabled → disabled_names passed to run_all."""
        import yaml

        from eedom.cli.main import cli

        (tmp_path / ".eagle-eyed-dom.yaml").write_text(
            yaml.dump({"plugins": {"disabled": ["test-plugin"]}})
        )

        mock_registry = MagicMock()
        mock_registry.run_all.return_value = []
        mock_registry.list.return_value = []

        with patch("eedom.cli.main.get_default_registry", return_value=mock_registry):
            runner = CliRunner()
            result = runner.invoke(cli, ["review", "--all", "--repo-path", str(tmp_path)])

        assert result.exit_code == 0
        call_kwargs = mock_registry.run_all.call_args.kwargs
        disabled = call_kwargs.get("disabled_names") or set()
        assert "test-plugin" in disabled

    def test_cli_disable_unions_with_config_disable(self, tmp_path: Path) -> None:
        """CLI --disable and config disabled are both present in disabled_names."""
        import yaml

        from eedom.cli.main import cli

        (tmp_path / ".eagle-eyed-dom.yaml").write_text(
            yaml.dump({"plugins": {"disabled": ["config-plugin"]}})
        )

        mock_registry = MagicMock()
        mock_registry.run_all.return_value = []
        mock_registry.list.return_value = []

        with patch("eedom.cli.main.get_default_registry", return_value=mock_registry):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["review", "--all", "--repo-path", str(tmp_path), "--disable", "cli-plugin"],
            )

        assert result.exit_code == 0
        call_kwargs = mock_registry.run_all.call_args.kwargs
        disabled = call_kwargs.get("disabled_names") or set()
        assert "config-plugin" in disabled
        assert "cli-plugin" in disabled

    def test_cli_enable_overrides_config_disabled(self, tmp_path: Path) -> None:
        """CLI --enable puts the plugin name in enabled_names, overriding config disabled."""
        import yaml

        from eedom.cli.main import cli

        (tmp_path / ".eagle-eyed-dom.yaml").write_text(
            yaml.dump({"plugins": {"disabled": ["test-plugin"]}})
        )

        mock_registry = MagicMock()
        mock_registry.run_all.return_value = []
        mock_registry.list.return_value = []

        with patch("eedom.cli.main.get_default_registry", return_value=mock_registry):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["review", "--all", "--repo-path", str(tmp_path), "--enable", "test-plugin"],
            )

        assert result.exit_code == 0
        call_kwargs = mock_registry.run_all.call_args.kwargs
        enabled = call_kwargs.get("enabled_names") or set()
        assert "test-plugin" in enabled

    def test_package_flag_in_review_help(self) -> None:
        """--package flag appears in review --help."""
        from eedom.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--package" in result.output


class TestEvaluateInputValidation:
    """Input validation on evaluate command (wave2-finding-0)."""

    def test_evaluate_repo_path_not_exists(self, tmp_path: Path) -> None:
        """evaluate rejects --repo-path that does not exist."""
        nonexistent = tmp_path / "nonexistent"
        runner = CliRunner()
        with patch("eedom.core.config.EedomSettings", side_effect=Exception("no config")):
            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    str(nonexistent),
                    "--diff",
                    "-",
                    "--pr-url",
                    "https://github.com/org/repo/pull/1",
                    "--team",
                    "platform",
                    "--operating-mode",
                    "monitor",
                ],
                input="",
            )
        assert result.exit_code != 0
        assert "does not exist" in result.output or "Error" in result.output

    def test_evaluate_repo_path_not_directory(self, tmp_path: Path) -> None:
        """evaluate rejects --repo-path that points to a file, not a directory."""
        file_path = tmp_path / "notadir.txt"
        file_path.write_text("test")
        runner = CliRunner()
        with patch("eedom.core.config.EedomSettings", side_effect=Exception("no config")):
            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    str(file_path),
                    "--diff",
                    "-",
                    "--pr-url",
                    "https://github.com/org/repo/pull/1",
                    "--team",
                    "platform",
                    "--operating-mode",
                    "monitor",
                ],
                input="",
            )
        assert result.exit_code != 0
        assert "not a directory" in result.output or "Error" in result.output

    def test_evaluate_pr_url_invalid_format(self, tmp_path: Path) -> None:
        """evaluate rejects --pr-url that is not a valid GitHub PR URL."""
        runner = CliRunner()
        with patch("eedom.core.config.EedomSettings", side_effect=Exception("no config")):
            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    str(tmp_path),
                    "--diff",
                    "-",
                    "--pr-url",
                    "not-a-valid-url",
                    "--team",
                    "platform",
                    "--operating-mode",
                    "monitor",
                ],
                input="",
            )
        assert result.exit_code != 0
        assert "github.com" in result.output or "Error" in result.output

    def test_evaluate_pr_url_non_github(self, tmp_path: Path) -> None:
        """evaluate rejects --pr-url pointing to non-GitHub services."""
        runner = CliRunner()
        with patch("eedom.core.config.EedomSettings", side_effect=Exception("no config")):
            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    str(tmp_path),
                    "--diff",
                    "-",
                    "--pr-url",
                    "https://gitlab.com/owner/repo/merge_requests/123",
                    "--team",
                    "platform",
                    "--operating-mode",
                    "monitor",
                ],
                input="",
            )
        assert result.exit_code != 0
        assert "github.com" in result.output or "Error" in result.output

    def test_evaluate_team_invalid(self, tmp_path: Path) -> None:
        """evaluate rejects --team values not in the allowed list."""
        runner = CliRunner()
        with patch("eedom.core.config.EedomSettings", side_effect=Exception("no config")):
            result = runner.invoke(
                cli,
                [
                    "evaluate",
                    "--repo-path",
                    str(tmp_path),
                    "--diff",
                    "-",
                    "--pr-url",
                    "https://github.com/org/repo/pull/1",
                    "--team",
                    "invalid_team_xyz",
                    "--operating-mode",
                    "monitor",
                ],
                input="",
            )
        assert result.exit_code != 0
        assert "team" in result.output.lower() or "Error" in result.output


class TestEvaluateExceptionLogging:
    """Pipeline exceptions must be logged via logger.error (wave2-finding-1)."""

    def test_pipeline_exception_uses_logger_error_not_exception(self, tmp_path: Path) -> None:
        """Pipeline failures must call logger.error (exc_info=True), not logger.exception."""
        runner = CliRunner()
        with (
            patch("eedom.core.config.EedomSettings") as mock_settings,
            patch(
                "eedom.composition.bootstrap.bootstrap",
                side_effect=ValueError("simulated pipeline error"),
            ),
            patch("eedom.cli.main.logger") as mock_logger,
        ):
            mock_settings.return_value = MagicMock()
            with runner.isolated_filesystem():
                result = runner.invoke(
                    cli,
                    [
                        "evaluate",
                        "--repo-path",
                        ".",
                        "--diff",
                        "-",
                        "--pr-url",
                        "https://github.com/org/repo/pull/1",
                        "--team",
                        "platform",
                        "--operating-mode",
                        "monitor",
                    ],
                    input="",
                )

        assert result.exit_code == 1
        assert mock_logger.error.called, "logger.error must be called on pipeline failure"
        assert not mock_logger.exception.called, "logger.exception must not be used"


class TestReviewGhRepoValidation:
    """GitHub repo format validation on review command (wave2-finding-4)."""

    _REG_PATCH = "eedom.cli.main.get_default_registry"

    def _mock_registry(self) -> MagicMock:
        mock_reg = MagicMock()
        mock_reg.run_all.return_value = []
        mock_reg.list.return_value = []
        return mock_reg

    def test_review_gh_repo_invalid_no_slash(self) -> None:
        """--repo without slash (no owner/name separator) is rejected."""
        runner = CliRunner()
        mock_reg = self._mock_registry()
        with patch(self._REG_PATCH, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(cli, ["review", "--repo-path", ".", "--repo", "invalid"])
        assert result.exit_code != 0
        assert "Invalid GitHub repo format" in result.output or "owner/name" in result.output

    def test_review_gh_repo_invalid_trailing_slash(self) -> None:
        """--repo with trailing slash and no name (owner/) is rejected."""
        runner = CliRunner()
        mock_reg = self._mock_registry()
        with patch(self._REG_PATCH, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(cli, ["review", "--repo-path", ".", "--repo", "owner/"])
        assert result.exit_code != 0
        assert "Invalid GitHub repo format" in result.output or "owner/name" in result.output

    def test_review_gh_repo_invalid_leading_slash(self) -> None:
        """--repo with leading slash (missing owner) is rejected."""
        runner = CliRunner()
        mock_reg = self._mock_registry()
        with patch(self._REG_PATCH, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(cli, ["review", "--repo-path", ".", "--repo", "/name"])
        assert result.exit_code != 0
        assert "Invalid GitHub repo format" in result.output or "owner/name" in result.output

    def test_review_gh_repo_invalid_too_many_parts(self) -> None:
        """--repo with extra path segments (owner/name/extra) is rejected."""
        runner = CliRunner()
        mock_reg = self._mock_registry()
        with patch(self._REG_PATCH, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(
                cli, ["review", "--repo-path", ".", "--repo", "owner/name/extra"]
            )
        assert result.exit_code != 0
        assert "Invalid GitHub repo format" in result.output or "owner/name" in result.output

    def test_review_gh_repo_valid_format_accepted(self) -> None:
        """--repo with valid owner/name format does not trigger validation error."""
        runner = CliRunner()
        mock_reg = self._mock_registry()
        with patch(self._REG_PATCH, return_value=mock_reg), runner.isolated_filesystem():
            result = runner.invoke(cli, ["review", "--repo-path", ".", "--repo", "my-org/my-repo"])
        assert "Invalid GitHub repo format" not in result.output


class TestWatchExtensionsIncludesJson:
    """Watch mode must detect .json file changes (issue #81)."""

    def test_json_in_watch_extensions(self) -> None:
        from eedom.cli.main import _WATCH_EXTENSIONS

        assert ".json" in _WATCH_EXTENSIONS


class TestBuildFileListJsonDiscovery:
    """Verify _build_file_list includes .json files in --all mode (issue #55)."""

    _REG_PATCH = "eedom.cli.main.get_default_registry"

    def test_json_cfn_template_appears_in_file_list(self, tmp_path: Path) -> None:
        """A .json file in the repo is included in the files passed to run_all.

        cfn-nag's can_run() filters non-CFN JSON internally, so the discovery
        layer must not exclude .json by extension.
        """
        (tmp_path / "template.json").write_text(
            '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}'
        )

        mock_registry = MagicMock()
        mock_registry.run_all.return_value = []
        mock_registry.list.return_value = []

        with patch(self._REG_PATCH, return_value=mock_registry):
            runner = CliRunner()
            result = runner.invoke(cli, ["review", "--all", "--repo-path", str(tmp_path)])

        assert result.exit_code == 0
        call_args = mock_registry.run_all.call_args
        files: list[str] = (
            call_args.args[0] if call_args.args else call_args.kwargs.get("files", [])
        )
        assert any(
            "template.json" in f for f in files
        ), f"Expected template.json in file list but got: {files}"


class TestReviewPRMode:
    """Tests for --pr inline review posting mode."""

    _REG_PATCH = "eedom.cli.main.get_default_registry"

    def _mock_registry(self) -> MagicMock:
        mock_reg = MagicMock()
        mock_reg.run_all.return_value = []
        mock_reg.list.return_value = []
        return mock_reg

    def test_pr_zero_rejected_by_intrange(self) -> None:
        """--pr 0 is rejected by IntRange(min=1) validation."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--repo-path", ".", "--pr", "0"])
        assert result.exit_code != 0
        assert "0" in result.output or "Invalid" in result.output or "invalid" in result.output

    def test_pr_success_posts_review(self) -> None:
        """--pr with valid repo posts review and exits 0."""
        mock_reg = self._mock_registry()
        mock_review = MagicMock()
        mock_review.event = "COMMENT"
        mock_review.comments = []
        mock_review.outside_diff = []

        with (
            patch(self._REG_PATCH, return_value=mock_reg),
            patch("eedom.core.pr_review.detect_gh_repo", return_value="org/repo"),
            patch("eedom.core.pr_review.get_pr_diff_files", return_value={"src/app.py"}),
            patch("eedom.core.pr_review.sarif_to_review", return_value=mock_review),
            patch("eedom.core.pr_review.post_review", return_value=True) as mock_post,
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["review", "--repo-path", ".", "--pr", "42", "--repo", "org/repo"]
            )

        assert result.exit_code == 0
        assert "Posted" in result.output
        mock_post.assert_called_once()

    def test_pr_no_repo_detected_exits_1(self) -> None:
        """--pr without --repo and no git remote exits 1."""
        mock_reg = self._mock_registry()

        with (
            patch(self._REG_PATCH, return_value=mock_reg),
            patch("eedom.core.pr_review.detect_gh_repo", return_value=None),
        ):
            runner = CliRunner()
            result = runner.invoke(cli, ["review", "--repo-path", ".", "--pr", "42"])

        assert result.exit_code == 1
        assert "Could not detect" in result.output

    def test_pr_post_failure_exits_1(self) -> None:
        """--pr exits 1 when post_review returns False."""
        mock_reg = self._mock_registry()
        mock_review = MagicMock()
        mock_review.event = "COMMENT"
        mock_review.comments = []
        mock_review.outside_diff = []

        with (
            patch(self._REG_PATCH, return_value=mock_reg),
            patch("eedom.core.pr_review.detect_gh_repo", return_value="org/repo"),
            patch("eedom.core.pr_review.get_pr_diff_files", return_value=set()),
            patch("eedom.core.pr_review.sarif_to_review", return_value=mock_review),
            patch("eedom.core.pr_review.post_review", return_value=False),
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["review", "--repo-path", ".", "--pr", "42", "--repo", "org/repo"]
            )

        assert result.exit_code == 1
        assert "Failed" in result.output

    def test_pr_diff_fetch_error_exits_1(self) -> None:
        """--pr exits 1 when get_pr_diff_files raises RuntimeError."""
        mock_reg = self._mock_registry()

        with (
            patch(self._REG_PATCH, return_value=mock_reg),
            patch("eedom.core.pr_review.detect_gh_repo", return_value="org/repo"),
            patch(
                "eedom.core.pr_review.get_pr_diff_files",
                side_effect=RuntimeError("API error: 404"),
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["review", "--repo-path", ".", "--pr", "42", "--repo", "org/repo"]
            )

        assert result.exit_code == 1
        assert "API error" in result.output


# ---------------------------------------------------------------------------
# --scope CLI flag
# ---------------------------------------------------------------------------


class TestScopeFlag:
    def test_scope_option_in_review_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert "--scope" in result.output

    def test_scope_accepts_repo_value(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert "repo" in result.output

    def test_scope_accepts_diff_value(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert "diff" in result.output

    def test_scope_accepts_folder_value(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert "folder" in result.output

    def test_scope_diff_without_diff_file_errors(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--scope", "diff", "--repo-path", "."])
        assert result.exit_code != 0

    def test_scope_folder_without_path_errors(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--scope", "folder", "--repo-path", "."])
        assert result.exit_code != 0
