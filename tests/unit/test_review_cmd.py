"""Tests for caliper.cli.review_cmd — helpers extracted from cli.main.review()."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from caliper.cli.review_cmd import (
    build_file_lists,
    render_review_output,
    resolve_plugin_selection,
)
from caliper.core.repo_config import PluginConfig, RepoConfig
from caliper.core.tool_runner import ToolInvocation, ToolResult
from caliper.core.use_cases import ScanScope


class TestResolvePluginSelection:
    def test_no_flags_returns_repo_config_lists(self) -> None:
        repo_config = RepoConfig(plugins=PluginConfig(disabled=["osv"], enabled=["trivy"]))

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="")

        assert disabled == {"osv", "scancode"}
        assert enabled == {"trivy"}

    def test_cli_flags_merge_with_repo_config(self) -> None:
        repo_config = RepoConfig(plugins=PluginConfig(disabled=["osv"], enabled=[]))

        disabled, enabled = resolve_plugin_selection(
            repo_config, disable="syft, cpd", enable="secrets"
        )

        assert disabled == {"osv", "syft", "cpd", "scancode"}
        assert enabled == {"secrets"}

    def test_empty_string_entries_are_discarded(self) -> None:
        repo_config = RepoConfig()

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="")

        assert disabled == {"scancode"}
        assert enabled == set()

    def test_scancode_is_opt_in_by_default(self) -> None:
        """scancode isn't installed in the default image — never on by default."""
        repo_config = RepoConfig()

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="")

        assert "scancode" in disabled
        assert "scancode" not in enabled

    def test_scancode_enable_flag_overrides_default_opt_out(self) -> None:
        repo_config = RepoConfig()

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="scancode")

        assert "scancode" in disabled  # still present, but...
        assert "scancode" in enabled  # ...enabled wins per run_all's precedence rule


class TestBuildFileLists:
    def test_repo_scope_default_calls_collect_repo_files(self, tmp_path: Path) -> None:
        calls = []

        def collect(root: Path, suffixes: tuple[str, ...]) -> list[str]:
            calls.append((root, suffixes))
            return ["a.py"]

        files, repo_files = build_file_lists(
            repo=tmp_path,
            resolved_scope=None,
            diff=None,
            package=None,
            collect_repo_files=collect,
            read_diff=lambda _p: "",
            review_suffixes=(".py",),
        )

        assert files == ["a.py"]
        assert repo_files is None
        assert calls == [(tmp_path, (".py",))]

    def test_folder_scope_scopes_to_package_dir(self, tmp_path: Path) -> None:
        folder = tmp_path / "pkg"
        folder.mkdir()
        calls = []

        def collect(root: Path, suffixes: tuple[str, ...]) -> list[str]:
            calls.append(root)
            return ["pkg/b.py"]

        files, repo_files = build_file_lists(
            repo=tmp_path,
            resolved_scope=ScanScope.FOLDER,
            diff=None,
            package=str(folder),
            collect_repo_files=collect,
            read_diff=lambda _p: "",
            review_suffixes=(".py",),
        )

        assert files == ["pkg/b.py"]
        assert repo_files is None
        assert calls == [folder.resolve()]

    def test_diff_scope_returns_diff_files_and_full_repo_files(self, tmp_path: Path) -> None:
        changed = tmp_path / "changed.py"
        changed.write_text("x = 1\n")
        diff_text = "diff --git a/changed.py b/changed.py\n"

        files, repo_files = build_file_lists(
            repo=tmp_path,
            resolved_scope=ScanScope.DIFF,
            diff="ignored.diff",
            package=None,
            collect_repo_files=lambda root, suffixes: ["all.py"],
            read_diff=lambda _p: diff_text,
            review_suffixes=(".py",),
        )

        assert files == [str(changed.resolve())]
        assert repo_files == ["all.py"]

    def test_plain_diff_without_scope_returns_diff_files_only(self, tmp_path: Path) -> None:
        changed = tmp_path / "changed.py"
        changed.write_text("x = 1\n")
        diff_text = "diff --git a/changed.py b/changed.py\n"

        files, repo_files = build_file_lists(
            repo=tmp_path,
            resolved_scope=None,
            diff="ignored.diff",
            package=None,
            collect_repo_files=lambda root, suffixes: ["all.py"],
            read_diff=lambda _p: diff_text,
            review_suffixes=(".py",),
        )

        assert files == [str(changed.resolve())]
        assert repo_files is None

    def test_diff_file_outside_repo_root_is_skipped(self, tmp_path: Path) -> None:
        diff_text = "diff --git a/../outside.py b/../outside.py\n"

        files, repo_files = build_file_lists(
            repo=tmp_path,
            resolved_scope=ScanScope.DIFF,
            diff="ignored.diff",
            package=None,
            collect_repo_files=lambda root, suffixes: [],
            read_diff=lambda _p: diff_text,
            review_suffixes=(".py",),
        )

        assert files == []


class TestRenderReviewOutput:
    def _base_kwargs(self, tmp_path: Path, **overrides) -> dict:
        kwargs = {
            "results": [],
            "summary": None,
            "output_format": "markdown",
            "output": None,
            "pr": None,
            "gh_repo": None,
            "sarif_max_findings": 1000,
            "repo": tmp_path,
            "repo_name": "acme/widgets",
            "pr_num": 0,
            "title": "PR Review",
            "file_count": 0,
            "plugin_map": {},
            "write_output": lambda path, content: None,
        }
        kwargs.update(overrides)
        return kwargs

    def test_markdown_written_to_stdout_via_click_echo(self, tmp_path: Path, capsys) -> None:
        render_review_output(**self._base_kwargs(tmp_path))

        captured = capsys.readouterr()
        assert "acme/widgets" in captured.out

    def test_markdown_relativizes_absolute_finding_paths(self, tmp_path: Path, capsys) -> None:
        """A real caliper review comment leaked absolute CI-runner paths
        (e.g. /home/runner/work/x/x/src/...) because render_comment was never
        given repo_path. render_review_output must pass a RESOLVED repo_path
        (--repo-path defaults to "." and is never resolved by click, but
        scanner-reported paths are absolute) so relativization actually fires."""
        from caliper.core.plugin import PluginResult

        abs_path = str(tmp_path / "src" / "app.py")
        results = [
            PluginResult(
                plugin_name="semgrep",
                findings=[{"file": abs_path, "line": 1, "severity": "medium", "rule_id": "x"}],
            )
        ]

        render_review_output(**self._base_kwargs(tmp_path, results=results))

        captured = capsys.readouterr()
        assert abs_path not in captured.out
        assert "src/app.py" in captured.out

    def test_markdown_written_to_file(self, tmp_path: Path, capsys) -> None:
        written = {}

        def write_output(path: str, content: str) -> None:
            written["path"] = path
            written["content"] = content

        render_review_output(
            **self._base_kwargs(tmp_path, output="out.md", write_output=write_output)
        )

        assert written["path"] == "out.md"
        captured = capsys.readouterr()
        assert "Review written to out.md" in captured.out

    def test_json_format_dispatches_to_render_json(self, tmp_path: Path, capsys) -> None:
        render_review_output(**self._base_kwargs(tmp_path, output_format="json"))

        captured = capsys.readouterr()
        assert '"repo"' in captured.out or "acme/widgets" in captured.out

    def test_sarif_format_prints_sarif_document(self, tmp_path: Path, capsys) -> None:
        render_review_output(**self._base_kwargs(tmp_path, output_format="sarif"))

        captured = capsys.readouterr()
        assert '"version"' in captured.out

    def test_sarif_format_written_to_file(self, tmp_path: Path, capsys) -> None:
        written = {}

        def write_output(path: str, content: str) -> None:
            written["path"] = path

        render_review_output(
            **self._base_kwargs(
                tmp_path, output_format="sarif", output="out.sarif", write_output=write_output
            )
        )

        assert written["path"] == "out.sarif"

    def test_pr_mode_without_detectable_repo_exits_1(self, tmp_path: Path) -> None:
        with (
            patch("caliper.core.pr_review.detect_gh_repo", return_value=None),
            SystemExitCapture() as exit_info,
        ):
            render_review_output(**self._base_kwargs(tmp_path, pr=7, gh_repo=None))

        assert exit_info.code == 1

    def test_pr_mode_posts_review_on_success(self, tmp_path: Path, capsys) -> None:
        fake_pr_review = type(
            "FakeReview", (), {"event": "COMMENT", "comments": [], "outside_diff": []}
        )()

        with (
            patch("caliper.core.pr_review.get_pr_diff_files", return_value=["a.py"]),
            patch("caliper.core.pr_review.sarif_to_review", return_value=fake_pr_review),
            patch("caliper.core.pr_review.post_review", return_value=True),
        ):
            render_review_output(
                **self._base_kwargs(tmp_path, pr=7, gh_repo="acme/widgets", output_format="sarif")
            )

        captured = capsys.readouterr()
        assert "Posted review on PR #7" in captured.out

    def test_pr_mode_exits_1_when_post_fails(self, tmp_path: Path) -> None:
        fake_pr_review = type(
            "FakeReview", (), {"event": "COMMENT", "comments": [], "outside_diff": []}
        )()

        with (
            patch("caliper.core.pr_review.get_pr_diff_files", return_value=["a.py"]),
            patch("caliper.core.pr_review.sarif_to_review", return_value=fake_pr_review),
            patch("caliper.core.pr_review.post_review", return_value=False),
            SystemExitCapture() as exit_info,
        ):
            render_review_output(
                **self._base_kwargs(tmp_path, pr=7, gh_repo="acme/widgets", output_format="sarif")
            )

        assert exit_info.code == 1


class SystemExitCapture:
    """Context manager that captures sys.exit()'s code without propagating it."""

    def __enter__(self) -> SystemExitCapture:
        self.code = None
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if exc_type is SystemExit:
            self.code = exc_value.code
            return True
        return False


class _RecordingToolRunner:
    """Fake ToolRunnerPort that records every invocation and answers from a
    canned response table keyed by a command-prefix tuple. Never touches a
    real subprocess/container — used to prove task-022's AC5 (no test spawns
    a real container).
    """

    def __init__(
        self,
        responses: dict[tuple[str, ...], ToolResult] | None = None,
        default: ToolResult | None = None,
    ) -> None:
        self.invocations: list[ToolInvocation] = []
        self._responses = responses or {}
        self._default = default or ToolResult(
            exit_code=127, stdout="", stderr="not found", not_installed=True
        )

    def run(self, invocation: ToolInvocation) -> ToolResult:
        self.invocations.append(invocation)
        for prefix, result in self._responses.items():
            if tuple(invocation.cmd[: len(prefix)]) == tuple(prefix):
                return result
        return self._default


class TestReviewRunnerFlag:
    """task-022: `caliper review --runner auto|container|native`."""

    def test_ac1_runner_auto_picks_container_when_podman_and_image_present(self) -> None:
        """PROP-001: --runner auto with a fake ToolRunnerPort reporting podman
        present and the image pullable resolves to the container path."""
        from caliper.cli.review_cmd import resolve_runner_choice

        responses = {
            ("podman", "--version"): ToolResult(exit_code=0, stdout="podman version 4.9.0"),
            ("podman", "image", "exists"): ToolResult(exit_code=0, stdout=""),
        }
        fake_runner = _RecordingToolRunner(responses=responses)

        choice = resolve_runner_choice("auto", fake_runner)

        assert choice == "container"

    def test_ac1_runner_auto_falls_back_to_native_with_one_line_stderr_notice(self, capsys) -> None:
        """PROP-001: with neither podman nor docker on PATH, --runner auto
        falls back to native and prints a one-line stderr notice."""
        from caliper.cli.review_cmd import resolve_runner_choice

        fake_runner = _RecordingToolRunner()  # default: not_installed for every probe

        choice = resolve_runner_choice("auto", fake_runner)

        captured = capsys.readouterr()
        assert choice == "native"
        stderr_lines = [line for line in captured.err.splitlines() if line.strip()]
        assert len(stderr_lines) == 1
        assert "native" in stderr_lines[0].lower()

    def test_ac2_container_invocation_mounts_repo_ro_and_temp_rw(self, tmp_path: Path) -> None:
        """PROP-002: the assembled container command mounts repo_path
        read-only at /workspace and .temp read-write."""
        from caliper.cli.review_cmd import build_container_invocation

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        temp_path = repo_path / ".temp"
        temp_path.mkdir()

        invocation = build_container_invocation(
            repo_path=repo_path,
            temp_path=temp_path,
            env={},
            cli_args=["review", "--repo-path", "/workspace"],
        )

        cmd = invocation.cmd
        assert "-v" in cmd
        mount_args = [cmd[i + 1] for i, tok in enumerate(cmd) if tok == "-v"]
        assert f"{repo_path}:/workspace:ro" in mount_args
        assert any(
            arg.startswith(f"{temp_path}:/workspace/.temp") and arg.endswith(":ro") is False
            for arg in mount_args
        )

    def test_ac2_container_invocation_forwards_caliper_env_vars_only(self, tmp_path: Path) -> None:
        """PROP-002: every CALIPER_* env var present in the process
        environment is forwarded; unrelated env vars are not."""
        from caliper.cli.review_cmd import build_container_invocation

        env = {
            "CALIPER_LOG_LEVEL": "debug",
            "CALIPER_WEBHOOK_SECRET": "shh",
            "UNRELATED_VAR": "nope",
            "PATH": "/usr/bin",
        }

        invocation = build_container_invocation(
            repo_path=tmp_path, temp_path=tmp_path / ".temp", env=env, cli_args=["review"]
        )

        cmd = invocation.cmd
        env_pairs = [cmd[i + 1] for i, tok in enumerate(cmd) if tok == "-e"]
        assert "CALIPER_LOG_LEVEL=debug" in env_pairs
        assert "CALIPER_WEBHOOK_SECRET=shh" in env_pairs
        assert not any(pair.startswith("UNRELATED_VAR") for pair in env_pairs)
        assert not any(pair.startswith("PATH=") for pair in env_pairs)

    def test_ac2_container_invocation_forwards_cli_args_verbatim(self, tmp_path: Path) -> None:
        """PROP-002: the original CLI args are forwarded verbatim to the
        containerized invocation."""
        from caliper.cli.review_cmd import build_container_invocation

        cli_args = ["review", "--repo-path", "/workspace", "--output-format", "sarif"]

        invocation = build_container_invocation(
            repo_path=tmp_path, temp_path=tmp_path / ".temp", env={}, cli_args=cli_args
        )

        assert invocation.cmd[-len(cli_args) :] == cli_args

    def test_ac3_container_invocation_runs_as_non_root_user(self, tmp_path: Path) -> None:
        """PROP-003: the container invocation runs as the image's non-root
        user, never root/uid 0."""
        from caliper.cli.review_cmd import build_container_invocation

        invocation = build_container_invocation(
            repo_path=tmp_path, temp_path=tmp_path / ".temp", env={}, cli_args=["review"]
        )

        cmd = invocation.cmd
        assert "--user" in cmd
        user_idx = cmd.index("--user")
        user_value = cmd[user_idx + 1]
        assert user_value not in {"0", "root", "0:0"}

    def test_ac3_cli_returns_container_exit_code_and_stdout_unchanged(self, tmp_path: Path) -> None:
        """PROP-003: the CLI returns the container process's exit code and
        stdout unchanged, via the fake ToolRunnerPort."""
        from caliper.cli.review_cmd import run_review_via_container

        fake_result = ToolResult(exit_code=7, stdout="42 findings\n", stderr="", duration_ms=42)
        fake_runner = _RecordingToolRunner(default=fake_result)

        result = run_review_via_container(
            fake_runner,
            repo_path=tmp_path,
            temp_path=tmp_path / ".temp",
            env={},
            cli_args=["review", "--repo-path", "/workspace"],
        )

        assert result.exit_code == 7
        assert result.stdout == "42 findings\n"

    def test_ac4_review_accepts_runner_but_part_command_does_not(self) -> None:
        """PROP-004: `caliper review` gains a --runner option; `caliper part`
        does not accept it and is unaffected by it — it always runs natively."""
        from caliper.cli.main import cli

        review_param_names = {p.name for p in cli.commands["review"].params}
        part_param_names = {p.name for p in cli.commands["part"].params}

        assert "runner" in review_param_names
        assert "runner" not in part_param_names

    def test_ac5_runner_flow_never_touches_a_real_subprocess(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """PROP-005: the whole auto -> container-invocation -> execution flow
        is driven entirely by a fake ToolRunnerPort; no test in this module
        ever spawns a real container/subprocess."""
        from caliper.cli.review_cmd import (
            build_container_invocation,
            resolve_runner_choice,
            run_review_via_container,
        )

        def _boom(*args, **kwargs):
            raise AssertionError("real subprocess.run must never be called; use ToolRunnerPort")

        monkeypatch.setattr("subprocess.run", _boom)
        monkeypatch.setattr("subprocess.Popen", _boom)

        responses = {
            ("podman", "--version"): ToolResult(exit_code=0, stdout="podman version 4.9.0"),
            ("podman", "image", "exists"): ToolResult(exit_code=0, stdout=""),
        }
        fake_runner = _RecordingToolRunner(
            responses=responses, default=ToolResult(exit_code=0, stdout="ok", stderr="")
        )

        choice = resolve_runner_choice("auto", fake_runner)
        build_container_invocation(
            repo_path=tmp_path, temp_path=tmp_path / ".temp", env={}, cli_args=["review"]
        )
        result = run_review_via_container(
            fake_runner,
            repo_path=tmp_path,
            temp_path=tmp_path / ".temp",
            env={},
            cli_args=["review"],
        )

        assert choice == "container"
        assert result.stdout == "ok"
        assert len(fake_runner.invocations) >= 2
