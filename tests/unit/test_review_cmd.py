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
from caliper.core.use_cases import ScanScope


class TestResolvePluginSelection:
    def test_no_flags_returns_repo_config_lists(self) -> None:
        repo_config = RepoConfig(plugins=PluginConfig(disabled=["osv"], enabled=["trivy"]))

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="")

        assert disabled == {"osv", "clamav"}
        assert enabled == {"trivy"}

    def test_cli_flags_merge_with_repo_config(self) -> None:
        repo_config = RepoConfig(plugins=PluginConfig(disabled=["osv"], enabled=[]))

        disabled, enabled = resolve_plugin_selection(
            repo_config, disable="syft, cpd", enable="secrets"
        )

        assert disabled == {"osv", "syft", "cpd", "clamav"}
        assert enabled == {"secrets"}

    def test_empty_string_entries_are_discarded(self) -> None:
        repo_config = RepoConfig()

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="")

        assert disabled == {"clamav"}
        assert enabled == set()

    def test_clamav_is_opt_in_by_default(self) -> None:
        """clamav is expensive/noisy — never on by default, only via --enable."""
        repo_config = RepoConfig()

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="")

        assert "clamav" in disabled
        assert "clamav" not in enabled

    def test_clamav_enable_flag_overrides_default_opt_out(self) -> None:
        repo_config = RepoConfig()

        disabled, enabled = resolve_plugin_selection(repo_config, disable="", enable="clamav")

        assert "clamav" in disabled  # still present, but...
        assert "clamav" in enabled  # ...enabled wins per run_all's precedence rule


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
