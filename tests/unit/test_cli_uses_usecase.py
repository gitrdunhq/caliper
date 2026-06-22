"""Tests verifying that CLI review() delegates to review_repository().

RED phase for issue #183 — all five tests must FAIL until cli/main.py is
updated to call review_repository() instead of registry.run_all() directly.
"""

# tested-by: tests/unit/test_cli_uses_usecase.py

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from caliper.cli.main import cli
from caliper.core.use_cases import ReviewOptions, ReviewResult


def _make_fake_result(results: list | None = None) -> ReviewResult:
    """Build a minimal ReviewResult for use as mock return values."""
    return ReviewResult(
        results=results or [],
        verdict="clear",
        security_score=100.0,
        quality_score=100.0,
    )


# ---------------------------------------------------------------------------
# 1. CLI review() calls review_repository()
# ---------------------------------------------------------------------------


class TestCliCallsReviewRepository:
    """CLI review() must delegate to review_repository() instead of calling
    registry.run_all() directly."""

    def test_review_calls_review_repository(self) -> None:
        """review() invokes review_repository() exactly once."""
        runner = CliRunner()
        fake_result = _make_fake_result()

        with (
            patch("caliper.core.use_cases.review_repository", return_value=fake_result) as mock_rr,
            runner.isolated_filesystem(),
        ):
            runner.invoke(cli, ["review", "--repo-path", ".", "--all"])

        mock_rr.assert_called_once()


# ---------------------------------------------------------------------------
# 2. CLI review() passes the right ReviewOptions
# ---------------------------------------------------------------------------


class TestCliPassesCorrectReviewOptions:
    """CLI review() must build ReviewOptions from CLI args and pass it to
    review_repository()."""

    def test_scanners_option_is_forwarded(self) -> None:
        """--scanners is split on commas and forwarded as ReviewOptions.scanners."""
        runner = CliRunner()
        fake_result = _make_fake_result()

        with (
            patch("caliper.core.use_cases.review_repository", return_value=fake_result) as mock_rr,
            runner.isolated_filesystem(),
        ):
            runner.invoke(
                cli,
                ["review", "--repo-path", ".", "--all", "--scanners", "semgrep,trivy"],
            )

        # Call signature: review_repository(context, files, repo_path, options)
        options: ReviewOptions = mock_rr.call_args.args[3]
        assert options.scanners == ["semgrep", "trivy"]

    def test_disable_option_is_forwarded(self) -> None:
        """--disable is parsed and included in ReviewOptions.disabled."""
        runner = CliRunner()
        fake_result = _make_fake_result()

        with (
            patch("caliper.core.use_cases.review_repository", return_value=fake_result) as mock_rr,
            runner.isolated_filesystem(),
        ):
            runner.invoke(
                cli,
                ["review", "--repo-path", ".", "--all", "--disable", "gitleaks"],
            )

        options: ReviewOptions = mock_rr.call_args.args[3]
        assert "gitleaks" in options.disabled

    def test_enable_option_is_forwarded(self) -> None:
        """--enable is parsed and included in ReviewOptions.enabled."""
        runner = CliRunner()
        fake_result = _make_fake_result()

        with (
            patch("caliper.core.use_cases.review_repository", return_value=fake_result) as mock_rr,
            runner.isolated_filesystem(),
        ):
            runner.invoke(
                cli,
                ["review", "--repo-path", ".", "--all", "--enable", "custom-plugin"],
            )

        options: ReviewOptions = mock_rr.call_args.args[3]
        assert "custom-plugin" in options.enabled


# ---------------------------------------------------------------------------
# 3. CLI review() uses ReviewResult.results for rendering
# ---------------------------------------------------------------------------


class TestCliUsesReviewResultForRendering:
    """CLI review() must pass ReviewResult.results to the renderer, not the
    raw registry output."""

    def test_render_comment_receives_results_from_review_result(self) -> None:
        """render_comment is called with exactly the results list from ReviewResult."""
        runner = CliRunner()
        fake_plugin_result = MagicMock()
        fake_plugin_result.name = "fake-scanner"
        fake_plugin_result.findings = []
        fake_plugin_result.error = None
        fake_result = _make_fake_result(results=[fake_plugin_result])

        with patch("caliper.core.use_cases.review_repository", return_value=fake_result):
            with patch(
                "caliper.core.renderer.render_comment", return_value="# report"
            ) as mock_render:
                with runner.isolated_filesystem():
                    runner.invoke(cli, ["review", "--repo-path", ".", "--all"])

        mock_render.assert_called_once()
        # First positional arg to render_comment must be the results list.
        assert mock_render.call_args.args[0] == [fake_plugin_result]
