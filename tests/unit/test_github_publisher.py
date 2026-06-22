# tested-by: tests/unit/test_github_publisher.py
"""Contract tests for GitHubPublisher adapter (issue #177).

RED phase: all tests import from caliper.adapters.github_publisher which does not exist yet.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from caliper.adapters.github_publisher import (
    GitHubPublisher,  # noqa: F401 — will ImportError until green
)
from caliper.core.ports import PullRequestPublisherPort

# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_github_publisher_satisfies_pull_request_publisher_port(self):
        """GitHubPublisher must be an instance of PullRequestPublisherPort."""
        pub = GitHubPublisher()
        assert isinstance(pub, PullRequestPublisherPort)


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_constructor_accepts_no_args(self):
        """Constructor works with no arguments (token defaults to None)."""
        pub = GitHubPublisher()
        assert pub.token is None

    def test_constructor_accepts_token(self):
        """Constructor accepts an explicit token string."""
        pub = GitHubPublisher(token="ghp_abc123")
        assert pub.token == "ghp_abc123"


# ---------------------------------------------------------------------------
# post_comment
# ---------------------------------------------------------------------------


class TestPostComment:
    def test_post_comment_returns_true_on_success(self):
        """post_comment returns True when gh CLI exits 0."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = pub.post_comment("org/repo", 42, "great work")
        assert result is True

    def test_post_comment_returns_false_on_failure(self):
        """post_comment returns False when gh CLI exits non-zero."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            result = pub.post_comment("org/repo", 42, "great work")
        assert result is False

    def test_post_comment_calls_gh_cli(self):
        """post_comment must invoke the `gh` CLI."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("org/repo", 7, "body text")
        args = mock_run.call_args[0][0]
        assert args[0] == "gh"

    def test_post_comment_passes_repo_and_pr_number(self):
        """gh CLI call must include the repo and PR number."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("myorg/myrepo", 99, "hello")
        args = mock_run.call_args[0][0]
        cmd_str = " ".join(str(a) for a in args)
        assert "myorg/myrepo" in cmd_str
        assert "99" in cmd_str

    def test_post_comment_passes_body(self):
        """gh CLI call must include the comment body."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("org/repo", 1, "unique-body-text")
        # Body might be passed as arg or via stdin — check call args list
        call_args = mock_run.call_args
        all_args = " ".join(str(a) for a in call_args[0][0])
        all_kwargs = str(call_args[1]) if call_args[1] else ""
        assert "unique-body-text" in all_args or "unique-body-text" in all_kwargs

    def test_post_comment_sets_token_env_when_provided(self):
        """When token is set, GH_TOKEN must be in the subprocess env."""
        pub = GitHubPublisher(token="ghp_secret")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("org/repo", 1, "body")
        kwargs = mock_run.call_args[1]
        env = kwargs.get("env") or {}
        assert env.get("GH_TOKEN") == "ghp_secret"

    def test_post_comment_returns_false_on_exception(self):
        """post_comment returns False (does not raise) when subprocess raises."""
        pub = GitHubPublisher()
        with patch("subprocess.run", side_effect=FileNotFoundError("gh not found")):
            result = pub.post_comment("org/repo", 1, "body")
        assert result is False


# ---------------------------------------------------------------------------
# post_review
# ---------------------------------------------------------------------------


class TestPostReview:
    def test_post_review_returns_true_on_success(self):
        """post_review returns True when gh CLI exits 0."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = pub.post_review("org/repo", 5, {"event": "APPROVE", "body": "lgtm"})
        assert result is True

    def test_post_review_returns_false_on_failure(self):
        """post_review returns False when gh CLI exits non-zero."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            result = pub.post_review("org/repo", 5, {"event": "REQUEST_CHANGES"})
        assert result is False

    def test_post_review_calls_gh_cli(self):
        """post_review must invoke the `gh` CLI."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_review("org/repo", 3, {"event": "COMMENT"})
        args = mock_run.call_args[0][0]
        assert args[0] == "gh"

    def test_post_review_returns_false_on_exception(self):
        """post_review returns False (does not raise) when subprocess raises."""
        pub = GitHubPublisher()
        with patch("subprocess.run", side_effect=FileNotFoundError("gh not found")):
            result = pub.post_review("org/repo", 1, {})
        assert result is False


# ---------------------------------------------------------------------------
# add_label
# ---------------------------------------------------------------------------


class TestAddLabel:
    def test_add_label_returns_true_on_success(self):
        """add_label returns True when gh CLI exits 0."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = pub.add_label("org/repo", 12, "security")
        assert result is True

    def test_add_label_returns_false_on_failure(self):
        """add_label returns False when gh CLI exits non-zero."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            result = pub.add_label("org/repo", 12, "security")
        assert result is False

    def test_add_label_calls_gh_cli(self):
        """add_label must invoke the `gh` CLI."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.add_label("org/repo", 8, "needs-review")
        args = mock_run.call_args[0][0]
        assert args[0] == "gh"

    def test_add_label_passes_label_name(self):
        """gh CLI call must include the label name."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.add_label("org/repo", 8, "my-special-label")
        args = mock_run.call_args[0][0]
        cmd_str = " ".join(str(a) for a in args)
        assert "my-special-label" in cmd_str

    def test_add_label_returns_false_on_exception(self):
        """add_label returns False (does not raise) when subprocess raises."""
        pub = GitHubPublisher()
        with patch("subprocess.run", side_effect=FileNotFoundError("gh not found")):
            result = pub.add_label("org/repo", 1, "label")
        assert result is False


# ---------------------------------------------------------------------------
# Token scrubbing (security: wave2-patch-7)
# ---------------------------------------------------------------------------


class TestTokenScrubbing:
    def test_scrub_token_replaces_token_with_redacted(self):
        """_scrub_token must replace the raw token with [REDACTED]."""
        token = "ghp_super_secret_token_12345"
        publisher = GitHubPublisher(token=token)
        result = publisher._scrub_token(f"Error: Bearer {token} is invalid")
        assert token not in result
        assert "[REDACTED]" in result

    def test_scrub_token_is_noop_when_token_absent(self):
        """_scrub_token must not modify text that does not contain the token."""
        publisher = GitHubPublisher(token="ghp_mytoken")
        result = publisher._scrub_token("Error: something else happened")
        assert result == "Error: something else happened"

    def test_run_scrubs_token_from_stderr_after_failed_command(self):
        """_run must scrub the token from result.stderr when the command fails."""
        token = "ghp_super_secret_12345"
        publisher = GitHubPublisher(token=token)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = f"Error: authentication failed with token {token}"
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            publisher._run(["gh", "pr", "comment", "1", "--repo", "org/repo", "--body", "test"])

        # The mock_result.stderr attribute must have been overwritten with the scrubbed value.
        assert token not in mock_result.stderr
        assert "[REDACTED]" in mock_result.stderr


# ---------------------------------------------------------------------------
# Subprocess timeout (security: wave4-patch-2)
# ---------------------------------------------------------------------------


class TestSubprocessTimeout:
    """_run() must pass an explicit timeout to subprocess.run to prevent hangs."""

    _CMD = ["gh", "pr", "comment", "1", "--repo", "org/repo", "--body", "test"]

    def test_run_passes_timeout_kwarg_to_subprocess(self):
        """_run() must call subprocess.run with a numeric timeout keyword argument."""
        publisher = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            publisher._run(self._CMD)

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert "timeout" in call_kwargs, "subprocess.run must include timeout= parameter"
        assert isinstance(call_kwargs["timeout"], (int, float)), "timeout must be numeric"
        assert call_kwargs["timeout"] is not None

    def test_post_comment_uses_timeout(self):
        """post_comment must invoke subprocess with a timeout."""
        publisher = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            publisher.post_comment("org/repo", 1, "body")

        call_kwargs = mock_run.call_args[1]
        assert "timeout" in call_kwargs, "post_comment subprocess call missing timeout"

    def test_post_review_uses_timeout(self):
        """post_review must invoke subprocess with a timeout."""
        publisher = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            publisher.post_review("org/repo", 1, {"event": "APPROVE"})

        call_kwargs = mock_run.call_args[1]
        assert "timeout" in call_kwargs, "post_review subprocess call missing timeout"

    def test_add_label_uses_timeout(self):
        """add_label must invoke subprocess with a timeout."""
        publisher = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            publisher.add_label("org/repo", 1, "bug")

        call_kwargs = mock_run.call_args[1]
        assert "timeout" in call_kwargs, "add_label subprocess call missing timeout"

    def test_timeout_expired_returns_false(self):
        """subprocess.TimeoutExpired must be caught and return False."""
        import subprocess

        publisher = GitHubPublisher()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(self._CMD, 30)):
            result = publisher._run(self._CMD)

        assert result is False, "TimeoutExpired must return False, not propagate"
