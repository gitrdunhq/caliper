# tested-by: tests/unit/test_publisher_create_pr.py
"""``PullRequestPublisherPort.create_pull_request`` — new PR-creation capability (#524).

RED phase: ``create_pull_request`` does not exist yet anywhere in the port or
its adapters. Needed for stacked PR push (#524 bullet 1): opening N new PRs,
one per part, is the one capability the port never had — every existing
method only ever posts to a PR that already exists.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from caliper.adapters.github_publisher import GitHubPublisher, NullPublisher
from caliper.core.ports import PullRequestPublisherPort


class TestPortDeclaresCreatePullRequest:
    def test_port_has_create_pull_request_method(self) -> None:
        assert hasattr(
            PullRequestPublisherPort, "create_pull_request"
        ), "PullRequestPublisherPort must declare a 'create_pull_request' method"


class TestGitHubPublisherCreatePullRequest:
    def test_builds_exact_gh_argv(self) -> None:
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="https://github.com/o/r/pull/7\n", stderr=""
            )
            pub.create_pull_request("o/r", "feat-b", "main", "T", "B")
        args, kwargs = mock_run.call_args
        assert args[0] == [
            "gh",
            "pr",
            "create",
            "--repo",
            "o/r",
            "--head",
            "feat-b",
            "--base",
            "main",
            "--title",
            "T",
            "--body",
            "B",
        ]
        assert kwargs["timeout"] == 30

    def test_returns_url_parsed_from_stdout_on_success(self) -> None:
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="https://github.com/o/r/pull/7\n", stderr=""
            )
            result = pub.create_pull_request("o/r", "feat-b", "main", "T", "B")
        assert result == "https://github.com/o/r/pull/7"

    def test_returns_none_on_nonzero_exit(self) -> None:
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
            result = pub.create_pull_request("o/r", "feat-b", "main", "T", "B")
        assert result is None

    def test_returns_none_on_exception(self) -> None:
        pub = GitHubPublisher()
        with patch("subprocess.run", side_effect=FileNotFoundError("gh not found")):
            result = pub.create_pull_request("o/r", "feat-b", "main", "T", "B")
        assert result is None

    def test_returns_none_on_timeout(self) -> None:
        pub = GitHubPublisher()
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(["gh", "pr", "create"], 30),
        ):
            result = pub.create_pull_request("o/r", "feat-b", "main", "T", "B")
        assert result is None

    def test_returns_none_on_unparseable_stdout(self) -> None:
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="not a url\n", stderr="")
            result = pub.create_pull_request("o/r", "feat-b", "main", "T", "B")
        assert result is None

    def test_sets_token_env_when_provided(self) -> None:
        pub = GitHubPublisher(token="ghp_secret")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="https://github.com/o/r/pull/1\n", stderr=""
            )
            pub.create_pull_request("o/r", "feat-b", "main", "T", "B")
        kwargs = mock_run.call_args[1]
        assert kwargs.get("env", {}).get("GH_TOKEN") == "ghp_secret"


class TestNullPublisherCreatePullRequest:
    def test_returns_a_fake_url(self) -> None:
        result = NullPublisher().create_pull_request("o/r", "h", "b", "t", "y")
        assert result is not None
        assert isinstance(result, str)

    def test_is_deterministic_for_same_inputs(self) -> None:
        a = NullPublisher().create_pull_request("o/r", "h", "b", "t", "y")
        b = NullPublisher().create_pull_request("o/r", "h", "b", "t", "y")
        assert a == b


class TestProtocolConformanceStillHolds:
    def test_github_publisher_still_satisfies_port(self) -> None:
        assert isinstance(GitHubPublisher(), PullRequestPublisherPort)

    def test_null_publisher_satisfies_port(self) -> None:
        assert isinstance(NullPublisher(), PullRequestPublisherPort)
