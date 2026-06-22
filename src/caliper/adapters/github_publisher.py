# tested-by: tests/unit/test_github_publisher.py
"""GitHubPublisher — PullRequestPublisherPort adapter using the gh CLI.

Calls `gh pr comment`, `gh pr review`, and `gh pr edit` to publish review
artifacts back to a GitHub pull request.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

from caliper.core.ports import PullRequestPublisherPort


class GitHubPublisher:
    """Implements PullRequestPublisherPort by shelling out to the gh CLI."""

    def __init__(self, token: str | None = None) -> None:
        self.token = token

    def _env(self) -> dict[str, str] | None:
        """Build env dict with GH_TOKEN injected when a token is set."""
        if self.token is None:
            return None
        env = os.environ.copy()
        env["GH_TOKEN"] = self.token
        return env

    def _scrub_token(self, text: str) -> str:
        """Replace the raw token value with [REDACTED] to prevent accidental exposure."""
        if self.token and self.token in text:
            return text.replace(self.token, "[REDACTED]")
        return text

    def _run(self, cmd: list[str]) -> bool:
        """Run a gh CLI command. Returns True on exit 0, False otherwise."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self._env(),
                timeout=30,
            )
            if result.stderr:
                result.stderr = self._scrub_token(result.stderr)
            return result.returncode == 0
        except Exception:
            return False

    def post_comment(self, repo: str, pr_num: int, body: str) -> bool:
        """Post a comment on a pull request."""
        return self._run(["gh", "pr", "comment", str(pr_num), "--repo", repo, "--body", body])

    def post_review(self, repo: str, pr_num: int, review: dict[str, Any]) -> bool:
        """Submit a review on a pull request."""
        event = review.get("event", "COMMENT")
        review_body = review.get("body", "")
        cmd = ["gh", "pr", "review", str(pr_num), "--repo", repo]
        if event == "APPROVE":
            cmd.append("--approve")
        elif event == "REQUEST_CHANGES":
            cmd.extend(["--request-changes", "--body", review_body])
        else:
            cmd.extend(["--comment", "--body", review_body])
        return self._run(cmd)

    def add_label(self, repo: str, pr_num: int, label: str) -> bool:
        """Add a label to a pull request."""
        return self._run(["gh", "pr", "edit", str(pr_num), "--repo", repo, "--add-label", label])


class NullPublisher:
    """No-op PullRequestPublisherPort for testing and dry-run contexts."""

    def post_comment(self, repo: str, pr_num: int, body: str) -> bool:
        return True

    def post_review(self, repo: str, pr_num: int, review: dict[str, Any]) -> bool:
        return True

    def add_label(self, repo: str, pr_num: int, label: str) -> bool:
        return True


assert isinstance(
    GitHubPublisher(), PullRequestPublisherPort
), "GitHubPublisher must satisfy PullRequestPublisherPort"


from caliper.core.registries import PUBLISHERS  # noqa: E402  (registration wiring)


@PUBLISHERS.register("github")
def build_github_publisher(*, token: str | None = None) -> GitHubPublisher:
    return GitHubPublisher(token=token)


@PUBLISHERS.register("null")
def build_null_publisher() -> NullPublisher:
    return NullPublisher()
