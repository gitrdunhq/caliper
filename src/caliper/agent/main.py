"""Foreman agent entry point and orchestrator.
# tested-by: tests/unit/test_agent_main.py

Reactive PR flow: GitHub Action invokes this module, which creates a
Copilot agent session with tools, evaluates the PR diff, and posts
per-package review comments.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import httpx
import structlog

from caliper.agent.config import AgentSettings, EnforcementMode
from caliper.agent.prompt import build_system_prompt
from caliper.agent.tools import (  # noqa: F401
    analyze_complexity,
    check_package,
    evaluate_change,
    scan_code,
    scan_duplicates,
    scan_k8s,
)

logger = structlog.get_logger(__name__)

_MAX_DIFF_IN_MESSAGE = 200_000


class ForemanAgent:
    """Orchestrates the full reactive PR review flow."""

    def __init__(self, config: AgentSettings) -> None:
        self._config = config
        self._decisions_have_reject = False

    async def run(
        self,
        diff_text: str,
        pr_url: str,
        pr_number: int,
        repo_owner: str,
        repo_name: str,
        team: str,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full agent flow. Returns summary dict with exit_code."""
        is_log_mode = self._config.enforcement_mode == EnforcementMode.log

        async with httpx.AsyncClient(
            timeout=30,
            headers=self._github_headers(),
        ) as http:
            self._http = http

            if not is_log_mode:
                await self._post_comment(
                    pr_number,
                    repo_owner,
                    repo_name,
                    "⏳ **Foreman** is reviewing this PR...",
                )

            try:
                agent_response = await self._run_agent_session(diff_text, pr_url, team)
            except Exception as exc:
                logger.error("agent.session_failed", error=str(exc))
                fail_closed = self._config.enforcement_mode == EnforcementMode.block
                if not is_log_mode:
                    await self._post_comment(
                        pr_number,
                        repo_owner,
                        repo_name,
                        f"🔴 **Foreman** review failed: {exc}\n\n"
                        + (
                            "Build blocked — review did not complete."
                            if fail_closed
                            else "Review incomplete."
                        ),
                    )
                return {
                    "exit_code": 1 if fail_closed else 0,
                    "comments_posted": 1 if not is_log_mode else 0,
                    "error": str(exc),
                }

            has_reject = self._decisions_have_reject

            comments_posted = 0
            if not is_log_mode and agent_response.strip():
                body = agent_response
                if len(body) > self._config.max_comment_length:
                    body = body[: self._config.max_comment_length] + "\n\n*[truncated]*"
                await self._post_comment(pr_number, repo_owner, repo_name, body)
                comments_posted = 1

            if has_reject and self._config.enforcement_mode == EnforcementMode.block:
                exit_code = 1
            else:
                exit_code = 0

            if commit_sha:
                status = "failure" if exit_code == 1 else "success"
                await self._set_check_status(commit_sha, repo_owner, repo_name, status)

        return {
            "exit_code": exit_code,
            "comments_posted": comments_posted,
            "has_reject": has_reject,
        }

    async def _run_agent_session(
        self,
        diff_text: str,
        pr_url: str,
        team: str,
    ) -> str:
        """Create a Copilot agent session and run it against the diff."""
        from agent_framework_github_copilot import GitHubCopilotAgent

        system_prompt = build_system_prompt(
            policy_version=self._config.policy_version,
        )

        self._decisions_have_reject = False

        agent = GitHubCopilotAgent(
            instructions=system_prompt,
            name="foreman",
            description="Dependency review and code review agent",
            tools=[
                evaluate_change,
                check_package,
                scan_code,
                scan_duplicates,
                scan_k8s,
                analyze_complexity,
            ],
        )

        diff_summary = diff_text
        if len(diff_text) > _MAX_DIFF_IN_MESSAGE:
            diff_summary = (
                diff_text[:_MAX_DIFF_IN_MESSAGE] + "\n[diff truncated — tools receive full diff]"
            )

        user_message = (
            f"A pull request has been opened at {pr_url} by team '{team}'.\n\n"
            f"Evaluate this PR for dependency changes and code pattern issues.\n\n"
            f"1. Call evaluate_change with the full diff to assess dependency changes.\n"
            f"2. Call scan_code with the full diff to check for code pattern issues.\n"
            f"3. Produce per-package review comments using the format in your instructions.\n\n"
            f"Repository path: {self._config.repo_path}\n\n"
            f"<diff>\n{diff_summary}\n</diff>"
        )

        response = await agent.run(user_message)
        response_text = response.text if response else ""

        self._extract_reject_from_tool_results(response)

        return response_text

    def _extract_reject_from_tool_results(self, response: Any) -> None:
        """Check structured tool results for reject verdicts (not LLM prose)."""
        try:
            if not response or not hasattr(response, "value"):
                return
            value = response.value
            if isinstance(value, dict):
                decisions = value.get("decisions", [])
                for d in decisions:
                    if isinstance(d, dict) and d.get("decision") in ("reject", "needs_review"):
                        self._decisions_have_reject = True
                        return
        except Exception as exc:
            logger.debug("extract_reject.parse_error", error=str(exc))

    def _github_headers(self) -> dict[str, str]:
        """Build GitHub API headers."""
        token = self._config.github_token.get_secret_value()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _post_comment(
        self,
        pr_number: int,
        repo_owner: str,
        repo_name: str,
        body: str,
    ) -> None:
        """Post a comment on the PR via GitHub API."""
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments"
        try:
            resp = await self._http.post(url, json={"body": body})
            if resp.status_code >= 400:
                logger.warning(
                    "comment.api_error",
                    pr=pr_number,
                    status=resp.status_code,
                    body=resp.text[:200],
                )
            else:
                logger.info("comment.posted", pr=pr_number, status=resp.status_code)
        except Exception as exc:
            logger.warning("comment.failed", pr=pr_number, error=str(exc))

    async def _set_check_status(
        self,
        commit_sha: str,
        repo_owner: str,
        repo_name: str,
        status: str,
    ) -> None:
        """Set commit status via GitHub API."""
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/statuses/{commit_sha}"
        try:
            await self._http.post(
                url,
                json={
                    "state": status,
                    "context": "foreman/caliper",
                    "description": "Foreman dependency review",
                },
            )
        except Exception as exc:
            logger.warning("check_status.failed", sha=commit_sha, error=str(exc))


async def main() -> None:
    """CLI entry point — reads env vars, runs agent, exits."""
    config = AgentSettings()

    pr_number = int(os.environ.get("FOREMAN_PR_NUMBER", "0"))
    if pr_number == 0:
        logger.error("main.missing_pr_number", hint="Set FOREMAN_PR_NUMBER")
        sys.exit(1)

    diff_path = os.environ.get("FOREMAN_DIFF_PATH", "-")
    if diff_path == "-":
        diff_text = sys.stdin.read()
    else:
        with open(diff_path) as f:
            diff_text = f.read()

    pr_url = os.environ.get("FOREMAN_PR_URL", "")
    repo_owner = os.environ.get("FOREMAN_REPO_OWNER", "")
    repo_name = os.environ.get("FOREMAN_REPO_NAME", "")
    team = os.environ.get("FOREMAN_TEAM", "default")
    commit_sha = os.environ.get("FOREMAN_COMMIT_SHA")

    agent = ForemanAgent(config)
    result = await agent.run(
        diff_text=diff_text,
        pr_url=pr_url,
        pr_number=pr_number,
        repo_owner=repo_owner,
        repo_name=repo_name,
        team=team,
        commit_sha=commit_sha,
    )

    sys.exit(result["exit_code"])


if __name__ == "__main__":
    asyncio.run(main())
