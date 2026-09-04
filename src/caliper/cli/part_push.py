"""Imperative shell: materialize a cut's stack, push each part, open chained
PRs, post the linking comment on the original PR (#524).

# tested-by: tests/unit/test_part_push.py

Composes ``core.part_stack.plan_stack``'s pure plan with real IO: runs the
already-generated restack.sh through ``ToolRunnerPort`` (the exact
invocation shape ``cli/part_session.py``'s ``/apply`` already uses — no
third branch-manipulation code path), then for each ``StackEntry`` in order
verifies the local ref exists, pushes it under its deterministic remote
name, and opens a PR via ``PullRequestPublisherPort.create_pull_request``.
Stops at the first failure; the linking comment is posted only on full
success, never on a partial stack.

Retry/resume of a partially-failed stack is explicitly out of scope (see
SPEC.md's open question) — a failure here is a stop, not a checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from caliper.cli.part_comment import render_stack_link_comment, render_stack_pr_body
from caliper.core.part_stack import StackEntry
from caliper.core.ports import PullRequestPublisherPort
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

_VERIFY_TIMEOUT = 30
_PUSH_TIMEOUT = 120


def materialize_parts(restack_path: str, repo_path: Path, runner: ToolRunnerPort) -> bool:
    """Run the generated restack.sh to create the local caliper-part-* refs.

    ``restack_path`` may be relative to the caller's cwd (e.g. a relative
    ``--out``), not to ``repo_path`` — resolved to absolute first, matching
    ``part_session.py``'s ``/apply`` (a relative path 404s otherwise).
    """
    script_path = str(Path(restack_path).resolve())
    result = runner.run(ToolInvocation(cmd=["bash", script_path], cwd=str(repo_path), timeout=300))
    return result.exit_code == 0


@dataclass(frozen=True)
class StackPushResult:
    """Outcome of pushing a whole stack: what opened, where it stopped."""

    opened_urls: list[str] = field(default_factory=list)
    failed_index: int | None = None
    error: str | None = None
    comment_posted: bool = False


def push_stack(
    entries: list[StackEntry],
    *,
    repo_path: Path,
    slug: str,
    pr_number: int,
    publisher: PullRequestPublisherPort,
    runner: ToolRunnerPort,
    remote: str = "origin",
) -> StackPushResult:
    """Push each entry in order, open its PR, stop at the first failure.

    On full success, posts the linking comment on the original PR
    (non-fatal if it fails — the opened PRs are the durable outcome; the
    comment is a courtesy notification, not rolled back on failure).
    """
    opened_urls: list[str] = []
    total = len(entries)

    for entry in entries:
        verify = runner.run(
            ToolInvocation(
                cmd=["git", "rev-parse", "--verify", entry.local_ref],
                cwd=str(repo_path),
                timeout=_VERIFY_TIMEOUT,
            )
        )
        if verify.exit_code != 0:
            return StackPushResult(
                opened_urls=opened_urls,
                failed_index=entry.index,
                error=(
                    f"local ref {entry.local_ref!r} missing for part {entry.index}/{total}: "
                    f"{verify.stderr}"
                ),
            )

        push = runner.run(
            ToolInvocation(
                cmd=["git", "push", remote, f"{entry.local_ref}:refs/heads/{entry.remote_branch}"],
                cwd=str(repo_path),
                timeout=_PUSH_TIMEOUT,
            )
        )
        if push.exit_code != 0:
            return StackPushResult(
                opened_urls=opened_urls,
                failed_index=entry.index,
                error=(
                    f"push failed for part {entry.index}/{total} "
                    f"({entry.remote_branch}): {push.stderr}"
                ),
            )

        title = f"part {entry.index} of {total}: {entry.part.bucket.value}"
        body = render_stack_pr_body(
            entry.part, index=entry.index, total=total, slug=slug, pr_num=pr_number
        )
        url = publisher.create_pull_request(
            slug, entry.remote_branch, entry.base_branch, title, body
        )
        if url is None:
            return StackPushResult(
                opened_urls=opened_urls,
                failed_index=entry.index,
                error=(f"failed to open PR for part {entry.index}/{total} ({entry.remote_branch})"),
            )
        opened_urls.append(url)

    comment_posted = False
    try:
        comment_body = render_stack_link_comment(opened_urls, slug=slug, pr_num=pr_number)
        comment_posted = bool(publisher.post_comment(slug, pr_number, comment_body))
    except Exception:
        comment_posted = False

    return StackPushResult(opened_urls=opened_urls, comment_posted=comment_posted)
