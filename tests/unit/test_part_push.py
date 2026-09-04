"""Tests for the stacked-PR push imperative shell — ``cli.part_push`` (#524).

# tested-by: tests/unit/test_part_push.py

Offline: a fake ``ToolRunnerPort`` records every ``ToolInvocation`` and
returns canned exit codes per command; a fake publisher records
``create_pull_request``/``post_comment`` calls. No real git, no network.
"""

from __future__ import annotations

from pathlib import Path

from caliper.cli.part_push import StackPushResult, materialize_parts, push_stack
from caliper.core.models import ChangeType, Kerf, Part
from caliper.core.part_stack import StackEntry
from caliper.core.tool_runner import ToolInvocation, ToolResult


def _part(bucket: ChangeType, *files: str) -> Part:
    return Part(id="p", files=sorted(files), bucket=bucket, size=1, opened_by=Kerf(fired_rule="r"))


def _entries(n: int) -> list[StackEntry]:
    out = []
    prev_base = "main"
    for i in range(1, n + 1):
        remote = f"caliper-pr524-{i:02d}-business"
        out.append(
            StackEntry(
                index=i,
                local_ref=f"caliper-part-{i}",
                remote_branch=remote,
                base_branch=prev_base,
                part=_part(ChangeType.business, f"f{i}.py"),
            )
        )
        prev_base = remote
    return out


class FakeRunner:
    """Records every ToolInvocation; returns a canned ToolResult per command
    prefix (matched by the first N argv elements), else exit_code=0."""

    def __init__(self, exit_codes: dict[tuple, int] | None = None) -> None:
        self.calls: list[ToolInvocation] = []
        self._exit_codes = exit_codes or {}

    def run(self, invocation: ToolInvocation) -> ToolResult:
        self.calls.append(invocation)
        for prefix, code in self._exit_codes.items():
            if tuple(invocation.cmd[: len(prefix)]) == prefix:
                return ToolResult(exit_code=code, stdout="", stderr="boom" if code else "")
        return ToolResult(exit_code=0, stdout="", stderr="")


class FakePublisher:
    def __init__(self, urls: list[str | None] | None = None, comment_result: bool = True) -> None:
        self._urls = list(urls or [])
        self._comment_result = comment_result
        self.create_calls: list[tuple] = []
        self.comment_calls: list[tuple] = []

    def create_pull_request(self, repo, head, base, title, body):
        self.create_calls.append((repo, head, base, title, body))
        if self._urls:
            return self._urls.pop(0)
        return f"https://github.com/{repo}/pull/{len(self.create_calls) + 100}"

    def post_comment(self, repo, pr_num, body):
        self.comment_calls.append((repo, pr_num, body))
        return self._comment_result

    def post_review(self, repo, pr_num, review):
        return True

    def add_label(self, repo, pr_num, label):
        return True


class TestMaterializeParts:
    def test_runs_bash_with_resolved_absolute_path(self, tmp_path: Path) -> None:
        script = tmp_path / "restack.sh"
        script.write_text("#!/bin/bash\n")
        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        runner = FakeRunner()

        materialize_parts(str(script), repo_path, runner)

        assert len(runner.calls) == 1
        inv = runner.calls[0]
        assert inv.cmd == ["bash", str(script.resolve())]
        assert inv.cwd == str(repo_path)
        assert inv.timeout == 300

    def test_returns_true_on_exit_zero(self, tmp_path: Path) -> None:
        script = tmp_path / "restack.sh"
        script.write_text("")
        repo_path = tmp_path
        runner = FakeRunner()
        assert materialize_parts(str(script), repo_path, runner) is True

    def test_returns_false_on_nonzero_exit(self, tmp_path: Path) -> None:
        script = tmp_path / "restack.sh"
        script.write_text("")
        repo_path = tmp_path
        runner = FakeRunner(exit_codes={("bash",): 1})
        assert materialize_parts(str(script), repo_path, runner) is False


class TestPushStack:
    def test_pushes_each_entry_with_exact_argv(self, tmp_path: Path) -> None:
        entries = _entries(2)
        runner = FakeRunner()
        publisher = FakePublisher()

        push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        verify_calls = [c for c in runner.calls if c.cmd[:3] == ["git", "rev-parse", "--verify"]]
        push_calls = [c for c in runner.calls if c.cmd[:2] == ["git", "push"]]
        assert [c.cmd for c in verify_calls] == [
            ["git", "rev-parse", "--verify", "caliper-part-1"],
            ["git", "rev-parse", "--verify", "caliper-part-2"],
        ]
        assert [c.cmd for c in push_calls] == [
            ["git", "push", "origin", "caliper-part-1:refs/heads/caliper-pr524-01-business"],
            ["git", "push", "origin", "caliper-part-2:refs/heads/caliper-pr524-02-business"],
        ]
        assert all(c.cwd == str(tmp_path) for c in verify_calls + push_calls)

    def test_pr_base_chain_matches_previous_entrys_remote_branch(self, tmp_path: Path) -> None:
        entries = _entries(3)
        runner = FakeRunner()
        publisher = FakePublisher()

        push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        bases = [call[2] for call in publisher.create_calls]
        assert bases == ["main", entries[0].remote_branch, entries[1].remote_branch]

    def test_opened_urls_collected_in_order(self, tmp_path: Path) -> None:
        entries = _entries(2)
        runner = FakeRunner()
        publisher = FakePublisher(
            urls=["https://github.com/o/r/pull/1", "https://github.com/o/r/pull/2"]
        )

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert result.opened_urls == [
            "https://github.com/o/r/pull/1",
            "https://github.com/o/r/pull/2",
        ]
        assert result.failed_index is None
        assert result.error is None

    def test_stops_at_first_verify_failure_no_later_invocations(self, tmp_path: Path) -> None:
        entries = _entries(3)
        runner = FakeRunner(exit_codes={("git", "rev-parse", "--verify", "caliper-part-2"): 1})
        publisher = FakePublisher()

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert result.failed_index == 2
        assert result.error is not None and "caliper-part-2" in result.error
        assert len(result.opened_urls) == 1
        # no verify/push for part 3 at all
        assert not any("caliper-part-3" in " ".join(c.cmd) for c in runner.calls)
        assert len(publisher.create_calls) == 1

    def test_stops_at_first_push_failure(self, tmp_path: Path) -> None:
        entries = _entries(2)
        runner = FakeRunner(exit_codes={("git", "push"): 1})
        publisher = FakePublisher()

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert result.failed_index == 1
        assert result.opened_urls == []
        assert len(publisher.create_calls) == 0

    def test_stops_when_create_pull_request_returns_none(self, tmp_path: Path) -> None:
        entries = _entries(2)
        runner = FakeRunner()
        publisher = FakePublisher(urls=[None])

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert result.failed_index == 1
        assert result.opened_urls == []
        # part 2's push never attempted
        assert not any("caliper-part-2" in " ".join(c.cmd) for c in runner.calls)

    def test_posts_linking_comment_only_on_full_success(self, tmp_path: Path) -> None:
        entries = _entries(2)
        runner = FakeRunner()
        publisher = FakePublisher()

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert len(publisher.comment_calls) == 1
        assert result.comment_posted is True

    def test_comment_not_posted_on_partial_failure(self, tmp_path: Path) -> None:
        entries = _entries(2)
        runner = FakeRunner(exit_codes={("git", "push"): 1})
        publisher = FakePublisher()

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert len(publisher.comment_calls) == 0
        assert result.comment_posted is False

    def test_comment_failure_is_non_fatal_and_does_not_touch_opened_urls(
        self, tmp_path: Path
    ) -> None:
        entries = _entries(1)
        runner = FakeRunner()
        publisher = FakePublisher(comment_result=False)

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert result.comment_posted is False
        assert result.failed_index is None
        assert result.error is None
        assert len(result.opened_urls) == 1

    def test_single_entry_stack_opens_one_pr_and_posts_comment(self, tmp_path: Path) -> None:
        entries = _entries(1)
        runner = FakeRunner()
        publisher = FakePublisher()

        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=publisher,
            runner=runner,
        )

        assert len(result.opened_urls) == 1
        assert publisher.create_calls[0][2] == "main"
        assert result.comment_posted is True

    def test_stack_push_result_is_a_dataclass_with_expected_fields(self, tmp_path: Path) -> None:
        entries = _entries(1)
        result = push_stack(
            entries,
            repo_path=tmp_path,
            slug="owner/repo",
            pr_number=524,
            publisher=FakePublisher(),
            runner=FakeRunner(),
        )
        assert isinstance(result, StackPushResult)
        assert isinstance(result.opened_urls, list)
