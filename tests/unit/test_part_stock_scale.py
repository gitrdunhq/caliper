"""Large-diff behavior for the stock producer — ``core.part_stock`` (#525).

# tested-by: tests/unit/test_part_stock_scale.py

Two guarantees at scale, proven without wall-clock timing (which would be
flaky across CI runners of different speed):

1. **O(1) git subprocess calls regardless of file count.** ``build_stock``
   already batches every git invocation (rev-parse x2, ls-files x2, diff
   --name-status, diff --numstat, one batched check-attr) — the number of
   *invocations* must stay identical whether the diff touches 5 files or
   5000, or an N+1 has crept back in.
2. **A progress heartbeat above a file-count threshold**, so a large diff
   doesn't look hung — and silence below it, so normal-size runs stay quiet.
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.part_stock import _PROGRESS_THRESHOLD, build_stock
from caliper.core.repo_config import PartingConfig
from caliper.core.tool_runner import ToolInvocation, ToolResult

_SHAS = {"BASE": "aaaaaaaaaaaa", "HEAD": "bbbbbbbbbbbb"}


class SyntheticRunner:
    """Generates N synthetic modified-file records; records every invocation
    so tests can assert on call *count*, not wall-clock duration."""

    def __init__(self, n: int) -> None:
        self.n = n
        self.calls: list[list[str]] = []
        self._files = [f"src/mod_{i}.py" for i in range(n)]

    def run(self, invocation: ToolInvocation) -> ToolResult:
        cmd = invocation.cmd
        self.calls.append(cmd)

        def ok(out: str) -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        if "rev-parse" in cmd:
            return ok(_SHAS[cmd[-1]] + "\n")
        if "ls-files" in cmd and "-s" in cmd:
            return ok("\n".join(f"100644 sha 0\t{f}" for f in self._files))
        if "ls-files" in cmd:
            return ok("\n".join(self._files))
        if "--name-status" in cmd:
            return ok("\n".join(f"M\t{f}" for f in self._files))
        if "--numstat" in cmd:
            return ok("\n".join(f"1\t1\t{f}" for f in self._files))
        return ok("")


def test_git_invocation_count_is_identical_at_5_and_5000_files() -> None:
    small = SyntheticRunner(5)
    build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), small)

    large = SyntheticRunner(5000)
    build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), large)

    assert len(small.calls) == len(large.calls), (
        f"git invocation count grew with file count ({len(small.calls)} at 5 files vs "
        f"{len(large.calls)} at 5000) — an N+1 has crept into build_stock"
    )


def test_check_attr_is_called_exactly_once_regardless_of_file_count() -> None:
    runner = SyntheticRunner(2000)
    build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), runner)

    check_attr_calls = [c for c in runner.calls if "check-attr" in c]
    assert len(check_attr_calls) == 1


def test_progress_heartbeat_fires_above_the_threshold(monkeypatch) -> None:
    events: list[tuple[str, dict]] = []

    class FakeLogger:
        def info(self, event: str, **kw: object) -> None:
            events.append((event, kw))

    monkeypatch.setattr("caliper.core.part_stock.logger", FakeLogger())
    runner = SyntheticRunner(_PROGRESS_THRESHOLD + 1)

    build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), runner)

    assert events, "no progress heartbeat logged for a diff above the threshold"
    event, kw = events[0]
    assert kw.get("file_count") == _PROGRESS_THRESHOLD + 1


def test_no_heartbeat_below_the_threshold(monkeypatch) -> None:
    events: list[tuple[str, dict]] = []

    class FakeLogger:
        def info(self, event: str, **kw: object) -> None:
            events.append((event, kw))

    monkeypatch.setattr("caliper.core.part_stock.logger", FakeLogger())
    runner = SyntheticRunner(5)

    build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), runner)

    assert not events, f"unexpected progress heartbeat for a small (5-file) diff: {events}"
