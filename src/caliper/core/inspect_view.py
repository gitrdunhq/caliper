"""Per-part review view — the changed-line map and content for one part.

# tested-by: tests/unit/test_inspect_view.py

Builds the inputs the inspection needs from the stock, without re-parsing diffs
elsewhere: the hunk line map (file -> changed new-side line numbers) the Adjudicate
anchor rule needs, the changed-line text (file -> joined added-line content) the
anchor rule checks ``anchor_quote`` against, the changed-line bytes the cache key
hashes, and the unified diff text the Review prompt shows. All git runs through
``ToolRunnerPort`` and is fail-closed (a git failure is a hard error, never a
partial view).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from caliper.core.parting import PartingError
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

_GIT_TIMEOUT = 60
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class PartView:
    """The review view for one part: anchors, cache material, and prompt material."""

    changed_lines: dict[str, set[int]] = field(default_factory=dict)
    changed_text: dict[str, str] = field(default_factory=dict)
    changed_bytes: bytes = b""
    diff_text: str = ""


def _git_base(root: Path) -> list[str]:
    return ["git", "-c", f"safe.directory={root}", "-c", "core.ignorecase=false"]


def _run_git(runner: ToolRunnerPort, root: Path, args: list[str]) -> str:
    result = runner.run(
        ToolInvocation(cmd=[*_git_base(root), *args], cwd=str(root), timeout=_GIT_TIMEOUT)
    )
    if result.not_installed:
        raise PartingError("git is not installed; inspect requires git")
    if result.timed_out:
        raise PartingError(f"git timed out after {_GIT_TIMEOUT}s: git {' '.join(args)}")
    if result.exit_code != 0:
        raise PartingError(
            f"git failed (exit {result.exit_code}): git {' '.join(args)}\n{result.stderr[:400]}"
        )
    return result.stdout


def parse_unified_diff(text: str) -> dict[str, list[tuple[int, str]]]:
    """Parse a ``git diff -U0`` into file -> list of (new_line_number, added_content).

    Only added (new-side) lines are recorded — they are the changed lines a claim
    may anchor to. Deletions consume no new-side line number.
    """
    out: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    new_line = 0
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            current = line[len("+++ b/") :]
            out.setdefault(current, [])
            continue
        if line.startswith("+++ ") or line.startswith("--- "):
            continue
        m = _HUNK_RE.match(line)
        if m:
            new_line = int(m.group(1))
            continue
        if current is None:
            continue
        if line.startswith("+"):
            out[current].append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-"):
            continue  # removed line: no new-side number
        # context lines do not appear with -U0
    return out


def build_view(
    repo_path: Path,
    base: str,
    head: str,
    files: list[str],
    runner: ToolRunnerPort | None = None,
) -> PartView:
    """Compute the :class:`PartView` for *files* over ``base..head``. Fail-closed."""
    runner = runner or SubprocessToolRunner()
    if not files:
        return PartView()
    diff_text = _run_git(
        runner,
        repo_path,
        ["diff", "--no-color", "-U0", base, head, "--", *files],
    )
    parsed = parse_unified_diff(diff_text)
    changed_lines: dict[str, set[int]] = {}
    changed_text: dict[str, str] = {}
    chunks: list[bytes] = []
    for f in sorted(parsed):
        nums = sorted(n for n, _ in parsed[f])
        changed_lines[f] = set(nums)
        changed_text[f] = "\n".join(content for _, content in sorted(parsed[f]))
        for n, content in sorted(parsed[f]):
            chunks.append(f"{f}:{n}:".encode() + content.encode("utf-8", "replace") + b"\n")
    return PartView(
        changed_lines=changed_lines,
        changed_text=changed_text,
        changed_bytes=b"".join(chunks),
        diff_text=diff_text,
    )
