#!/usr/bin/env python3
"""Select the pytest targets affected by a change set, deterministically.
# tested-by: tests/unit/test_affected_tests.py

Every source file under src/caliper carries `# tested-by: tests/unit/test_x.py`;
that annotation IS the map. Rules, in order:

* dependency/container/conftest changes -> the full suite (the map cannot be trusted)
* a changed test file selects itself
* a changed source file selects its tested-by file; no annotation or a missing
  target -> the full suite (fail safe, never fail silent)
* workflows, templates and CAPABILITIES map to their policy tests
* the cross-cutting guard tests always run (cheap, catch count/ratchet/tier drift)

Usage: scripts/affected_tests.py [--base REV] [--explain]   -> prints test paths.
Base: CALIPER_TEST_BASE, else a datum lane's batch-root HEAD, else merge-base with main.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ALWAYS_RUN: tuple[str, ...] = (
    "tests/unit/test_capability_counts.py",
    "tests/unit/test_file_size_ratchet.py",
    "tests/unit/test_deterministic_architecture_guards.py",
    "tests/unit/test_drift_guards.py",
)
FULL_SUITE_TRIGGERS: tuple[str, ...] = (
    "pyproject.toml",
    "uv.lock",
    "Dockerfile",
    "Dockerfile.test",
    "conftest.py",
    "tests/conftest.py",
    "Makefile",
    "scripts/test-run.sh",
    "scripts/build-test.sh",
)
PATH_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        r"^\.github/(workflows|actions)/",
        (
            "tests/unit/test_github_actions_policy.py",
            "tests/unit/test_deterministic_workflow_guards.py",
        ),
    ),
    (r"^\.github/dependabot\.yml$", ("tests/unit/test_dependabot_policy.py",)),
    (
        r"^src/caliper/templates/.*\.j2$",
        ("tests/unit/test_plugin_templates.py", "tests/unit/test_renderer.py"),
    ),
    (r"^docs/CAPABILITIES\.md$", ("tests/unit/test_capability_counts.py",)),
    (r"^docs/schema/", ("tests/unit/test_report_schema.py",)),
    (r"^policies/.*\.rego$", ()),  # OPA tests run via `opa test`, not pytest
    (r"^src/caliper/cli/part_ui_dist/", ("tests/unit/test_part_serve.py",)),
)
_TESTED_BY = re.compile(r"#\s*tested-by:\s*(\S+)")


@dataclass
class Selection:
    tests: list[str]
    full_suite: bool = False
    reason: str = ""
    explain: dict[str, list[str]] = field(default_factory=dict)


def tested_by_for(root: Path, rel: str) -> str | None:
    try:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _TESTED_BY.search(text)
    return m.group(1) if m else None


def parse_changed(raw: str) -> list[str]:
    """Accept `git diff --name-only` lines and `git status --porcelain` lines alike."""
    out: set[str] = set()
    for line in raw.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if len(line) > 3 and line[2] == " " and line[:2].strip("?MADRCU! ") == "":
            line = line[3:]
        if " -> " in line:
            line = line.split(" -> ", 1)[1]
        out.add(line.strip())
    return sorted(out)


def select_tests(
    changed: list[str],
    lookup: Callable[[str], str | None],
    exists: Callable[[str], bool] | None = None,
) -> Selection:
    exists = exists or (lambda p: Path(p).exists())
    tests: set[str] = set(ALWAYS_RUN)
    explain: dict[str, list[str]] = {}
    for f in sorted(set(changed)):
        if f in FULL_SUITE_TRIGGERS or f.endswith("/conftest.py"):
            return Selection(
                ["tests/"], True, f"{f} changed: dependency/harness file, full suite", explain
            )
        if f.startswith("tests/") and f.endswith(".py"):
            tests.add(f)
            explain[f] = [f]
            continue
        matched = False
        for pattern, targets in PATH_RULES:
            if re.search(pattern, f):
                tests.update(targets)
                explain[f] = list(targets)
                matched = True
                break
        if matched:
            continue
        if f.startswith("src/caliper/") and f.endswith(".py"):
            target = lookup(f)
            if target is None:
                return Selection(
                    ["tests/"], True, f"{f}: no tested-by annotation, full suite", explain
                )
            if not exists(target):
                return Selection(
                    ["tests/"], True, f"{f}: tested-by target {target} missing, full suite", explain
                )
            tests.add(target)
            explain[f] = [target]
            continue
        explain[f] = []  # docs, config, non-test assets: guards only
    return Selection(sorted(tests), False, "", explain)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False, timeout=30
    ).stdout


def lane_batch_root(path: Path) -> Path | None:
    """Return the datum batch-root worktree that *path* lives under, if any.

    Lane worktrees are laid out as ``<run>-root/.datum/worktrees/<run>/task-NNN``;
    the ``-root`` checkout is the epic branch at batch start, so its HEAD is the
    right diff base for a lane. Detected structurally, no datum config needed.
    """
    for anc in [path, *path.parents]:
        if anc.name.endswith("-root") and (anc / ".git").exists():
            return anc
    return None


def default_base(root: Path, git=None) -> str:
    """CALIPER_TEST_BASE > lane batch-root HEAD > merge-base with main > HEAD~1."""
    git = git or (lambda *a: _git(root, *a))
    env = os.environ.get("CALIPER_TEST_BASE", "").strip()
    if env:
        return env
    batch_root = lane_batch_root(root.resolve())
    if batch_root is not None:
        head = subprocess.run(
            ["git", "-C", str(batch_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        ).stdout.strip()
        if head:
            return head
    mb = (
        git("merge-base", "HEAD", "main").strip()
        or git("merge-base", "HEAD", "origin/main").strip()
    )
    return mb or "HEAD~1"


def changed_files(root: Path, base: str | None) -> list[str]:
    if base is None:
        base = default_base(root)
    committed = _git(root, "diff", "--name-only", f"{base}...HEAD") or _git(
        root, "diff", "--name-only", base
    )
    working = _git(root, "status", "--porcelain")
    return parse_changed(committed + "\n" + working)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--base", default=None, help="Diff base revision (default: merge-base with main)"
    )
    ap.add_argument("--explain", action="store_true", help="Print the file -> tests map to stderr")
    ap.add_argument("--root", default=None)
    a = ap.parse_args(argv)
    root = (
        Path(a.root)
        if a.root
        else Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
            ).stdout.strip()
        )
    )
    changed = changed_files(root, a.base)
    sel = select_tests(
        changed, lambda f: tested_by_for(root, f), exists=lambda p: (root / p).exists()
    )
    if a.explain:
        print(f"changed files: {len(changed)}", file=sys.stderr)
        for f, t in sel.explain.items():
            print(f"  {f} -> {', '.join(t) or '(guards only)'}", file=sys.stderr)
        if sel.full_suite:
            print(f"  FULL SUITE: {sel.reason}", file=sys.stderr)
    print(" ".join(sel.tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
