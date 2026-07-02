# tested-by: tests/unit/test_file_source.py
"""Tests for the file-source port + adapters (git ls-files vs. filesystem walk).

A single ``FileSourcePort`` enumerates the files caliper should scan under a
root. Two adapters back it: ``WalkFileSource`` (os.walk + caliper ignore rules)
and ``GitLsFilesSource`` (``git ls-files --cached --others --exclude-standard``,
which respects ``.gitignore`` for free while still catching new working-tree
files). ``select_file_source`` picks git when the root is a usable git repo and
falls back to walk otherwise, with an ``CALIPER_FILE_SOURCE`` override.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.file_source import (
    GitLsFilesSource,
    WalkFileSource,
    select_file_source,
)
from caliper.core.ports import FileSourcePort
from caliper.core.registries import FILE_SOURCES
from tests.unit._strategies import path_segment

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _init_git_repo(root: Path) -> None:
    """Initialise a minimal git repo at *root* (deterministic identity)."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)


def _commit_all(root: Path, message: str = "init") -> None:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=root, check=True)


def _write(path: Path, content: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# Protocol conformance + registry
# ---------------------------------------------------------------------------


class TestConformance:
    def test_walk_source_satisfies_port(self):
        assert isinstance(WalkFileSource(), FileSourcePort)

    def test_git_source_satisfies_port(self):
        assert isinstance(GitLsFilesSource(), FileSourcePort)

    def test_sources_registered_under_stable_keys(self):
        assert "walk" in FILE_SOURCES
        assert "git" in FILE_SOURCES
        assert FILE_SOURCES.create("walk").name == "walk"
        assert FILE_SOURCES.create("git").name == "git"


# ---------------------------------------------------------------------------
# WalkFileSource
# ---------------------------------------------------------------------------


class TestWalkFileSource:
    def test_lists_plain_files(self, tmp_path: Path):
        _write(tmp_path / "a.py")
        _write(tmp_path / "pkg" / "b.py")
        src = WalkFileSource()
        out = src.list_files(tmp_path)
        names = {p.name for p in out}
        assert {"a.py", "b.py"} <= names

    def test_excludes_default_ignored_dirs(self, tmp_path: Path):
        _write(tmp_path / "real.py")
        _write(tmp_path / ".venv" / "junk.py")
        _write(tmp_path / "node_modules" / "dep.js")
        _write(tmp_path / "__pycache__" / "c.pyc")
        out = WalkFileSource().list_files(tmp_path)
        rels = {p.relative_to(tmp_path).as_posix() for p in out}
        assert "real.py" in rels
        assert not any(r.startswith((".venv/", "node_modules/", "__pycache__/")) for r in rels)

    def test_respects_caliperignore(self, tmp_path: Path):
        _write(tmp_path / ".caliperignore", "secrets/\n")
        _write(tmp_path / "keep.py")
        _write(tmp_path / "secrets" / "leak.py")
        out = WalkFileSource().list_files(tmp_path)
        rels = {p.relative_to(tmp_path).as_posix() for p in out}
        assert "keep.py" in rels
        assert "secrets/leak.py" not in rels

    def test_suffixes_filter(self, tmp_path: Path):
        _write(tmp_path / "a.py")
        _write(tmp_path / "b.js")
        _write(tmp_path / "c.txt")
        out = WalkFileSource().list_files(tmp_path, suffixes=(".py", ".js"))
        suffixes = {p.suffix for p in out}
        assert suffixes <= {".py", ".js"}
        assert ".txt" not in suffixes

    def test_returns_sorted_paths(self, tmp_path: Path):
        for n in ("z.py", "a.py", "m.py"):
            _write(tmp_path / n)
        out = WalkFileSource().list_files(tmp_path, suffixes=(".py",))
        assert out == sorted(out)

    def test_is_available_always_true(self, tmp_path: Path):
        assert WalkFileSource().is_available(tmp_path) is True


# ---------------------------------------------------------------------------
# GitLsFilesSource
# ---------------------------------------------------------------------------


class TestGitLsFilesSource:
    def test_lists_tracked_files(self, tmp_path: Path):
        _init_git_repo(tmp_path)
        _write(tmp_path / "tracked.py")
        _commit_all(tmp_path)
        out = GitLsFilesSource().list_files(tmp_path)
        rels = {p.relative_to(tmp_path).as_posix() for p in out}
        assert "tracked.py" in rels

    def test_includes_untracked_but_not_ignored(self, tmp_path: Path):
        _init_git_repo(tmp_path)
        _write(tmp_path / "tracked.py")
        _commit_all(tmp_path)
        _write(tmp_path / "new_unstaged.py")  # never git-added
        out = GitLsFilesSource().list_files(tmp_path)
        rels = {p.relative_to(tmp_path).as_posix() for p in out}
        assert "new_unstaged.py" in rels

    def test_excludes_gitignored_files(self, tmp_path: Path):
        _init_git_repo(tmp_path)
        _write(tmp_path / ".gitignore", "build/\n*.log\n")
        _write(tmp_path / "keep.py")
        _write(tmp_path / "build" / "out.py")
        _write(tmp_path / "debug.log")
        _commit_all(tmp_path)
        out = GitLsFilesSource().list_files(tmp_path)
        rels = {p.relative_to(tmp_path).as_posix() for p in out}
        assert "keep.py" in rels
        assert "build/out.py" not in rels
        assert "debug.log" not in rels

    def test_applies_caliper_exclusions_on_top(self, tmp_path: Path):
        # A tracked file that .gitignore allows but caliper must still skip
        # (mirrors tests/e2e/fixtures — tracked but never caliper's own deps).
        _init_git_repo(tmp_path)
        _write(tmp_path / ".caliperignore", "fixtures/\n")
        _write(tmp_path / "scan_me.py")
        _write(tmp_path / "fixtures" / "pinned.py")
        _commit_all(tmp_path)
        out = GitLsFilesSource().list_files(tmp_path)
        rels = {p.relative_to(tmp_path).as_posix() for p in out}
        assert "scan_me.py" in rels
        assert "fixtures/pinned.py" not in rels

    def test_suffixes_filter(self, tmp_path: Path):
        _init_git_repo(tmp_path)
        _write(tmp_path / "a.py")
        _write(tmp_path / "b.js")
        _write(tmp_path / "c.txt")
        _commit_all(tmp_path)
        out = GitLsFilesSource().list_files(tmp_path, suffixes=(".py",))
        assert {p.suffix for p in out} == {".py"}

    def test_returns_sorted_paths(self, tmp_path: Path):
        _init_git_repo(tmp_path)
        for n in ("z.py", "a.py", "m.py"):
            _write(tmp_path / n)
        _commit_all(tmp_path)
        out = GitLsFilesSource().list_files(tmp_path, suffixes=(".py",))
        assert out == sorted(out)

    def test_is_available_true_in_git_repo(self, tmp_path: Path):
        _init_git_repo(tmp_path)
        assert GitLsFilesSource().is_available(tmp_path) is True

    def test_is_available_false_outside_git(self, tmp_path: Path):
        assert GitLsFilesSource().is_available(tmp_path) is False

    def test_list_files_fail_open_outside_git(self, tmp_path: Path):
        # Not a repo: must not raise; returns an empty list (caller falls back).
        assert GitLsFilesSource().list_files(tmp_path) == []

    def test_excludes_symlink_escaping_root(self, tmp_path: Path):
        # A tracked symlink whose target resolves outside the repo root must
        # never reach a scanner (opengrep aborts its whole run on one such
        # path) — mirrors the escape guard WalkFileSource already has.
        outside = tmp_path.parent / "outside_target.json"
        _write(outside, "{}")
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)
        _write(repo / "keep.py")
        (repo / "escape.json").symlink_to(outside)
        _commit_all(repo)
        out = GitLsFilesSource().list_files(repo)
        rels = {p.relative_to(repo).as_posix() for p in out}
        assert "keep.py" in rels
        assert "escape.json" not in rels


# ---------------------------------------------------------------------------
# select_file_source
# ---------------------------------------------------------------------------


class TestSelectFileSource:
    def test_auto_picks_git_in_repo(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("CALIPER_FILE_SOURCE", raising=False)
        _init_git_repo(tmp_path)
        assert select_file_source(tmp_path).name == "git"

    def test_auto_falls_back_to_walk_outside_repo(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("CALIPER_FILE_SOURCE", raising=False)
        assert select_file_source(tmp_path).name == "walk"

    def test_prefer_walk_forces_walk_in_repo(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("CALIPER_FILE_SOURCE", raising=False)
        _init_git_repo(tmp_path)
        assert select_file_source(tmp_path, prefer="walk").name == "walk"

    def test_prefer_git_forces_git(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("CALIPER_FILE_SOURCE", raising=False)
        _init_git_repo(tmp_path)
        assert select_file_source(tmp_path, prefer="git").name == "git"

    def test_env_override_walk(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CALIPER_FILE_SOURCE", "walk")
        _init_git_repo(tmp_path)
        assert select_file_source(tmp_path).name == "walk"


# ---------------------------------------------------------------------------
# Properties (DPS-12)
# ---------------------------------------------------------------------------


class TestProperties:
    """Determinism INVARIANT: same tree -> same file list, every time."""

    def test_walk_is_deterministic(self, tmp_path: Path):
        for n in ("a.py", "sub/b.py", "sub/c.py"):
            _write(tmp_path / n)
        src = WalkFileSource()
        first = src.list_files(tmp_path, suffixes=(".py",))
        second = src.list_files(tmp_path, suffixes=(".py",))
        assert first == second

    def test_git_is_deterministic(self, tmp_path: Path):
        _init_git_repo(tmp_path)
        for n in ("a.py", "sub/b.py", "sub/c.py"):
            _write(tmp_path / n)
        _commit_all(tmp_path)
        src = GitLsFilesSource()
        first = src.list_files(tmp_path, suffixes=(".py",))
        second = src.list_files(tmp_path, suffixes=(".py",))
        assert first == second


class TestContainmentProperty:
    """Isolation INVARIANT: no adapter ever returns a path outside root.

    Regresses the gap where GitLsFilesSource lacked WalkFileSource's
    escape-via-symlink guard: opengrep aborts its *entire* scan on one such
    path in the target list (see semgrep_runner.py's ``_abort_detail``
    docstring), so a single escaping symlink silently blinds a whole scanner.
    A property test fuzzing filenames/depths catches this class of bug across
    both adapters at once, where example-based tests only cover one adapter
    at a time.
    """

    @given(
        keep_names=st.lists(path_segment(max_size=8), min_size=1, max_size=3, unique=True),
        escape_name=path_segment(max_size=8),
    )
    @settings(max_examples=15, deadline=None)
    def test_no_source_returns_a_path_outside_root(
        self, keep_names: list[str], escape_name: str
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as outside_dir,
            tempfile.TemporaryDirectory() as repo_dir,
        ):
            outside_target = Path(outside_dir) / "escape_target.json"
            _write(outside_target, "{}")

            repo = Path(repo_dir)
            _init_git_repo(repo)
            for name in keep_names:
                _write(repo / f"{name}.py")
            (repo / f"{escape_name}.json").symlink_to(outside_target)
            _commit_all(repo)

            root_resolved = repo.resolve()
            for source in (WalkFileSource(), GitLsFilesSource()):
                for path in source.list_files(repo):
                    # Raises ValueError if path escapes root — that's the bug.
                    path.resolve().relative_to(root_resolved)
