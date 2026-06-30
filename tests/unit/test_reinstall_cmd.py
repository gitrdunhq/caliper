"""Tests for ``caliper reinstall`` — the local rebuild+reinstall convenience.

All git/bash IO is faked through the ToolRunnerPort seam, so these run with no
real git, no uv, and no network. The repo-validation tests use real temp files
(filesystem reads only).

Property domains (DPS-12):
  Determinism   INVARIANT   same checkout state -> identical tool-call sequence
  Integrity     SAFETY      a non-caliper dir is never rebuilt (validation gate)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from caliper.cli.reinstall_cmd import (
    ReinstallError,
    reinstall,
    validate_caliper_repo,
)
from caliper.core.tool_runner import ToolInvocation, ToolResult


@dataclass
class FakeRunner:
    """Canned git/bash responses; records every invocation for assertions."""

    toplevel: str
    git_ok: bool = True
    install_ok: bool = True
    install_stdout: str = ">> installed caliper 0.2.26+dev.20260630T130800.gabc1234"
    calls: list[list[str]] = field(default_factory=list)

    def run(self, invocation: ToolInvocation) -> ToolResult:
        self.calls.append(invocation.cmd)
        cmd = invocation.cmd
        if cmd[0] == "git" and "rev-parse" in cmd:
            if not self.git_ok:
                return ToolResult(exit_code=128, stdout="", stderr="not a git repository")
            return ToolResult(exit_code=0, stdout=self.toplevel + "\n", stderr="")
        if cmd[0] == "bash":
            if not self.install_ok:
                return ToolResult(exit_code=1, stdout="", stderr="uv tool install failed")
            return ToolResult(exit_code=0, stdout=self.install_stdout, stderr="")
        return ToolResult(exit_code=0, stdout="", stderr="")


def _make_repo(root: Path, *, name: str = "caliper", with_script: bool = True) -> Path:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "0.2.26"\n', encoding="utf-8"
    )
    if with_script:
        scripts = root / "scripts"
        scripts.mkdir(exist_ok=True)
        (scripts / "install-local.sh").write_text("#!/usr/bin/env bash\necho installed\n")
    return root


class TestReinstall:
    def test_resolves_root_validates_and_runs_script(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = FakeRunner(toplevel=str(repo))
        out = reinstall(None, runner=runner, cwd=repo)
        assert "installed caliper 0.2.26+dev" in out
        # resolved the root via git, then ran the install script from that root
        assert any(c[0] == "git" and "--show-toplevel" in c for c in runner.calls)
        assert any(
            c[0] == "bash" and c[1].endswith("scripts/install-local.sh") for c in runner.calls
        )

    def test_repo_override_skips_git_resolution(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = FakeRunner(toplevel="/wrong/path")
        reinstall(str(repo), runner=runner, cwd=Path("/elsewhere"))
        assert not any(c[0] == "git" for c in runner.calls)  # --repo given, no git lookup
        assert any(c[0] == "bash" for c in runner.calls)

    def test_rejects_non_caliper_pyproject(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, name="not-caliper")
        runner = FakeRunner(toplevel=str(repo))
        with pytest.raises(ReinstallError, match="not the caliper project"):
            reinstall(str(repo), runner=runner)
        assert not any(c[0] == "bash" for c in runner.calls)  # never rebuilt

    def test_rejects_missing_pyproject(self, tmp_path: Path) -> None:
        runner = FakeRunner(toplevel=str(tmp_path))
        with pytest.raises(ReinstallError, match="no pyproject.toml"):
            reinstall(str(tmp_path), runner=runner)

    def test_rejects_missing_install_script(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, with_script=False)
        runner = FakeRunner(toplevel=str(repo))
        with pytest.raises(ReinstallError, match="install-local.sh"):
            reinstall(str(repo), runner=runner)

    def test_git_resolution_failure_raises(self, tmp_path: Path) -> None:
        runner = FakeRunner(toplevel=str(tmp_path), git_ok=False)
        with pytest.raises(ReinstallError, match="find the repo root"):
            reinstall(None, runner=runner, cwd=tmp_path)

    def test_install_script_failure_raises(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = FakeRunner(toplevel=str(repo), install_ok=False)
        with pytest.raises(ReinstallError, match="reinstall caliper"):
            reinstall(str(repo), runner=runner)


class TestValidateCaliperRepo:
    def test_returns_script_path_for_valid_repo(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        assert validate_caliper_repo(repo) == repo / "scripts" / "install-local.sh"

    def test_raises_outside_a_checkout(self, tmp_path: Path) -> None:
        with pytest.raises(ReinstallError):
            validate_caliper_repo(tmp_path)


class TestPyprojectValidation:
    """Validation parses TOML, not substrings — quoting/spacing must not fool it,
    and a `name` in some *other* table must never pass the caliper gate."""

    def test_accepts_single_quoted_name(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            "[project]\nname = 'caliper'\nversion = '0.2.26'\n", encoding="utf-8"
        )
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "install-local.sh").write_text("#!/usr/bin/env bash\n")
        assert validate_caliper_repo(tmp_path).name == "install-local.sh"

    def test_accepts_extra_spacing(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname   =    "caliper"\nversion = "0.2.26"\n', encoding="utf-8"
        )
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "install-local.sh").write_text("#!/usr/bin/env bash\n")
        assert validate_caliper_repo(tmp_path).name == "install-local.sh"

    def test_rejects_caliper_name_only_in_other_table(self, tmp_path: Path) -> None:
        # The substring check would falsely pass here; tomllib reads project.name.
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "not-caliper"\nversion = "1.0"\n' '[tool.foo]\nname = "caliper"\n',
            encoding="utf-8",
        )
        with pytest.raises(ReinstallError, match="not the caliper project"):
            validate_caliper_repo(tmp_path)

    def test_rejects_unparseable_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("this = = not toml\n", encoding="utf-8")
        with pytest.raises(ReinstallError):
            validate_caliper_repo(tmp_path)


class TestProperties:
    def test_determinism(self, tmp_path: Path) -> None:
        # INVARIANT: same checkout + same args -> identical tool-call sequence.
        repo = _make_repo(tmp_path)
        r1 = FakeRunner(toplevel=str(repo))
        r2 = FakeRunner(toplevel=str(repo))
        reinstall(None, runner=r1, cwd=repo)
        reinstall(None, runner=r2, cwd=repo)
        assert r1.calls == r2.calls
