"""Tests for ``caliper part --doctor`` — core.cli.part_doctor.run_doctor.

# tested-by: tests/unit/test_part_doctor.py

A fake ``ToolRunnerPort`` stands in for jj/git/gh/mkcert so every check is
covered with no real tools installed. Read-only: never mutates state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.cli.part_doctor import DoctorCheck, render_doctor_report, run_doctor
from caliper.core.tool_runner import ToolInvocation, ToolResult


@pytest.fixture(autouse=True)
def _isolated_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The workdir check touches the real filesystem (mkdir, exist_ok=True) —
    point it at a throwaway path so tests never write under the real
    $XDG_CONFIG_HOME/caliper (mirrors tests/unit/test_part_pr.py)."""
    monkeypatch.setenv("CALIPER_STATE_DIR", str(tmp_path / "state"))


class FakeTools:
    """Configurable canned responses for jj/git/gh/mkcert; records every call."""

    def __init__(
        self,
        *,
        jj_missing: bool = False,
        git_missing: bool = False,
        gh_missing: bool = False,
        gh_unauthenticated: bool = False,
        mkcert_missing: bool = False,
    ) -> None:
        self.jj_missing = jj_missing
        self.git_missing = git_missing
        self.gh_missing = gh_missing
        self.gh_unauthenticated = gh_unauthenticated
        self.mkcert_missing = mkcert_missing
        self.calls: list[list[str]] = []

    def run(self, invocation: ToolInvocation) -> ToolResult:
        cmd = invocation.cmd
        self.calls.append(cmd)

        def ok(out: str = "") -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        def missing() -> ToolResult:
            return ToolResult(exit_code=127, stdout="", stderr="", not_installed=True)

        if cmd[0] == "jj":
            if self.jj_missing:
                return missing()
            if cmd[1:] == ["--version"]:
                return ok("jj 0.99.0\n")
            if cmd[1:] == ["root"]:
                return ok("/repo\n")
            return ok()
        if cmd[0] == "gh":
            if self.gh_missing:
                return missing()
            if self.gh_unauthenticated:
                return ToolResult(
                    exit_code=1, stdout="", stderr="You are not logged into any hosts"
                )
            return ok("Logged in to github.com\n")
        if cmd[0] == "mkcert":
            if self.mkcert_missing:
                return missing()
            return ok("v1.4.4\n")
        if cmd[0] == "git" or cmd[1:2] == ["-c"]:
            if self.git_missing:
                return missing()
            if "--git-dir" in cmd:
                return ok(".git\n")
            if "--version" in cmd:
                return ok("git version 2.43.0\n")
            return ok()
        return ok()


def test_all_tools_present_all_checks_pass(tmp_path: Path) -> None:
    checks = run_doctor(tmp_path, runner=FakeTools())
    assert all(c.ok for c in checks)
    names = {c.name for c in checks}
    assert "jj" in names
    assert "git" in names
    assert "execution backend" in names
    assert "gh auth (for --pr)" in names
    assert "state workdir (for --pr)" in names
    assert "mkcert (for --serve --lan)" not in names  # only when check_lan=True


def test_jj_missing_falls_back_to_git_backend_still_passes(tmp_path: Path) -> None:
    checks = run_doctor(tmp_path, runner=FakeTools(jj_missing=True))
    by_name = {c.name: c for c in checks}
    assert by_name["jj"].ok is False
    assert by_name["execution backend"].ok is True
    assert by_name["execution backend"].detail == "git"


def test_both_jj_and_git_missing_fails_backend_check(tmp_path: Path) -> None:
    checks = run_doctor(tmp_path, runner=FakeTools(jj_missing=True, git_missing=True))
    by_name = {c.name: c for c in checks}
    assert by_name["execution backend"].ok is False


def test_gh_unauthenticated_fails_that_check_only(tmp_path: Path) -> None:
    checks = run_doctor(tmp_path, runner=FakeTools(gh_unauthenticated=True))
    by_name = {c.name: c for c in checks}
    assert by_name["gh auth (for --pr)"].ok is False
    assert by_name["jj"].ok is True  # unrelated checks unaffected


def test_gh_missing_fails_that_check(tmp_path: Path) -> None:
    checks = run_doctor(tmp_path, runner=FakeTools(gh_missing=True))
    by_name = {c.name: c for c in checks}
    assert by_name["gh auth (for --pr)"].ok is False
    assert by_name["gh auth (for --pr)"].detail == "not found on PATH"


def test_mkcert_only_checked_when_check_lan_true(tmp_path: Path) -> None:
    without = run_doctor(tmp_path, runner=FakeTools())
    with_lan = run_doctor(tmp_path, check_lan=True, runner=FakeTools())
    assert not any(c.name.startswith("mkcert") for c in without)
    assert any(c.name.startswith("mkcert") for c in with_lan)


def test_mkcert_missing_fails_when_checked(tmp_path: Path) -> None:
    checks = run_doctor(tmp_path, check_lan=True, runner=FakeTools(mkcert_missing=True))
    by_name = {c.name: c for c in checks}
    assert by_name["mkcert (for --serve --lan)"].ok is False


def test_render_doctor_report_summarizes_pass_fail() -> None:
    checks = [
        DoctorCheck("jj", True, "jj 0.99.0"),
        DoctorCheck("git", True, "git version 2.43.0"),
        DoctorCheck("gh auth (for --pr)", False, "not found on PATH"),
    ]
    report = render_doctor_report(checks)
    assert "[PASS] jj: jj 0.99.0" in report
    assert "[FAIL] gh auth (for --pr): not found on PATH" in report
    assert "2/3 checks passed" in report
    assert "1 failed" in report


def test_render_doctor_report_all_pass_no_failed_suffix() -> None:
    checks = [DoctorCheck("jj", True, "jj 0.99.0")]
    report = render_doctor_report(checks)
    assert "1/1 checks passed" in report
    assert "failed" not in report
