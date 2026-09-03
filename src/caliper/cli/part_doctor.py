"""``caliper part --doctor`` — environment diagnostics (#526).

# tested-by: tests/unit/test_part_doctor.py

A reviewer new to ``caliper part`` hits confusing failures when a dependency
is missing (jj, git, gh, mkcert) or the state workdir isn't writable — this
gives them one command that checks everything up front instead of a cryptic
error mid-run. Read-only: never mutates state, never gates a build (this is a
developer aid, not a scanner). Reuses ``core.part_gate.detect_backend`` for
the jj-vs-git probe so the doctor's answer never drifts from the real gate's.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from caliper.cli.part_pr import default_part_workdir
from caliper.core.part_gate import PartingGateError, detect_backend
from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort


@dataclass(frozen=True)
class DoctorCheck:
    """One diagnostic result: what was checked, whether it passed, and why."""

    name: str
    ok: bool
    detail: str


def _probe(runner: ToolRunnerPort, cwd: str, cmd: list[str]) -> tuple[bool, str]:
    """Run *cmd*; never raises — a missing tool is a failed check, not a crash."""
    result = runner.run(ToolInvocation(cmd=cmd, cwd=cwd, timeout=10))
    if result.not_installed:
        return False, "not found on PATH"
    if result.exit_code != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        return False, detail[0] if detail else f"exit {result.exit_code}"
    out = result.stdout.strip().splitlines()
    return True, out[0] if out else "found"


def run_doctor(
    repo_path: Path,
    *,
    check_lan: bool = False,
    runner: ToolRunnerPort | None = None,
) -> list[DoctorCheck]:
    """Run every diagnostic and return the results in a fixed, stable order."""
    runner = runner or SubprocessToolRunner()
    cwd = str(repo_path)
    checks: list[DoctorCheck] = []

    ok, detail = _probe(runner, cwd, ["jj", "--version"])
    checks.append(DoctorCheck("jj", ok, detail))

    ok, detail = _probe(runner, cwd, ["git", "--version"])
    checks.append(DoctorCheck("git", ok, detail))

    try:
        backend = detect_backend(runner, repo_path)
        checks.append(DoctorCheck("execution backend", True, backend))
    except PartingGateError as exc:
        checks.append(DoctorCheck("execution backend", False, str(exc)))

    gh_ok, gh_detail = _probe(runner, cwd, ["gh", "auth", "status"])
    checks.append(DoctorCheck("gh auth (for --pr)", gh_ok, gh_detail))

    workdir = default_part_workdir()
    try:
        workdir.mkdir(parents=True, exist_ok=True)
        writable = os.access(workdir, os.W_OK)
        detail = str(workdir) if writable else f"{workdir} is not writable"
    except OSError as exc:
        writable, detail = False, f"{workdir}: {exc}"
    checks.append(DoctorCheck("state workdir (for --pr)", writable, detail))

    if check_lan:
        ok, detail = _probe(runner, cwd, ["mkcert", "-version"])
        checks.append(DoctorCheck("mkcert (for --serve --lan)", ok, detail))

    return checks


def render_doctor_report(checks: list[DoctorCheck]) -> str:
    """Human-readable report: one line per check, PASS/FAIL, then a summary."""
    lines = ["caliper part --doctor", ""]
    for c in checks:
        status = "PASS" if c.ok else "FAIL"
        lines.append(f"  [{status}] {c.name}: {c.detail}")
    failed = [c for c in checks if not c.ok]
    lines.append("")
    lines.append(
        f"{len(checks) - len(failed)}/{len(checks)} checks passed"
        + (f" — {len(failed)} failed" if failed else "")
    )
    return "\n".join(lines) + "\n"
