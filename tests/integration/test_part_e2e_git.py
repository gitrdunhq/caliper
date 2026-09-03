"""End-to-end parting test against REAL git only, no jj (#520).

# tested-by: tests/integration/test_part_e2e_git.py

Mirrors ``tests/integration/test_part_e2e.py`` but builds a plain git repo with
no jj colocation, so ``caliper part`` must select the git-native execution
backend end to end: gate preconditions, restack.sh generation, real execution,
and rollback. Skips when jj IS on PATH and colocated in a way that would shadow
the fallback — instead this test forces the git backend by hiding jj from PATH
for the CLI invocation, so it runs the same regardless of the host's jj install.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from caliper.cli.part_cmd import part

pytestmark = pytest.mark.skipif(
    not (shutil.which("git") and shutil.which("bash")),
    reason="git-native end-to-end test requires git and bash on PATH",
)


def _run(cmd: list[str], cwd: Path, env: dict) -> str:
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"{' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout


def _no_jj_path(env: dict) -> str:
    """A PATH with every directory containing a `jj` binary removed, so probing
    for jj genuinely fails — this is what makes the fallback real rather than
    assumed."""
    dirs = [d for d in env.get("PATH", "").split(os.pathsep) if d and not (Path(d) / "jj").exists()]
    return os.pathsep.join(dirs)


@pytest.fixture()
def git_only_repo(tmp_path: Path):
    w = tmp_path / "repo"
    w.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    env["PATH"] = _no_jj_path(env)
    _run(["git", "init", "-q", "."], w, env)
    _run(["git", "config", "user.email", "t@t"], w, env)
    _run(["git", "config", "user.name", "t"], w, env)

    (w / "a.py").write_text("base\n")
    (w / "keep.py").write_text("keep\n")
    (w / "old.py").write_text("old\n")
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "base"], w, env)
    base = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    (w / "a.py").write_text("base\nmore\n")
    (w / "b.py").write_text("b\n")
    (w / "settings.yaml").write_text("k: v\n")
    _run(["git", "rm", "-q", "keep.py"], w, env)
    _run(["git", "mv", "old.py", "new.py"], w, env)
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "head"], w, env)
    head = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    return w, base, head, env


def _invoke(repo: Path, base: str, head: str, out: Path, env: dict, target: str = "stack"):
    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = env["PATH"]
    try:
        runner = CliRunner()
        return runner.invoke(
            part,
            [
                "--base",
                base,
                "--head",
                head,
                "--repo",
                str(repo),
                "--out",
                str(out),
                "--target",
                target,
            ],
            catch_exceptions=False,
        )
    finally:
        os.environ["PATH"] = old_path


def test_git_backend_selected_when_jj_absent(git_only_repo, tmp_path) -> None:
    repo, base, head, env = git_only_repo
    out = tmp_path / "o"
    result = _invoke(repo, base, head, out, env)
    assert result.exit_code == 0, result.output

    cut = json.loads((out / "cutlist.json").read_text())
    assert cut["provenance"]["backend"] == "git"
    assert cut["provenance"]["base_sha"] == base
    assert cut["provenance"]["head_sha"] == head

    script = (out / "restack.sh").read_text()
    assert script.splitlines()[0] == "#!/usr/bin/env bash"
    assert "git checkout --detach" in script
    executable_lines = [line for line in script.splitlines() if not line.lstrip().startswith("#")]
    assert not any(
        line.startswith("jj ") or " jj " in line for line in executable_lines
    ), "git-backend script must never shell out to jj"
    proc = subprocess.run(["bash", "-n", str(out / "restack.sh")], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_git_restack_reconstructs_head_then_rolls_back(git_only_repo, tmp_path) -> None:
    repo, base, head, env = git_only_repo
    out = tmp_path / "o"
    assert _invoke(repo, base, head, out, env).exit_code == 0

    starting_branch = _run(["git", "symbolic-ref", "-q", "--short", "HEAD"], repo, env).strip()
    starting_sha = _run(["git", "rev-parse", "HEAD"], repo, env).strip()
    assert starting_sha == head

    proc = subprocess.run(
        ["bash", str(out / "restack.sh")], cwd=repo, env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"

    # The reconstructed tip reproduces head exactly (empty diff).
    new_top = _run(["git", "rev-parse", "HEAD"], repo, env).strip()
    diff = subprocess.run(
        ["git", "diff", "--stat", head, new_top], cwd=repo, env=env, capture_output=True, text=True
    ).stdout.strip()
    assert diff == "", f"reconstructed tip differs from head:\n{diff}"
    branches = _run(["git", "branch"], repo, env)
    assert "caliper-part-1" in branches
    assert "caliper-part-backup-" in branches

    # The original branch was never touched — rollback is just checking it back out
    # and deleting what the script created; no reset needed.
    assert (
        _run(["git", "rev-parse", starting_branch], repo, env).strip() == starting_sha
    ), "the branch the developer started on must be untouched by the restack script"
    _run(["git", "checkout", starting_branch], repo, env)
    assert _run(["git", "rev-parse", "HEAD"], repo, env).strip() == starting_sha


def test_git_cut_list_identical_across_targets(git_only_repo, tmp_path) -> None:
    repo, base, head, env = git_only_repo
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    assert _invoke(repo, base, head, out_a, env, "stack").exit_code == 0
    assert _invoke(repo, base, head, out_b, env, "series").exit_code == 0

    cut_a = json.loads((out_a / "cutlist.json").read_text())
    cut_b = json.loads((out_b / "cutlist.json").read_text())
    assert cut_a["parts"] == cut_b["parts"]
    assert (out_a / "restack.sh").read_text() != (out_b / "restack.sh").read_text()
