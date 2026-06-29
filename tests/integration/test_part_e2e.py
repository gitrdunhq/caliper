"""End-to-end parting test against a REAL jj (skips when jj is absent).

# tested-by: tests/integration/test_part_e2e.py

Builds a colocated jj+git repo with a known ``base..head`` and drives the actual
``caliper part`` CLI. Verifies the cut list, the restack.sh (parses as shell and,
when executed against real jj, reconstructs head exactly), that the cut list is
identical under ``--target stack`` and ``--target series``, and that the run is
fully reversible via ``jj op restore``.

This covers acceptance tests 14/16/17 against a live substrate. The fake-runner
unit tests (test_part_gate, test_part_script, test_part_stock) remain the
container-runnable coverage; this one runs wherever jj is installed.
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
    not (shutil.which("jj") and shutil.which("git") and shutil.which("bash")),
    reason="real-jj end-to-end test requires jj, git and bash on PATH",
)


def _run(cmd: list[str], cwd: Path, env: dict) -> str:
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"{' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout


@pytest.fixture()
def colocated_repo(tmp_path: Path):
    w = tmp_path / "repo"
    w.mkdir()
    cfg = tmp_path / "jjconfig.toml"
    cfg.write_text('[user]\nname = "t"\nemail = "t@t"\n')
    env = {
        **os.environ,
        "JJ_CONFIG": str(cfg),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    _run(["git", "init", "-q", "."], w, env)
    _run(["git", "config", "user.email", "t@t"], w, env)
    _run(["git", "config", "user.name", "t"], w, env)

    # base commit
    (w / "a.py").write_text("base\n")
    (w / "keep.py").write_text("keep\n")
    (w / "old.py").write_text("old\n")
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "base"], w, env)
    base = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    # head commit: modify a.py, add lock + b.py + config, delete keep.py, rename old->new
    (w / "a.py").write_text("base\nmore\n")
    (w / "poetry.lock").write_text("lock\n")
    (w / "b.py").write_text("b\n")
    (w / "settings.yaml").write_text("k: v\n")
    _run(["git", "rm", "-q", "keep.py"], w, env)
    _run(["git", "mv", "old.py", "new.py"], w, env)
    _run(["git", "add", "-A"], w, env)
    _run(["git", "commit", "-qm", "head"], w, env)
    head = _run(["git", "rev-parse", "HEAD"], w, env).strip()

    # colocate jj (creates an empty clean working-copy commit on top of head)
    _run(["jj", "git", "init", "--colocate", "."], w, env)
    return w, base, head, env


def _invoke(repo: Path, base: str, head: str, out: Path, target: str = "stack"):
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


def test_caliper_part_produces_cutlist_and_valid_script(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    out = tmp_path / "stack"
    result = _invoke(repo, base, head, out, "stack")
    assert result.exit_code == 0, result.output

    cut = json.loads((out / "cutlist.json").read_text())
    by_bucket = {tuple(p["files"][0:1] or [""])[0]: p["bucket"] for p in cut["parts"]}
    # classification of the known diff
    assert by_bucket["poetry.lock"] == "generated"
    assert by_bucket["new.py"] == "move"
    assert by_bucket["settings.yaml"] == "config"
    assert by_bucket["gone.py" if False else "keep.py"] == "delete"
    # provenance stamped + revsets pinned to commit ids
    assert cut["provenance"]["base_sha"] == base
    assert cut["provenance"]["head_sha"] == head
    assert cut["provenance"]["resolved_revsets"]["head"] == head

    script = (out / "restack.sh").read_text()
    assert script.splitlines()[0] == "#!/usr/bin/env bash"
    assert "jj op restore" in script  # rollback header present
    proc = subprocess.run(["bash", "-n", str(out / "restack.sh")], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_cut_list_identical_across_targets(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    assert _invoke(repo, base, head, out_a, "stack").exit_code == 0
    assert _invoke(repo, base, head, out_b, "series").exit_code == 0

    cut_a = json.loads((out_a / "cutlist.json").read_text())
    cut_b = json.loads((out_b / "cutlist.json").read_text())
    assert cut_a["parts"] == cut_b["parts"]  # identical cut list...
    # ...but the scripts differ (bookmark strategy)
    assert (out_a / "restack.sh").read_text() != (out_b / "restack.sh").read_text()


def test_backup_bookmark_created_by_gate(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    assert _invoke(repo, base, head, tmp_path / "o", "stack").exit_code == 0
    bookmarks = _run(["jj", "bookmark", "list"], repo, env)
    assert "caliper-part-backup-" in bookmarks


def test_restack_reconstructs_head_then_rolls_back(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    out = tmp_path / "o"
    assert _invoke(repo, base, head, out, "stack").exit_code == 0

    pre_op = _run(["jj", "op", "log", "--no-graph", "--limit", "1", "-T", "id"], repo, env).strip()

    # Execute the generated restack script against real jj.
    proc = subprocess.run(
        ["bash", str(out / "restack.sh")], cwd=repo, env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"

    # The top of the reconstructed stack reproduces head exactly (empty diff).
    new_top = _run(["jj", "log", "-r", "@", "--no-graph", "-T", "commit_id"], repo, env).strip()
    diff = _run(["git", "diff", "--stat", head, new_top], repo, env).strip()
    assert diff == "", f"reconstructed stack differs from head:\n{diff}"
    # the stack was built (per-part bookmarks exist)
    assert "caliper-part-1" in _run(["jj", "bookmark", "list"], repo, env)

    # Fully reversible: restore to the pre-execution operation.
    _run(["jj", "op", "restore", pre_op], repo, env)
    assert "caliper-part-1" not in _run(["jj", "bookmark", "list"], repo, env)


def test_gate_aborts_on_stray_working_copy_file(colocated_repo, tmp_path) -> None:
    repo, base, head, env = colocated_repo
    (repo / "stray.txt").write_text("oops\n")  # untracked, non-ignored
    result = CliRunner().invoke(
        part, ["--base", base, "--head", head, "--repo", str(repo), "--out", str(tmp_path / "o")]
    )
    assert result.exit_code != 0
    # jj auto-snapshots the stray file into @, so the jj-native dirty check fires
    # first; either way it is a precondition abort with no state change.
    out = result.output.lower()
    assert "precondition failed" in out and ("dirty-tree" in out or "untracked" in out)
    assert "caliper-part-backup-" not in _run(["jj", "bookmark", "list"], repo, env)
