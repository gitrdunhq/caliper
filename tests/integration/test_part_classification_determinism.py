"""Classification determinism across hostile git config (acceptance test 15).

# tested-by: tests/integration/test_part_classification_determinism.py

The stock producer pins every git flag (rename/copy thresholds, rename limit,
ignorecase off) so classification can never depend on ambient git config. This
test runs the producer against the same ``base..head`` twice — once under hostile
ambient config (`diff.renames=false`, `core.ignorecase=true`, a tiny
`diff.renameLimit`), once clean — and asserts the produced Records and the
resulting CutList are byte-identical, proving the pinned flags win.

Needs git (not jj): the producer is pure git.

Property domains (DPS-12):
  Determinism INVARIANT  pinned flags -> records independent of ambient config
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from caliper.core.models import ChangeType
from caliper.core.part_stock import build_stock
from caliper.core.parting import part
from caliper.core.repo_config import PartingConfig

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="requires git on PATH")

_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def _git(args: list[str], cwd: Path) -> None:
    import os

    proc = subprocess.run(
        ["git", *args], cwd=cwd, env={**os.environ, **_ENV}, capture_output=True, text=True
    )
    assert proc.returncode == 0, f"git {' '.join(args)}\n{proc.stderr}"


def _rev(args: list[str], cwd: Path) -> str:
    import os

    return subprocess.run(
        ["git", *args], cwd=cwd, env={**os.environ, **_ENV}, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture()
def repo_with_rename(tmp_path: Path):
    w = tmp_path / "repo"
    w.mkdir()
    _git(["init", "-q", "."], w)
    # base: a renamable file + a logic file + a lockfile
    (w / "module.py").write_text("def f():\n    return 1\n")
    (w / "app.py").write_text("x = 1\n")
    (w / "poetry.lock").write_text("lock\n")
    _git(["add", "-A"], w)
    _git(["commit", "-qm", "base"], w)
    base = _rev(["rev-parse", "HEAD"], w)
    # head: pure rename module.py->renamed.py, modify app.py, modify lockfile
    _git(["mv", "module.py", "renamed.py"], w)
    (w / "app.py").write_text("x = 1\ny = 2\n")
    (w / "poetry.lock").write_text("lock\nlock2\n")
    _git(["add", "-A"], w)
    _git(["commit", "-qm", "head"], w)
    head = _rev(["rev-parse", "HEAD"], w)
    return w, base, head


def test_classification_deterministic_across_hostile_git_config(repo_with_rename) -> None:
    repo, base, head = repo_with_rename
    cfg = PartingConfig()

    # Hostile ambient config that, unpinned, would change classification:
    # diff.renames=false would turn the rename into add+delete (2 records, wrong
    # buckets); a tiny renameLimit would suppress rename detection; ignorecase
    # flips path handling.
    for key, val in [
        ("diff.renames", "false"),
        ("core.ignorecase", "true"),
        ("diff.renameLimit", "1"),
    ]:
        _git(["config", key, val], repo)
    stock_hostile = build_stock(repo, base, head, cfg)
    cut_hostile = part(stock_hostile.records, cfg)

    # Clean config.
    for key in ["diff.renames", "core.ignorecase", "diff.renameLimit"]:
        subprocess.run(["git", "-C", str(repo), "config", "--unset", key], capture_output=True)
    stock_clean = build_stock(repo, base, head, cfg)
    cut_clean = part(stock_clean.records, cfg)

    # Records and cut list are identical regardless of ambient config.
    assert [r.model_dump() for r in stock_hostile.records] == [
        r.model_dump() for r in stock_clean.records
    ]
    assert cut_hostile.model_dump() == cut_clean.model_dump()

    # And the rename was detected as a single move despite diff.renames=false,
    # proving --find-renames on the command line overrode the ambient setting.
    moves = [r for r in stock_hostile.records if r.change_type == ChangeType.move]
    assert [m.file for m in moves] == ["renamed.py"]
    assert "module.py" not in [r.file for r in stock_hostile.records]
