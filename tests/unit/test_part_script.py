"""Tests for the restack.sh emitter — ``core.part_script``.

# tested-by: tests/unit/test_part_script.py

Renders are pure; the scripts must parse as valid shell (``bash -n``). Covers the
rollback header, the capability header, stack vs series bookmark strategy, the
per-peel validate command, rename old-path restoration, and the manual fallback.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from caliper.core.models import ChangeType, PartTarget, Record
from caliper.core.part_script import (
    probe_path_capability,
    render_restack_script,
    rollback_header,
)
from caliper.core.parting import part
from caliper.core.repo_config import PartingConfig
from caliper.core.tool_runner import ToolInvocation, ToolResult


def _cutlist():
    records = [
        Record(file="poetry.lock", change_type=ChangeType.generated, size=10),
        Record(file="a.py", change_type=ChangeType.logic, size=100),
        Record(file="b.py", change_type=ChangeType.logic, size=100),
        Record(file="new.py", change_type=ChangeType.move, size=0, old_path="old.py"),
        Record(file="gone.py", change_type=ChangeType.delete, size=5),
    ]
    return part(records, PartingConfig(size_cap=400))


def _render(target: PartTarget, *, can: bool = True, validate: str = "") -> str:
    return render_restack_script(
        _cutlist(),
        base_rev="baseid",
        head_rev="headid",
        old_paths={"new.py": "old.py"},
        backup_bookmark="caliper-part-backup-TS",
        rescue_op_id="op-rescue-1",
        jj_version="jj 0.99.0",
        target=target,
        validate_command=validate,
        can_reconstruct=can,
    )


def _assert_bash_parses(script: str, tmp_path) -> None:
    bash = shutil.which("bash")
    if not bash:  # pragma: no cover
        pytest.skip("bash not available")
    f = tmp_path / "restack.sh"
    f.write_text(script)
    proc = subprocess.run([bash, "-n", str(f)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_rollback_header_at_top() -> None:
    head = _render(PartTarget.stack).splitlines()
    assert head[0] == "#!/usr/bin/env bash"
    joined = "\n".join(head[:12])
    assert "ROLLBACK" in joined
    assert "caliper-part-backup-TS" in joined
    assert "jj op restore op-rescue-1" in joined


def test_capability_header_states_availability() -> None:
    assert "reconstruction available: yes" in _render(PartTarget.stack, can=True)
    assert "reconstruction available: no" in _render(PartTarget.stack, can=False)


def test_reconstructs_on_base_with_restore_from_head(tmp_path) -> None:
    script = _render(PartTarget.stack)
    _assert_bash_parses(script, tmp_path)
    assert "jj new baseid -m 'caliper part: reconstruct stock on base'" in script
    assert "jj restore --from headid" in script


def test_rename_old_path_is_restored(tmp_path) -> None:
    script = _render(PartTarget.stack)
    _assert_bash_parses(script, tmp_path)
    # the move part restores BOTH new and old path so the old path is removed
    line = next(ln for ln in script.splitlines() if "new.py" in ln and "jj restore" in ln)
    assert "old.py" in line


def test_stack_target_bookmarks_each_part(tmp_path) -> None:
    script = _render(PartTarget.stack)
    _assert_bash_parses(script, tmp_path)
    assert "jj bookmark create caliper-part-1 -r @" in script
    assert "jj bookmark create caliper-part-2 -r @" in script
    assert "caliper-part-series" not in script


def test_series_target_single_tip_bookmark(tmp_path) -> None:
    script = _render(PartTarget.series)
    _assert_bash_parses(script, tmp_path)
    assert "jj bookmark create caliper-part-series -r @" in script
    assert "jj bookmark create caliper-part-1 -r @" not in script


def test_validate_command_runs_per_peel(tmp_path) -> None:
    script = _render(PartTarget.stack, validate="make test")
    _assert_bash_parses(script, tmp_path)
    assert script.count("if ! ( make test ); then") == len(_cutlist().parts)


def test_no_validate_block_when_unset() -> None:
    assert "if ! (" not in _render(PartTarget.stack, validate="")


def test_manual_steps_when_no_reconstruct(tmp_path) -> None:
    script = _render(PartTarget.stack, can=False)
    _assert_bash_parses(script, tmp_path)
    assert "cannot reconstruct by path non-interactively" in script
    assert "jj restore --from" not in script
    assert "poetry.lock" in script and "a.py" in script and "gone.py" in script


def test_script_never_pushes_or_force_pushes() -> None:
    for target in (PartTarget.stack, PartTarget.series):
        for line in _render(target).splitlines():
            if "push" in line:
                assert line.lstrip().startswith("#"), line


def test_delete_part_flagged_in_script() -> None:
    assert "DELETE: review for cross-part deletion safety" in _render(PartTarget.stack)


def test_rollback_header_helper() -> None:
    lines = rollback_header("bk", "op1")
    assert any("bk" in line for line in lines)
    assert any("jj op restore op1" in line for line in lines)


def test_probe_path_capability_detects_filesets() -> None:
    class HelpRunner:
        def run(self, invocation: ToolInvocation) -> ToolResult:
            if "--version" in invocation.cmd:
                return ToolResult(exit_code=0, stdout="jj 0.99.0\n", stderr="")
            return ToolResult(
                exit_code=0, stdout="Usage: jj restore [OPTIONS] [FILESETS]...\n", stderr=""
            )

    can, version = probe_path_capability("/repo", HelpRunner())
    assert can is True
    assert version == "jj 0.99.0"


def test_probe_path_capability_false_when_jj_absent() -> None:
    class MissingRunner:
        def run(self, invocation: ToolInvocation) -> ToolResult:
            return ToolResult(exit_code=127, stdout="", stderr="", not_installed=True)

    can, version = probe_path_capability("/repo", MissingRunner())
    assert can is False
    assert version == ""
