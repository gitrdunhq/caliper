"""Shared parting orchestrator — gate -> cut -> suggest -> describe -> script.

# tested-by: tests/unit/test_part_pipeline.py

Both presentation-tier entry points for ``part`` (`cli/part_cmd.py`'s CLI and
`cli/part_serve.py`'s web sidecar) need the exact same sequence: run the safety
gate, cut the stock, offer (and optionally apply) tier suggestions, probe jj's
non-interactive path-restore capability, describe each part's commit subject,
and render the restack script. This module defines that sequence once so
neither shell can drift from the other.

Lives in ``cli/`` (presentation tier), not ``core/`` — it composes the parting
plugin and other presentation-tier helpers (``write_override``,
``suggest_overrides``, ``describe_parts``), which the core tier is not allowed
to import (see ``tests/unit/test_deterministic_architecture_guards.py``).
"""

from __future__ import annotations

from pathlib import Path

import orjson
from pydantic import BaseModel, ConfigDict

from caliper.cli.part_describe import describe_parts
from caliper.cli.part_serve import write_override
from caliper.cli.part_suggest import suggest_overrides
from caliper.core.commit_describer import CommitDescriberPort, NullDescriber
from caliper.core.models import CutList
from caliper.core.part_gate import run_gate
from caliper.core.part_script import probe_path_capability, render_restack_script
from caliper.core.registries import PARTING
from caliper.core.repo_config import OverrideRule, PartingConfig
from caliper.core.tier_suggester import NullSuggester, TierSuggesterPort
from caliper.core.tool_runner import ToolRunnerPort
from caliper.plugins import _parting  # noqa: F401  registration side effect: "parting" -> PARTING

_MODEL_CONFIG = ConfigDict(populate_by_name=True, use_enum_values=False)


class PartRunResult(BaseModel):
    """Everything one `run_part` invocation produced — cut, script, provenance."""

    model_config = _MODEL_CONFIG

    cutlist: CutList
    script_text: str
    backup_bookmark: str
    rescue_op_id: str
    jj_version: str
    can_reconstruct: bool
    subjects: dict[str, str]
    proposed_overrides: list[OverrideRule]
    applied_overrides: list[OverrideRule]
    restack_path: str | None = None
    cutlist_path: str | None = None


def _cutlist_json(cut: CutList) -> str:
    return orjson.dumps(cut.model_dump(mode="json"), option=orjson.OPT_INDENT_2).decode()


def _cut_with_provenance(
    repo_path: Path, base: str, head: str, cfg: PartingConfig, resolved_revsets: dict[str, str]
) -> tuple[CutList, dict[str, str]]:
    outcome = PARTING.create("parting").cut(repo_path, base, head, cfg)
    cut = outcome.cutlist.model_copy(
        update={
            "provenance": outcome.cutlist.provenance.model_copy(
                update={"resolved_revsets": resolved_revsets}
            )
        }
    )
    return cut, outcome.old_paths


def run_part(
    repo_path: Path,
    base: str,
    head: str,
    cfg: PartingConfig,
    *,
    timestamp: str,
    force: bool = False,
    describer: CommitDescriberPort | None = None,
    suggester: TierSuggesterPort | None = None,
    suggest_apply: bool = False,
    override_write_target: Path | None = None,
    out_dir: Path | None = None,
    runner: ToolRunnerPort | None = None,
) -> PartRunResult:
    """Run the full parting pipeline once. Raises `PartingGateError`/`PartingError`
    on precondition or cut failure — same exceptions the CLI has always caught."""
    describer = describer or NullDescriber()
    suggester = suggester or NullSuggester()

    # 1. Safety gate — runs before anything is touched; aborts hard on failure.
    gate = run_gate(repo_path, base, head, timestamp=timestamp, force=force, runner=runner)

    # 2. Cut: producer (build_stock) -> consumer (part()). Pin the gate's revsets.
    cut, old_paths = _cut_with_provenance(repo_path, base, head, cfg, gate.resolved_revsets)

    # 2b. Advisory tier suggester (imperative shell): ask a local model to propose
    # override globs for the 'logic' residual. Env-driven and OUTSIDE config_digest;
    # the model only authors globs — the deterministic boundary validates them and
    # only the globs a caller accepts (suggest_apply) ever enter the cut.
    proposed = suggest_overrides(cut, suggester, existing_overrides=cfg.overrides)
    applied: list[OverrideRule] = []
    if proposed and suggest_apply:
        write_target = override_write_target or repo_path
        for r in proposed:
            write_override(write_target, glob=r.glob, bucket=r.bucket.value, note=r.note)
        # Re-part with the accepted globs layered in-memory (independent of where
        # the file landed), so the rendered cut reflects them deterministically.
        cfg = cfg.model_copy(update={"overrides": [*cfg.overrides, *proposed]})
        cut, old_paths = _cut_with_provenance(repo_path, base, head, cfg, gate.resolved_revsets)
        applied = proposed

    # 3. Probe the installed jj for non-interactive path restore (do not assume).
    can_reconstruct, jj_version = probe_path_capability(str(repo_path), runner=runner)

    # 3b. Advisory describer (imperative shell): name each commit with a local
    # model, fail-soft to the deterministic subject. Env-driven and OUTSIDE
    # config_digest, so it never touches the cut — only the human-readable subject.
    subjects = describe_parts(cut, describer)

    # 4. Emit the restack script, pinning the gate's resolved base/head ids.
    script = render_restack_script(
        cut,
        base_rev=gate.resolved_revsets.get("base") or base,
        head_rev=gate.resolved_revsets.get("head") or head,
        old_paths=old_paths,
        backup_bookmark=gate.backup_bookmark,
        rescue_op_id=gate.rescue_op_id,
        jj_version=jj_version or gate.jj_version,
        target=cfg.target,
        validate_command=cfg.validate_command,
        can_reconstruct=can_reconstruct,
        subjects=subjects,
    )

    restack_path: str | None = None
    cutlist_path: str | None = None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        script_file = out_dir / "restack.sh"
        script_file.write_text(script)
        script_file.chmod(0o755)
        restack_path = str(script_file)
        # JSON persistence is optional (a proposal, not a verdict) but useful for
        # `--explain` / the web sidecar's download button.
        cutlist_file = out_dir / "cutlist.json"
        cutlist_file.write_text(_cutlist_json(cut))
        cutlist_path = str(cutlist_file)

    return PartRunResult(
        cutlist=cut,
        script_text=script,
        backup_bookmark=gate.backup_bookmark,
        rescue_op_id=gate.rescue_op_id,
        jj_version=jj_version or gate.jj_version,
        can_reconstruct=can_reconstruct,
        subjects=subjects,
        proposed_overrides=proposed,
        applied_overrides=applied,
        restack_path=restack_path,
        cutlist_path=cutlist_path,
    )
