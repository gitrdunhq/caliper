"""Pure plan for pushing a cut list as a sequential stack of PRs (#524).

# tested-by: tests/unit/test_part_stack.py

``plan_stack`` is the functional core for stacked PR push: given an already-
computed ``CutList``, it decides — with no IO, no wall-clock, no randomness —
which local ref (the bookmark ``core.part_script.render_restack_script``
already created under ``target=stack``) maps to which remote branch, and how
each part's PR chains onto the previous part's branch. The imperative shell
(push + `gh pr create`) is a separate module; this one only plans.
"""

from __future__ import annotations

from dataclasses import dataclass

from caliper.core.models import CutList, Part


@dataclass(frozen=True)
class StackEntry:
    """One part's place in the stack: what to push, and what to base it on."""

    index: int  # 1-based, matches render_restack_script's caliper-part-<i>
    local_ref: str  # the local bookmark/branch restack.sh already created
    remote_branch: str  # deterministic name to push it as
    base_branch: str  # this part's PR base (prior part's remote_branch, or the PR's base)
    part: Part


def plan_stack(cut: CutList, *, pr_number: int, base_branch: str) -> list[StackEntry]:
    """Plan the stack's local->remote branch mapping and PR base chain.

    Raises ValueError on an empty cut list — there is nothing to stack.
    """
    if not cut.parts:
        raise ValueError("cannot plan a stack for an empty cut list")

    entries: list[StackEntry] = []
    previous_base = base_branch
    for i, part in enumerate(cut.parts, start=1):
        remote_branch = f"caliper-pr{pr_number}-{i:02d}-{part.bucket.value}"
        entries.append(
            StackEntry(
                index=i,
                local_ref=f"caliper-part-{i}",
                remote_branch=remote_branch,
                base_branch=previous_base,
                part=part,
            )
        )
        previous_base = remote_branch
    return entries
