"""Tests for the pure stacked-PR plan — ``core.part_stack.plan_stack`` (#524).

# tested-by: tests/unit/test_part_stack.py

Given an already-cut ``CutList``, ``plan_stack`` computes the ordered list of
stack entries an imperative shell will push: the local ref the generated
restack.sh actually created (``caliper-part-<i>``) paired with a deterministic
remote branch name and the chained base branch for each part's future PR.
No IO, no wall-clock, no randomness — same inputs always yield the same plan.

Property domains (DPS-12):
  Determinism  INVARIANT  same CutList + pr_number + base_branch -> equal plan
  Uniqueness   INVARIANT  remote_branch values are unique across the stack
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance
from caliper.core.part_stack import StackEntry, plan_stack

_REF_UNSAFE_RE = re.compile(r"\s|\.\.|~|\^|:|\?|\*|\[")


def _provenance(digest: str = "d") -> Provenance:
    return Provenance(
        caliper_version="0",
        base_sha="b",
        head_sha="h",
        rename_threshold=50,
        config_digest=digest,
    )


def _stats(n: int) -> CutStats:
    return CutStats(part_count=n, file_count=0, size_p50=0, size_p90=0, move_logic_pure=True)


def _part(id_: str, bucket: ChangeType, *files: str) -> Part:
    return Part(id=id_, files=sorted(files), bucket=bucket, size=1, opened_by=Kerf(fired_rule="r"))


def _cutlist(*parts: Part) -> CutList:
    return CutList(parts=list(parts), provenance=_provenance(), stats=_stats(len(parts)))


def _is_valid_ref_name(name: str) -> bool:
    return (
        bool(name)
        and not name.startswith("/")
        and not name.endswith("/")
        and not _REF_UNSAFE_RE.search(name)
    )


# ---------------------------------------------------------------------------
# Unit fixtures
# ---------------------------------------------------------------------------


def test_entry_local_refs_match_restack_script_convention() -> None:
    """local_ref must match core.part_script.render_restack_script's
    ``caliper-part-<i>`` (1-based) bookmarks under target 'stack'."""
    cut = _cutlist(
        _part("p1", ChangeType.business, "a.py"),
        _part("p2", ChangeType.logic, "b.py"),
        _part("p3", ChangeType.documentation, "c.md"),
    )
    entries = plan_stack(cut, pr_number=524, base_branch="main")
    assert [e.local_ref for e in entries] == ["caliper-part-1", "caliper-part-2", "caliper-part-3"]


def test_first_entry_bases_on_the_pr_base_branch() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py"))
    entries = plan_stack(cut, pr_number=524, base_branch="main")
    assert entries[0].base_branch == "main"


def test_entries_chain_base_to_previous_remote_branch() -> None:
    cut = _cutlist(
        _part("p1", ChangeType.business, "a.py"),
        _part("p2", ChangeType.logic, "b.py"),
        _part("p3", ChangeType.documentation, "c.md"),
    )
    entries = plan_stack(cut, pr_number=524, base_branch="main")
    assert entries[1].base_branch == entries[0].remote_branch
    assert entries[2].base_branch == entries[1].remote_branch


def test_remote_branch_names_are_unique_and_encode_pr_index_bucket() -> None:
    cut = _cutlist(
        _part("p1", ChangeType.business, "a.py"),
        _part("p2", ChangeType.documentation, "b.md"),
    )
    entries = plan_stack(cut, pr_number=524, base_branch="main")
    names = [e.remote_branch for e in entries]
    assert len(set(names)) == len(names)
    assert "524" in names[0]
    assert "business" in names[0]
    assert "documentation" in names[1]


def test_remote_branch_names_are_valid_git_ref_names() -> None:
    cut = _cutlist(
        _part("p1", ChangeType.business, "a.py"),
        _part("p2", ChangeType.documentation, "b.md"),
    )
    entries = plan_stack(cut, pr_number=524, base_branch="main")
    for e in entries:
        assert _is_valid_ref_name(e.remote_branch), e.remote_branch


def test_entry_index_is_one_based() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py"), _part("p2", ChangeType.logic, "b.py"))
    entries = plan_stack(cut, pr_number=524, base_branch="main")
    assert [e.index for e in entries] == [1, 2]


def test_entry_exposes_the_source_part() -> None:
    p1 = _part("p1", ChangeType.business, "a.py")
    cut = _cutlist(p1)
    entries = plan_stack(cut, pr_number=524, base_branch="main")
    assert entries[0].part == p1


def test_calling_twice_with_same_inputs_returns_equal_entries() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py"), _part("p2", ChangeType.logic, "b.py"))
    a = plan_stack(cut, pr_number=524, base_branch="main")
    b = plan_stack(cut, pr_number=524, base_branch="main")
    assert a == b


def test_empty_cutlist_raises_value_error() -> None:
    cut = _cutlist()
    with pytest.raises(ValueError):
        plan_stack(cut, pr_number=1, base_branch="main")


def test_stack_entry_is_a_dataclass_with_expected_fields() -> None:
    p1 = _part("p1", ChangeType.business, "a.py")
    cut = _cutlist(p1)
    entry = plan_stack(cut, pr_number=524, base_branch="main")[0]
    assert isinstance(entry, StackEntry)
    assert entry.index == 1
    assert entry.local_ref == "caliper-part-1"
    assert entry.base_branch == "main"
    assert isinstance(entry.remote_branch, str)
    assert entry.part == p1


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


@st.composite
def _cutlists(draw: st.DrawFn) -> CutList:
    n = draw(st.integers(min_value=1, max_value=15))
    buckets = draw(st.lists(st.sampled_from(list(ChangeType)), min_size=n, max_size=n))
    parts = [_part(f"p{i}", buckets[i], f"f{i}.py") for i in range(n)]
    return _cutlist(*parts)


class TestProperties:
    @given(cut=_cutlists(), pr_number=st.integers(min_value=1, max_value=99999))
    @settings(max_examples=100)
    def test_plan_length_and_order_match_cutlist(self, cut: CutList, pr_number: int) -> None:
        """Determinism/coverage: len(plan) == len(cut.parts), order preserved."""
        entries = plan_stack(cut, pr_number=pr_number, base_branch="main")
        assert len(entries) == len(cut.parts)
        for k, entry in enumerate(entries):
            assert entry.part == cut.parts[k]

    @given(cut=_cutlists(), pr_number=st.integers(min_value=1, max_value=99999))
    @settings(max_examples=100)
    def test_remote_branches_are_unique(self, cut: CutList, pr_number: int) -> None:
        """Uniqueness INVARIANT: no two parts collide on a remote branch name."""
        entries = plan_stack(cut, pr_number=pr_number, base_branch="main")
        names = {e.remote_branch for e in entries}
        assert len(names) == len(entries)

    @given(cut=_cutlists(), pr_number=st.integers(min_value=1, max_value=99999))
    @settings(max_examples=100)
    def test_determinism_repeat_calls_equal(self, cut: CutList, pr_number: int) -> None:
        """Determinism INVARIANT: same inputs -> equal plan across calls."""
        a = plan_stack(cut, pr_number=pr_number, base_branch="main")
        b = plan_stack(cut, pr_number=pr_number, base_branch="main")
        assert a == b
