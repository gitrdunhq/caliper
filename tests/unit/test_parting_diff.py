"""Tests for ``core.parting.diff_cutlists`` — what changed since the last cut (#524).

# tested-by: tests/unit/test_parting_diff.py

Pure comparison of two ``CutList``s by file->bucket membership: added files
(new in the stock), removed files (gone from the stock), moved files (present
in both but reclassified to a different bucket), and part-count drift. No IO,
no re-parting — just a diff over already-computed cut lists, so a `--pr`
re-run on a moved head can show a reviewer what changed without re-reading
either cut list's provenance.

Property domains (DPS-12):
  Determinism  INVARIANT  same two cut lists -> byte-identical diff
"""

from __future__ import annotations

from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance
from caliper.core.parting import diff_cutlists


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


def _cutlist(*parts: Part, digest: str = "d") -> CutList:
    return CutList(parts=list(parts), provenance=_provenance(digest), stats=_stats(len(parts)))


def _part(id_: str, bucket: ChangeType, *files: str) -> Part:
    return Part(id=id_, files=sorted(files), bucket=bucket, size=1, opened_by=Kerf(fired_rule="r"))


def test_identical_cutlists_have_no_diff() -> None:
    cut = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"))
    d = diff_cutlists(cut, cut)
    assert d.added_files == []
    assert d.removed_files == []
    assert d.moved_files == []
    assert d.changed is False


def test_added_file() -> None:
    old = _cutlist(_part("p1", ChangeType.business, "a.py"))
    new = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"))
    d = diff_cutlists(old, new)
    assert d.added_files == ["b.py"]
    assert d.removed_files == []
    assert d.changed is True


def test_removed_file() -> None:
    old = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"))
    new = _cutlist(_part("p1", ChangeType.business, "a.py"))
    d = diff_cutlists(old, new)
    assert d.removed_files == ["b.py"]
    assert d.added_files == []
    assert d.changed is True


def test_file_moved_to_a_different_bucket() -> None:
    old = _cutlist(_part("p1", ChangeType.logic, "a.py"))
    new = _cutlist(_part("p1", ChangeType.business, "a.py"))
    d = diff_cutlists(old, new)
    assert d.moved_files == [("a.py", ChangeType.logic, ChangeType.business)]
    assert d.added_files == []
    assert d.removed_files == []
    assert d.changed is True


def test_moved_files_sorted_by_path() -> None:
    old = _cutlist(_part("p1", ChangeType.logic, "z.py", "a.py"))
    new = _cutlist(_part("p1", ChangeType.business, "z.py", "a.py"))
    d = diff_cutlists(old, new)
    assert [f for f, _, _ in d.moved_files] == ["a.py", "z.py"]


def test_part_count_drift_tracked_even_with_no_file_changes() -> None:
    """Same files, same buckets, but split into more parts (e.g. a size-cap
    change) — file-level diff is empty, but the part count still moved."""
    old = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"))
    new = _cutlist(
        _part("p1", ChangeType.business, "a.py"), _part("p2", ChangeType.business, "b.py")
    )
    d = diff_cutlists(old, new)
    assert d.added_files == []
    assert d.removed_files == []
    assert d.moved_files == []
    assert d.part_count_before == 1
    assert d.part_count_after == 2
    assert d.changed is True


def test_deterministic_regardless_of_part_order() -> None:
    old_a = _cutlist(
        _part("p1", ChangeType.business, "a.py"), _part("p2", ChangeType.logic, "b.py")
    )
    old_b = _cutlist(
        _part("p2", ChangeType.logic, "b.py"), _part("p1", ChangeType.business, "a.py")
    )
    new = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"))
    assert diff_cutlists(old_a, new) == diff_cutlists(old_b, new)
