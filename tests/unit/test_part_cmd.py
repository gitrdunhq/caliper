"""Tests for ``cli.part_cmd``'s pure rendering helpers.

# tested-by: tests/unit/test_part_cmd.py

``_render_cutlist_diff`` formats what changed between two cut lists (#524) so
a reviewer re-running ``--pr`` on a moved head sees what changed since the
last cut without eyeballing two full cut lists. It also distinguishes a
moved head (new commits) from an unmoved head with a config/override change
(same commits, different cut) — conflating the two would misread a size-cap
tweak as "the PR moved."
"""

from __future__ import annotations

from caliper.cli.part_cmd import _render_cutlist_diff
from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance


def _provenance(head_sha: str = "h", digest: str = "d") -> Provenance:
    return Provenance(
        caliper_version="0",
        base_sha="b",
        head_sha=head_sha,
        rename_threshold=50,
        config_digest=digest,
    )


def _stats(n: int) -> CutStats:
    return CutStats(part_count=n, file_count=0, size_p50=0, size_p90=0, move_logic_pure=True)


def _cutlist(*parts: Part, head_sha: str = "h", digest: str = "d") -> CutList:
    return CutList(
        parts=list(parts), provenance=_provenance(head_sha, digest), stats=_stats(len(parts))
    )


def _part(id_: str, bucket: ChangeType, *files: str) -> Part:
    return Part(id=id_, files=sorted(files), bucket=bucket, size=1, opened_by=Kerf(fired_rule="r"))


def test_no_prior_cut_renders_nothing() -> None:
    new = _cutlist(_part("p1", ChangeType.business, "a.py"))
    assert _render_cutlist_diff(None, new) == ""


def test_unchanged_diff_renders_a_no_change_line() -> None:
    old = _cutlist(_part("p1", ChangeType.business, "a.py"))
    new = _cutlist(_part("p1", ChangeType.business, "a.py"))
    out = _render_cutlist_diff(old, new)
    assert "no change since the last cut" in out


def test_added_and_removed_files_are_listed() -> None:
    old = _cutlist(_part("p1", ChangeType.business, "a.py", "c.py"), head_sha="h1")
    new = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"), head_sha="h2")
    out = _render_cutlist_diff(old, new)
    assert "+ b.py" in out
    assert "- c.py" in out


def test_moved_files_show_bucket_transition() -> None:
    old = _cutlist(_part("p1", ChangeType.logic, "a.py"), head_sha="h1")
    new = _cutlist(_part("p1", ChangeType.business, "a.py"), head_sha="h2")
    out = _render_cutlist_diff(old, new)
    assert "a.py" in out
    assert "logic" in out and "business" in out


def test_part_count_drift_is_reported() -> None:
    old = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"), head_sha="h1")
    new = _cutlist(
        _part("p1", ChangeType.business, "a.py"),
        _part("p2", ChangeType.business, "b.py"),
        head_sha="h1",
    )
    out = _render_cutlist_diff(old, new)
    assert "1" in out and "2" in out


def test_header_shows_head_sha_transition() -> None:
    old = _cutlist(_part("p1", ChangeType.business, "a.py"), head_sha="aaaa1111")
    new = _cutlist(_part("p1", ChangeType.business, "a.py"), head_sha="bbbb2222")
    out = _render_cutlist_diff(old, new)
    assert "aaaa1111" in out and "bbbb2222" in out


def test_config_only_change_on_unmoved_head_is_labeled_not_a_head_move() -> None:
    # Same head_sha, different config_digest (e.g. a size-cap change split one
    # part into two): the reviewer must not read this as "the PR moved."
    old = _cutlist(_part("p1", ChangeType.business, "a.py", "b.py"), head_sha="h1", digest="d1")
    new = _cutlist(
        _part("p1", ChangeType.business, "a.py"),
        _part("p2", ChangeType.business, "b.py"),
        head_sha="h1",
        digest="d2",
    )
    out = _render_cutlist_diff(old, new)
    assert "not new commits" in out


def test_config_only_change_with_no_cut_effect_is_still_reported() -> None:
    # Config changed but the resulting cut is byte-identical file-wise.
    old = _cutlist(_part("p1", ChangeType.business, "a.py"), head_sha="h1", digest="d1")
    new = _cutlist(_part("p1", ChangeType.business, "a.py"), head_sha="h1", digest="d2")
    out = _render_cutlist_diff(old, new)
    assert "config" in out
