"""Detector profiles — general bugs on by default, house rules opt-in.
# tested-by: tests/unit/detectors/test_profiles.py

Half of the 22 detectors encode caliper's own conventions (tested-by
annotations, pathlib-only paths, atomic writes, ...). Shipped on by default
they flag every other repo for not being caliper: CAL-008 and CAL-021 alone
were 705 of 1,377 findings on a dogfood run. Profiles keep the general bug
detectors on and make the house rules a deliberate choice.
"""

from __future__ import annotations

import pytest

from caliper.detectors._registry import discover_detectors, get_all_detectors
from caliper.detectors.profiles import DEFAULT_PROFILE, PROFILES, resolve_detector_ids

_HOUSE = {
    "CAL-003",
    "CAL-007",
    "CAL-008",
    "CAL-009",
    "CAL-011",
    "CAL-014",
    "CAL-017",
    "CAL-019",
    "CAL-021",
}


def _all_ids() -> set[str]:
    discover_detectors()
    return {d.detector_id for d in get_all_detectors()}


class TestProfileDriftGuard:
    def test_every_detector_is_in_exactly_one_profile(self) -> None:
        ids = _all_ids()
        assert ids, "no detectors discovered"
        seen: dict[str, list[str]] = {}
        for name, members in PROFILES.items():
            for d in members:
                seen.setdefault(d, []).append(name)
        missing = ids - set(seen)
        dupes = {d: p for d, p in seen.items() if len(p) > 1}
        unknown = set(seen) - ids
        assert not missing, f"detectors in no profile: {sorted(missing)}"
        assert not dupes, f"detectors in several profiles: {dupes}"
        assert not unknown, f"profile names a detector that does not exist: {sorted(unknown)}"

    def test_default_profile_is_general_bugs_only(self) -> None:
        assert DEFAULT_PROFILE == "default"
        assert not (PROFILES["default"] & _HOUSE)
        assert PROFILES["house-rules"] == _HOUSE
        for must in ("CAL-001", "CAL-002", "CAL-004", "CAL-005", "CAL-012"):
            assert must in PROFILES["default"]


class TestResolve:
    def test_default_profile_only(self) -> None:
        ids = resolve_detector_ids(["default"], enable=[], disable=[], known=_all_ids())
        assert "CAL-005" in ids and "CAL-008" not in ids and "CAL-014" not in ids

    def test_enable_adds_a_house_rule_without_the_whole_profile(self) -> None:
        ids = resolve_detector_ids(["default"], enable=["CAL-014"], disable=[], known=_all_ids())
        assert "CAL-014" in ids and "CAL-008" not in ids

    def test_disable_removes_a_default_detector(self) -> None:
        ids = resolve_detector_ids(["default"], enable=[], disable=["CAL-005"], known=_all_ids())
        assert "CAL-005" not in ids and "CAL-001" in ids

    def test_both_profiles_is_everything(self) -> None:
        ids = resolve_detector_ids(
            ["default", "house-rules"], enable=[], disable=[], known=_all_ids()
        )
        assert set(ids) == _all_ids()

    def test_result_is_sorted_and_deduplicated(self) -> None:
        ids = resolve_detector_ids(
            ["default"], enable=["CAL-001", "CAL-001"], disable=[], known=_all_ids()
        )
        assert ids == sorted(set(ids))

    def test_unknown_profile_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown detector profile"):
            resolve_detector_ids(["nope"], enable=[], disable=[], known=_all_ids())

    def test_unknown_detector_id_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown detector id"):
            resolve_detector_ids(["default"], enable=["CAL-999"], disable=[], known=_all_ids())
