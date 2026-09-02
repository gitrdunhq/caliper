"""Tests for the repo's own `.caliper-baseline.yaml` (dogfood baseline).

# tested-by: tests/unit/test_baseline_dogfood.py

Confirms the baseline file caliper uses to suppress its own currently-blocking
findings parses via the existing loader (`core/baseline.py`) and that every
entry carries a reason and has not expired as of a pinned reference date.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from caliper.core.baseline import Baseline, load_baseline

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BASELINE_PATH = _REPO_ROOT / ".caliper-baseline.yaml"

# Pinned "as of" date — deliberately not datetime.now() so this test is
# deterministic regardless of when it runs.
_AS_OF = date(2026, 9, 2)


class TestDogfoodBaselineFile:
    def test_baseline_file_exists_with_an_entry_per_blocking_finding(self) -> None:
        """AC1: the baseline file exists at repo root with at least one entry,
        and every entry carries both a reason and an expiry date."""
        assert _BASELINE_PATH.exists(), (
            f"{_BASELINE_PATH} must exist so `caliper review` dogfooding is not "
            "blocked by findings pending remediation"
        )

        baseline = load_baseline(_BASELINE_PATH)
        assert (
            len(baseline.entries) > 0
        ), "expected at least one entry — one per currently-blocking finding"
        for entry in baseline.entries:
            assert entry.reason, f"entry {entry.fingerprint} is missing a reason"
            assert (
                entry.expires is not None
            ), f"entry {entry.fingerprint} is missing an expiry/TTL date"

    def test_baseline_parses_without_error_via_existing_loader(self) -> None:
        """AC2: the file parses via caliper.core.baseline.load_baseline without
        falling back to an empty Baseline (which is what happens on read/parse
        failure — fail-open, but that would mean it never actually parsed)."""
        baseline = load_baseline(_BASELINE_PATH)
        assert isinstance(baseline, Baseline)
        assert len(baseline.entries) > 0, (
            "load_baseline() fell back to an empty Baseline — the file failed to "
            "parse (missing, invalid YAML, or invalid schema)"
        )

    def test_no_entry_is_expired_as_of_pinned_reference_date(self) -> None:
        """AC3: using a pinned 'as of' datetime fixture (not datetime.now()),
        no baseline entry's expiry is before that pinned date."""
        baseline = load_baseline(_BASELINE_PATH)
        assert len(baseline.entries) > 0

        expired = [e for e in baseline.entries if e.expires < _AS_OF]
        assert expired == [], (
            f"found expired baseline entries as of {_AS_OF}: "
            f"{[(e.fingerprint, e.expires) for e in expired]}"
        )
