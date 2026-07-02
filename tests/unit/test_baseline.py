"""Tests for caliper.core.baseline — finding suppression with expiry."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from caliper.core.baseline import (
    Baseline,
    BaselineEntry,
    filter_findings,
    finding_fingerprint,
    load_baseline,
    merge_new_entries,
    save_baseline,
)
from caliper.core.models import Finding, FindingCategory, FindingSeverity


def _finding(**overrides) -> Finding:
    fields = {
        "severity": FindingSeverity.high,
        "category": FindingCategory.vulnerability,
        "description": "SQL injection in query builder",
        "source_tool": "osv-scanner",
        "package_name": "django",
        "version": "3.2.0",
        "advisory_id": "GHSA-xxxx",
        "file_path": "requirements.txt",
        "line_number": 12,
    }
    fields.update(overrides)
    return Finding(**fields)


class TestFindingFingerprint:
    def test_same_finding_same_fingerprint(self) -> None:
        a = _finding()
        b = _finding()
        assert finding_fingerprint(a) == finding_fingerprint(b)

    def test_different_line_number_same_fingerprint(self) -> None:
        a = _finding(line_number=12)
        b = _finding(line_number=99)
        assert finding_fingerprint(a) == finding_fingerprint(b)

    def test_different_package_different_fingerprint(self) -> None:
        a = _finding(package_name="django")
        b = _finding(package_name="flask")
        assert finding_fingerprint(a) != finding_fingerprint(b)

    def test_different_advisory_different_fingerprint(self) -> None:
        a = _finding(advisory_id="GHSA-aaaa")
        b = _finding(advisory_id="GHSA-bbbb")
        assert finding_fingerprint(a) != finding_fingerprint(b)

    def test_windows_and_posix_paths_same_fingerprint(self) -> None:
        a = _finding(file_path="sub/dir/requirements.txt")
        b = _finding(file_path="sub\\dir\\requirements.txt")
        assert finding_fingerprint(a) == finding_fingerprint(b)

    def test_none_file_path_does_not_raise(self) -> None:
        f = _finding(file_path=None)
        assert isinstance(finding_fingerprint(f), str)


class TestFilterFindings:
    def test_finding_with_no_baseline_entry_is_kept(self) -> None:
        f = _finding()
        kept, suppressed, expired = filter_findings([f], Baseline(), date.today())

        assert kept == [f]
        assert suppressed == []
        assert expired == []

    def test_finding_with_active_entry_is_suppressed(self) -> None:
        f = _finding()
        today = date(2026, 1, 1)
        entry = BaselineEntry(
            fingerprint=finding_fingerprint(f),
            reason="tracked in JIRA-1",
            added=today,
            expires=today + timedelta(days=30),
        )

        kept, suppressed, expired = filter_findings([f], Baseline(entries=[entry]), today)

        assert kept == []
        assert suppressed == [f]
        assert expired == []

    def test_expired_entry_fails_safe_back_into_kept(self) -> None:
        f = _finding()
        today = date(2026, 6, 1)
        entry = BaselineEntry(
            fingerprint=finding_fingerprint(f),
            reason="tracked in JIRA-1",
            added=date(2026, 1, 1),
            expires=date(2026, 2, 1),
        )

        kept, suppressed, expired = filter_findings([f], Baseline(entries=[entry]), today)

        assert kept == [f]
        assert suppressed == []
        assert expired == [f]

    def test_entry_expiring_today_is_still_suppressed(self) -> None:
        """expires is the last valid day — inclusive, not a strict cutoff."""
        f = _finding()
        today = date(2026, 2, 1)
        entry = BaselineEntry(
            fingerprint=finding_fingerprint(f),
            reason="r",
            added=date(2026, 1, 1),
            expires=today,
        )

        kept, suppressed, expired = filter_findings([f], Baseline(entries=[entry]), today)

        assert suppressed == [f]
        assert kept == []
        assert expired == []

    def test_entry_expired_the_day_after_expires(self) -> None:
        f = _finding()
        expires = date(2026, 2, 1)
        today = expires + timedelta(days=1)
        entry = BaselineEntry(
            fingerprint=finding_fingerprint(f),
            reason="r",
            added=date(2026, 1, 1),
            expires=expires,
        )

        kept, suppressed, expired = filter_findings([f], Baseline(entries=[entry]), today)

        assert kept == [f]
        assert expired == [f]
        assert suppressed == []

    def test_duplicate_fingerprint_entries_first_wins(self) -> None:
        f = _finding()
        fp = finding_fingerprint(f)
        today = date(2026, 1, 1)
        first = BaselineEntry(
            fingerprint=fp, reason="first", added=today, expires=today + timedelta(days=1)
        )
        second = BaselineEntry(
            fingerprint=fp, reason="second", added=today, expires=today - timedelta(days=1)
        )

        kept, suppressed, expired = filter_findings([f], Baseline(entries=[first, second]), today)

        assert suppressed == [f]
        assert kept == []


class TestLoadSaveBaseline:
    def test_missing_file_returns_empty_baseline(self, tmp_path: Path) -> None:
        assert load_baseline(tmp_path / "missing.yaml") == Baseline()

    def test_invalid_yaml_returns_empty_baseline(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.yaml"
        path.write_text("not: valid: yaml: [")
        assert load_baseline(path) == Baseline()

    def test_invalid_schema_returns_empty_baseline(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.yaml"
        path.write_text("entries:\n  - fingerprint: abc\n")  # missing required fields
        assert load_baseline(path) == Baseline()

    def test_round_trips_through_save_and_load(self, tmp_path: Path) -> None:
        path = tmp_path / "sub" / "baseline.yaml"
        today = date(2026, 1, 1)
        baseline = Baseline(
            entries=[
                BaselineEntry(
                    fingerprint="abc123", reason="r", added=today, expires=today + timedelta(days=1)
                )
            ]
        )

        save_baseline(path, baseline)
        loaded = load_baseline(path)

        assert loaded == baseline


class TestMergeNewEntries:
    def test_new_finding_gets_added(self) -> None:
        f = _finding()
        today = date(2026, 1, 1)

        result = merge_new_entries(Baseline(), [f], reason="r", today=today, ttl_days=90)

        assert len(result.entries) == 1
        entry = result.entries[0]
        assert entry.fingerprint == finding_fingerprint(f)
        assert entry.reason == "r"
        assert entry.added == today
        assert entry.expires == today + timedelta(days=90)

    def test_already_baselined_finding_is_not_duplicated(self) -> None:
        f = _finding()
        today = date(2026, 1, 1)
        existing = Baseline(
            entries=[
                BaselineEntry(
                    fingerprint=finding_fingerprint(f),
                    reason="original reason",
                    added=date(2025, 1, 1),
                    expires=date(2025, 4, 1),
                )
            ]
        )

        result = merge_new_entries(existing, [f], reason="new reason", today=today, ttl_days=90)

        assert len(result.entries) == 1
        assert result.entries[0].reason == "original reason"

    def test_rerun_against_unchanged_findings_is_idempotent(self) -> None:
        f = _finding()
        today = date(2026, 1, 1)

        first = merge_new_entries(Baseline(), [f], reason="r", today=today, ttl_days=90)
        second = merge_new_entries(first, [f], reason="r", today=today, ttl_days=90)

        assert first == second

    def test_duplicate_findings_in_same_run_produce_one_entry(self) -> None:
        f = _finding()
        today = date(2026, 1, 1)

        result = merge_new_entries(Baseline(), [f, f], reason="r", today=today, ttl_days=90)

        assert len(result.entries) == 1


class TestProperties:
    """Determinism/SAFETY coverage for the fingerprint and expiry boundary."""

    @given(
        package=st.text(min_size=1, max_size=30),
        version=st.text(min_size=1, max_size=15),
        line_a=st.integers(min_value=0, max_value=100_000),
        line_b=st.integers(min_value=0, max_value=100_000),
    )
    def test_fingerprint_is_line_number_invariant(
        self, package: str, version: str, line_a: int, line_b: int
    ) -> None:
        """INVARIANT: fingerprint never depends on line_number."""
        a = _finding(package_name=package, version=version, line_number=line_a)
        b = _finding(package_name=package, version=version, line_number=line_b)
        assert finding_fingerprint(a) == finding_fingerprint(b)

    @given(
        expires_offset=st.integers(min_value=-3650, max_value=-1),
    )
    def test_expired_entry_never_suppresses(self, expires_offset: int) -> None:
        """SAFETY: an expired baseline entry never suppresses a finding."""
        f = _finding()
        today = date(2026, 1, 1)
        entry = BaselineEntry(
            fingerprint=finding_fingerprint(f),
            reason="r",
            added=today + timedelta(days=expires_offset - 1),
            expires=today + timedelta(days=expires_offset),
        )

        _kept, suppressed, _expired = filter_findings([f], Baseline(entries=[entry]), today)

        assert suppressed == []
