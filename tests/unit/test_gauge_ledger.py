"""Tests for the claims ledger — ``core.ledger`` (append-only advisory store).

# tested-by: tests/unit/test_gauge_ledger.py
"""

from __future__ import annotations

from caliper.core.ledger import append, load
from caliper.core.models import Claim, LedgerEntry


def _entry(assertion="x") -> LedgerEntry:
    return LedgerEntry(
        claim=Claim(
            file="a.py",
            line_range=(1, 2),
            severity="major",
            category="correctness",
            assertion=assertion,
        ),
        repo="r",
        sha="s",
        content_hash="h",
    )


def test_load_missing_ledger_is_empty(tmp_path) -> None:
    assert load(tmp_path / "nope.jsonl") == []


def test_append_is_append_only(tmp_path) -> None:
    path = tmp_path / "ledger.jsonl"
    append(path, [_entry("a")])
    append(path, [_entry("b")])  # second append does not rewrite the first
    loaded = load(path)
    assert [e.claim.assertion for e in loaded] == ["a", "b"]


def test_roundtrip_preserves_content_refs(tmp_path) -> None:
    path = tmp_path / "ledger.jsonl"
    append(path, [_entry("a")])
    e = load(path)[0]
    assert e.repo == "r" and e.sha == "s" and e.content_hash == "h"
