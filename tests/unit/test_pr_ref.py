"""Tests for GitHub PR reference parsing — ``core.pr_ref.parse_pr_ref``.

# tested-by: tests/unit/test_pr_ref.py

Pure parsing, no IO. Accepts a full PR URL or a bare number (the latter needs a
``default_slug`` for the owner/repo). Anything else is a hard ``ValueError`` at
the boundary (DPS-102) — the caller turns it into a clean CLI usage error.

Property domains (DPS-12):
  Determinism   INVARIANT   same input string -> identical PrRef
  (fail-open)   SAFETY      malformed URLs/numbers either parse cleanly or raise
                             a typed ValueError — never an unhandled exception
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.pr_ref import PrRef, parse_pr_ref
from tests.unit._strategies import (
    bare_pr_number,
    garbage_text,
    malformed_pr_ref,
    valid_pr_url,
    whitespace_and_control_text,
)


def test_full_url() -> None:
    ref = parse_pr_ref("https://github.com/owner/repo/pull/123")
    assert (ref.owner, ref.repo, ref.number) == ("owner", "repo", 123)
    assert ref.slug == "owner/repo"
    assert ref.clone_url == "https://github.com/owner/repo.git"
    assert ref.url == "https://github.com/owner/repo/pull/123"


def test_workdir_slug_is_owner_keyed() -> None:
    # The clone dir lives in a centralized, cross-repo workdir now, so the key
    # must include the owner — otherwise orgA/foo and orgB/foo collide.
    a = PrRef(owner="orgA", repo="foo", number=7)
    b = PrRef(owner="orgB", repo="foo", number=7)
    assert a.workdir_slug == "orgA-foo-pr7"
    assert b.workdir_slug == "orgB-foo-pr7"
    assert a.workdir_slug != b.workdir_slug


def test_workdir_slug_sanitizes_unsafe_chars() -> None:
    # Defensive: no path separators or odd chars leak into a directory name.
    ref = PrRef(owner="o/../x", repo="re po", number=3)
    assert "/" not in ref.workdir_slug
    assert " " not in ref.workdir_slug
    assert ref.workdir_slug.endswith("-pr3")


def test_url_with_trailing_path() -> None:
    # GitHub appends /files, /commits, #discussion etc — still a PR #9.
    ref = parse_pr_ref("https://github.com/o/r/pull/9/files")
    assert ref.number == 9


def test_url_http_scheme() -> None:
    ref = parse_pr_ref("http://github.com/o/r/pull/4")
    assert ref.number == 4


def test_bare_number_uses_default_slug() -> None:
    ref = parse_pr_ref("123", default_slug="gitrdunhq/caliper")
    assert (ref.owner, ref.repo, ref.number) == ("gitrdunhq", "caliper", 123)
    assert ref.url is None
    assert ref.clone_url == "https://github.com/gitrdunhq/caliper.git"


def test_hash_prefixed_number() -> None:
    ref = parse_pr_ref("#42", default_slug="a/b")
    assert ref.number == 42


def test_bare_number_without_slug_errors() -> None:
    with pytest.raises(ValueError, match="needs a repo"):
        parse_pr_ref("123")


def test_bare_number_with_unparseable_slug_errors() -> None:
    with pytest.raises(ValueError, match="repo slug"):
        parse_pr_ref("123", default_slug="not-a-slug")


def test_garbage_errors() -> None:
    with pytest.raises(ValueError):
        parse_pr_ref("not-a-pr")


def test_zero_number_rejected() -> None:
    with pytest.raises(ValueError):
        parse_pr_ref("https://github.com/o/r/pull/0")


class TestProperties:
    """Hypothesis coverage for the PR-reference parsing boundary."""

    def test_determinism(self) -> None:
        a = parse_pr_ref("https://github.com/o/r/pull/7")
        b = parse_pr_ref("https://github.com/o/r/pull/7")
        assert a == b
        assert isinstance(a, PrRef)

    @given(url=valid_pr_url())
    @settings(max_examples=200)
    def test_valid_url_determinism(self, url: str) -> None:
        """Same well-formed PR URL always parses to an equal PrRef."""
        a = parse_pr_ref(url)
        b = parse_pr_ref(url)
        assert a == b
        assert isinstance(a, PrRef)
        assert a.number >= 1

    @given(number=bare_pr_number())
    @settings(max_examples=200)
    def test_bare_number_determinism(self, number: str) -> None:
        """Same bare number (with a fixed default_slug) always parses identically."""
        a = parse_pr_ref(number, default_slug="acme/widgets")
        b = parse_pr_ref(number, default_slug="acme/widgets")
        assert a == b
        assert a.owner == "acme"
        assert a.repo == "widgets"

    @given(
        value=st.one_of(malformed_pr_ref(), garbage_text(), whitespace_and_control_text()),
        default_slug=st.one_of(st.none(), st.just("a/b"), garbage_text(max_size=20)),
    )
    @settings(max_examples=300)
    def test_malformed_input_raises_clean_value_error_or_parses(
        self, value: str, default_slug: str | None
    ) -> None:
        """Malformed/garbage input either parses to a valid PrRef, or raises a
        clean ``ValueError`` — never an unhandled exception (TypeError, regex
        errors, IndexError, etc.) that would leak a stack trace to the CLI.
        """
        try:
            result = parse_pr_ref(value, default_slug=default_slug)
        except ValueError:
            return
        assert isinstance(result, PrRef)
        assert result.number >= 1

    @given(
        value=st.one_of(malformed_pr_ref(), garbage_text(), whitespace_and_control_text()),
        default_slug=st.one_of(st.none(), st.just("a/b"), garbage_text(max_size=20)),
    )
    @settings(max_examples=300)
    def test_malformed_input_parsing_is_deterministic(
        self, value: str, default_slug: str | None
    ) -> None:
        """Determinism holds for the error path too: same junk -> same outcome."""

        def _outcome() -> PrRef | str:
            try:
                return parse_pr_ref(value, default_slug=default_slug)
            except ValueError as exc:
                return str(exc)

        assert _outcome() == _outcome()
