"""Tests for GitHub PR reference parsing — ``core.pr_ref.parse_pr_ref``.

# tested-by: tests/unit/test_pr_ref.py

Pure parsing, no IO. Accepts a full PR URL or a bare number (the latter needs a
``default_slug`` for the owner/repo). Anything else is a hard ``ValueError`` at
the boundary (DPS-102) — the caller turns it into a clean CLI usage error.

Property domains (DPS-12):
  Determinism   INVARIANT   same input string -> identical PrRef
"""

from __future__ import annotations

import pytest

from caliper.core.pr_ref import PrRef, parse_pr_ref


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
    def test_determinism(self) -> None:
        a = parse_pr_ref("https://github.com/o/r/pull/7")
        b = parse_pr_ref("https://github.com/o/r/pull/7")
        assert a == b
        assert isinstance(a, PrRef)
