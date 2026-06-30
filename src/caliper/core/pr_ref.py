"""Parse a GitHub PR reference (URL or bare number) into a typed ``PrRef``.

# tested-by: tests/unit/test_pr_ref.py

Pure, no IO: the functional core of ``caliper part --pr``. A full PR URL is
self-describing; a bare number (``123`` / ``#123``) borrows the owner/repo from
``default_slug`` (the current repo's origin, resolved by the shell). Anything
else is a hard ``ValueError`` at the boundary (DPS-102) — the CLI turns it into a
clean usage error rather than letting a malformed ref reach git.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

# Prefix match: GitHub appends /files, /commits, #discussion etc to a PR URL.
_PR_URL_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)"
)
_SLUG_RE = re.compile(r"^(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)$")
_NUMBER_RE = re.compile(r"^#?(?P<number>\d+)$")


class PrRef(BaseModel):
    """A resolved GitHub pull-request reference. Immutable boundary value."""

    model_config = ConfigDict(frozen=True)

    owner: str
    repo: str
    number: int
    url: str | None = None

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}.git"


def _strip_git_suffix(repo: str) -> str:
    return repo[:-4] if repo.endswith(".git") else repo


def parse_pr_ref(value: str, *, default_slug: str | None = None) -> PrRef:
    """Parse a PR URL or bare number into a ``PrRef``. Raises ``ValueError`` on junk."""
    value = value.strip()

    m = _PR_URL_RE.match(value)
    if m:
        number = int(m["number"])
        if number <= 0:
            raise ValueError(f"PR number must be positive, got {number}")
        return PrRef(owner=m["owner"], repo=_strip_git_suffix(m["repo"]), number=number, url=value)

    m = _NUMBER_RE.match(value)
    if m:
        number = int(m["number"])
        if number <= 0:
            raise ValueError(f"PR number must be positive, got {number}")
        if not default_slug:
            raise ValueError(
                f"bare PR number {value!r} needs a repo — run inside a GitHub repo "
                "or pass a full PR URL (https://github.com/owner/repo/pull/123)"
            )
        sm = _SLUG_RE.match(default_slug)
        if not sm:
            raise ValueError(
                f"could not resolve the current repo slug ({default_slug!r}); "
                "pass a full PR URL instead"
            )
        return PrRef(owner=sm["owner"], repo=_strip_git_suffix(sm["repo"]), number=number)

    raise ValueError(
        f"not a GitHub PR URL or number: {value!r} "
        "(e.g. https://github.com/owner/repo/pull/123 or 123)"
    )
