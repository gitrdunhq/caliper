"""Advisory commit-subject describer — port, request, and the deterministic boundary.

# tested-by: tests/unit/test_commit_describer.py

A part's ``type(scope):`` prefix is deterministic (derived from its bucket — and
release-please reads it for semver, so it must never depend on a model). The describer
fills only the human-readable *prose tail*, which is cosmetic and fail-soft: if no
backend is reachable the caller keeps the deterministic ``_peel_subject`` line. The
cut, classification, ordering and ``config_digest`` are untouched by anything here.

``normalize_subject`` is the boundary (DPS-102) that turns a small model's loose
output into one clean conventional-commit line. Concrete network backends live in the
data tier (``caliper.data.openai_describer``); this module stays pure and importable
without them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Leading ``type:`` / ``type(scope):`` a weak model may echo back in its tail.
_ECHOED_PREFIX = re.compile(r"^[a-z][a-z0-9]*(\([^)]*\))?:\s*")
_WHITESPACE = re.compile(r"\s+")


def normalize_subject(prefix: str, raw: str, *, max_len: int = 72) -> str:
    """Clean a model's free-text into ``prefix + tail``; return ``""`` when empty.

    Deterministic and pure. Steps: first non-empty line only, strip surrounding
    quotes/backticks, drop an echoed conventional prefix, collapse whitespace,
    lowercase just the leading character (acronyms like SSM/CDK keep their case),
    drop trailing punctuation, and cap the whole subject at *max_len* on a word
    boundary. An empty tail signals the caller to fall back to the deterministic
    subject rather than emit a bare prefix.
    """
    line = next((ln.strip() for ln in raw.splitlines() if ln.strip()), "")
    line = line.strip("`\"'").strip()
    line = _ECHOED_PREFIX.sub("", line)
    line = _WHITESPACE.sub(" ", line).strip()
    line = line.rstrip(". ")
    if line:
        line = line[0].lower() + line[1:]
    if not line:
        return ""
    subject = prefix + line
    if len(subject) <= max_len:
        return subject
    # Truncate the tail on a word boundary so we never emit a half-word.
    budget = max_len - len(prefix)
    clipped = line[:budget].rsplit(" ", 1)[0].rstrip(". ") if budget > 0 else ""
    return (prefix + clipped) if clipped else ""


@dataclass(frozen=True)
class DescribeRequest:
    """The advisory context handed to a describer for one already-decided part.

    ``prefix`` is the deterministic ``type(scope): `` head; the backend writes only
    the tail that follows it. ``files``/``context`` are read-only hints — never the
    decision, which is already made.
    """

    prefix: str
    bucket: str
    files: list[str]
    context: str = ""
    max_len: int = 72


@dataclass(frozen=True)
class DescribeResult:
    """A describer outcome. ``subject`` is ``None`` when unavailable (fail-soft)."""

    subject: str | None = None
    note: str = ""
    extras: dict = field(default_factory=dict)


@runtime_checkable
class CommitDescriberPort(Protocol):
    """Structural contract for a commit-subject backend. Advisory; never raises."""

    def describe(self, request: DescribeRequest) -> str | None:
        """Return a normalized subject line, or ``None`` to fall back deterministically."""
        ...


class NullDescriber:
    """The fail-soft default: no backend configured, so no subject is produced."""

    def describe(self, request: DescribeRequest) -> str | None:  # noqa: ARG002
        return None
