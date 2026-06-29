"""Tests for propose — the flywheel's only LLM step (fake drafter).

# tested-by: tests/unit/test_gauge_propose.py
"""

from __future__ import annotations

from caliper.core.flywheel import cluster_key
from caliper.core.gauge_propose import propose
from caliper.core.llm_port import DraftRequest, DraftResult
from caliper.core.models import Claim, LedgerEntry
from caliper.core.repo_config import GaugeConfig

CFG = GaugeConfig()


def _entry(assertion, cat="correctness", sha="s", ch="p", author="a"):
    return LedgerEntry(
        claim=Claim(
            file="a.py", line_range=(1, 2), severity="major", category=cat, assertion=assertion
        ),
        repo="r",
        sha=sha,
        content_hash=ch,
        author=author,
    )


def _recurring(assertion, cat="correctness", n=3):
    return [_entry(assertion, cat=cat, sha=f"s{i}", ch=f"p{i}", author=f"a{i}") for i in range(n)]


class _Drafter:
    def __init__(self, available=True):
        self.available = available

    def draft(self, request: DraftRequest) -> DraftResult:
        return DraftResult(
            available=self.available, kind="semgrep", draft=f"rule:{request.cluster_key}"
        )


def test_drafts_candidates_for_eligible_clusters_only() -> None:
    entries = _recurring("missing null check", "correctness", 3) + _recurring(
        "prefer f-string", "style", 4
    )
    cands = propose(entries, CFG, _Drafter(), top=10)
    assert len(cands) == 1  # the style cluster is ineligible (candidacy floor)
    assert cands[0].kind == "semgrep"
    assert cands[0].model_version == CFG.model_id
    assert cands[0].prompt_version == CFG.prompt_version


def test_unavailable_drafter_invents_nothing() -> None:
    entries = _recurring("missing null check", "correctness", 3)
    assert propose(entries, CFG, _Drafter(available=False), top=10) == []


def test_exclude_keys_skips_already_promoted() -> None:
    entries = _recurring("missing null check", "correctness", 3)
    key = cluster_key("correctness", "missing null check")
    assert propose(entries, CFG, _Drafter(), top=10, exclude_keys={key}) == []
