"""Tests for the Review runner — cache reproducibility + fail-soft LLM.

# tested-by: tests/unit/test_inspect_runner.py

Property domains (DPS-12):
  Idempotency  INVARIANT  same part hash -> cached claims, no second port call
  Reversibility/availability  fail-soft: unavailable LLM -> skipped, no invented claims
"""

from __future__ import annotations

# Register the isolated backends (the CLI does this in production; core may not).
import caliper.plugins._inspect_llm  # noqa: E402,F401
from caliper.core.inspect_cache import InspectCache
from caliper.core.inspect_runner import render_prompt, run_review
from caliper.core.inspect_view import PartView
from caliper.core.llm_port import LLMResult, LLMReview
from caliper.core.models import ChangeType, Kerf, Part
from caliper.core.repo_config import InspectConfig


def _part(files=("a.py",)) -> Part:
    return Part(
        id="part-x",
        files=list(files),
        bucket=ChangeType.logic,
        size=10,
        opened_by=Kerf(fired_rule="x"),
    )


class CountingBackend:
    def __init__(self, claims: list[dict], available: bool = True) -> None:
        self.claims = claims
        self.available = available
        self.calls = 0

    def review(self, review: LLMReview) -> LLMResult:
        self.calls += 1
        return LLMResult(available=self.available, raw_claims=self.claims, note="")


def test_no_llm_disabled_skips() -> None:
    out = run_review(_part(), PartView(), "", InspectConfig(), enabled=False)
    assert out.skipped_llm is True
    assert out.raw_claims == []


def test_bucket_without_llm_skips() -> None:
    part = Part(
        id="g",
        files=["x.lock"],
        bucket=ChangeType.generated,
        size=1,
        opened_by=Kerf(fired_rule="R1"),
    )
    out = run_review(part, PartView(), "", InspectConfig())
    assert out.skipped_llm is True


def test_unavailable_backend_is_fail_soft_no_invented_claims() -> None:
    backend = CountingBackend([], available=False)
    out = run_review(_part(), PartView(changed_bytes=b"x"), "", InspectConfig(), backend=backend)
    assert out.skipped_llm is True
    assert out.raw_claims == []


def test_cache_hit_returns_identical_claims_without_calling_port(tmp_path) -> None:
    claims = [
        {
            "file": "a.py",
            "line_range": [1, 2],
            "severity": "minor",
            "category": "style",
            "assertion": "x",
        }
    ]
    backend = CountingBackend(claims)
    cache = InspectCache(tmp_path / "c")
    view = PartView(changed_lines={"a.py": {1, 2}}, changed_bytes=b"abc")

    first = run_review(_part(), view, "", InspectConfig(), cache=cache, backend=backend)
    assert first.raw_claims == claims and backend.calls == 1

    # same part hash -> cache hit, port NOT called again
    second = run_review(_part(), view, "", InspectConfig(), cache=cache, backend=backend)
    assert second.raw_claims == claims and backend.calls == 1


def test_changed_part_misses_cache(tmp_path) -> None:
    claims = [
        {
            "file": "a.py",
            "line_range": [1, 1],
            "severity": "nit",
            "category": "style",
            "assertion": "x",
        }
    ]
    backend = CountingBackend(claims)
    cache = InspectCache(tmp_path / "c")

    run_review(_part(), PartView(diff_text="v1"), "", InspectConfig(), cache=cache, backend=backend)
    assert backend.calls == 1
    # different rendered prompt (diff text) -> different key -> miss -> port called again
    run_review(_part(), PartView(diff_text="v2"), "", InspectConfig(), cache=cache, backend=backend)
    assert backend.calls == 2


def test_null_backend_resolves_and_is_unavailable() -> None:
    """The default 'null' backend resolves from the isolated registry and fails soft."""
    out = run_review(_part(), PartView(changed_bytes=b"x"), "", InspectConfig(backend="null"))
    assert out.skipped_llm is True
    assert out.raw_claims == []


def test_render_prompt_puts_pr_context_first_and_emits_schema() -> None:
    """PR/issue prose is presented before the diff, and the claim schema (with the
    verbatim anchor_quote contract) is in the prompt so a real backend can comply."""
    view = PartView(diff_text="@@ -1 +1 @@\n+x = 1")
    prompt = render_prompt(
        _part(), view, "lower stuff", InspectConfig(), pr_context="Fixes the auth bug."
    )
    assert "anchor_quote" in prompt
    assert "Change description (read first)" in prompt
    # prose appears before the changed-hunks section
    assert prompt.index("Change description") < prompt.index("Part under review")


def test_pr_context_change_misses_cache(tmp_path) -> None:
    """Different PR context -> different rendered prompt -> different key -> port re-called."""
    claims = [
        {
            "file": "a.py",
            "line_range": [1, 1],
            "severity": "nit",
            "category": "style",
            "assertion": "x",
        }
    ]
    backend = CountingBackend(claims)
    cache = InspectCache(tmp_path / "c")
    view = PartView(diff_text="d")
    run_review(_part(), view, "", InspectConfig(), pr_context="ctx-1", cache=cache, backend=backend)
    run_review(_part(), view, "", InspectConfig(), pr_context="ctx-2", cache=cache, backend=backend)
    assert backend.calls == 2
