"""Tests for the advisory commit-subject describer — ``core.commit_describer``.

# tested-by: tests/unit/test_commit_describer.py

The describer is advisory and fail-soft: it only ever decorates the human-readable
subject of an already-decided part. ``normalize_subject`` is the deterministic
boundary that turns a small model's loose output into a clean conventional-commit
line — the LLM writes only the prose tail; caliper owns the ``type(scope):`` prefix.
"""

from __future__ import annotations

from caliper.core.commit_describer import (
    DescribeRequest,
    NullDescriber,
    normalize_subject,
)


class TestNormalizeSubject:
    """The deterministic clean-up boundary (DPS-102) applied to every model output."""

    def test_basic_tail_is_appended_to_prefix(self) -> None:
        assert (
            normalize_subject("feat(infra): ", "add canary automation stacksets")
            == "feat(infra): add canary automation stacksets"
        )

    def test_only_the_first_line_is_kept(self) -> None:
        raw = "add canary automation\nfiles changed:\n  bin/app.ts\n  lib/x.ts"
        assert normalize_subject("feat(infra): ", raw) == "feat(infra): add canary automation"

    def test_echoed_conventional_prefix_is_stripped_not_doubled(self) -> None:
        # weak models echo the whole `type(scope): ...` back — never double the prefix
        assert (
            normalize_subject("feat(infra): ", "feat(infra): add canary automation")
            == "feat(infra): add canary automation"
        )
        assert normalize_subject("docs: ", "docs: update the readme") == "docs: update the readme"

    def test_leading_character_is_lowercased_but_acronyms_preserved(self) -> None:
        # imperative + lowercase first word, but SSM/CDK/AWS keep their case
        assert (
            normalize_subject("feat(business): ", "Implement SSM remediation scripts")
            == "feat(business): implement SSM remediation scripts"
        )

    def test_trailing_period_and_surrounding_quotes_removed(self) -> None:
        assert normalize_subject("feat(data): ", '"add migration."') == "feat(data): add migration"
        assert normalize_subject("feat(data): ", "`add migration`") == "feat(data): add migration"

    def test_length_capped_on_word_boundary(self) -> None:
        raw = "add an extraordinarily long winded description that rambles well beyond the limit"
        out = normalize_subject("feat(infra): ", raw, max_len=72)
        assert len(out) <= 72
        assert out.startswith("feat(infra): add an extraordinarily")
        assert not out.endswith(" ")  # no dangling partial word/space

    def test_empty_or_whitespace_tail_returns_empty_string(self) -> None:
        # signals the caller to fall back to the deterministic _peel_subject
        assert normalize_subject("feat(infra): ", "") == ""
        assert normalize_subject("feat(infra): ", "   \n  ") == ""
        assert normalize_subject("feat(infra): ", "feat(infra):") == ""

    def test_internal_whitespace_collapsed(self) -> None:
        assert (
            normalize_subject("feat(infra): ", "add   the   thing") == "feat(infra): add the thing"
        )

    def test_deterministic(self) -> None:
        # INVARIANT (Determinism): same inputs -> identical output, every call
        args = ("feat(infra): ", "Refactor   the AWS CDK stacks.")
        assert normalize_subject(*args) == normalize_subject(*args)


class TestNullDescriber:
    """The fail-soft default: no backend configured -> no subject, never raises."""

    def test_returns_none(self) -> None:
        req = DescribeRequest(prefix="feat(infra): ", bucket="infra", files=["bin/app.ts"])
        assert NullDescriber().describe(req) is None

    def test_satisfies_the_port_protocol(self) -> None:
        from caliper.core.commit_describer import CommitDescriberPort

        assert isinstance(NullDescriber(), CommitDescriberPort)
