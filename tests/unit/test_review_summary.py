"""The review-output single source of truth (#output-SoT).
# tested-by: tests/unit/test_review_summary.py

DPS-12 domains: Determinism (same results+scope -> same summary, order-independent),
Integrity (the verdict reflects exactly the blocking rule — no drift between outputs),
Boundedness (counts equal the findings present).
"""

from __future__ import annotations

import pytest

from caliper.core.plugin import PluginResult
from caliper.core.review_summary import ReviewVerdict, build_review_summary, summarize_review


def _res(name, category, findings, *, error=None, status=None):
    summary = {"status": status} if status else {}
    return PluginResult(
        plugin_name=name, category=category, findings=findings, summary=summary, error=error
    )


def _f(severity, file="src/app.py"):
    return {"id": "x", "severity": severity, "message": "m", "file": file}


def test_clean_is_clear():
    assert summarize_review([_res("trivy", "dependency", [])]).verdict == ReviewVerdict.clear


def test_skipped_only_is_clear_not_warnings():
    s = summarize_review([_res("typos", "quality", [], status="skipped")])
    assert s.verdict == ReviewVerdict.clear
    assert s.skipped_count == 1


def test_crashed_is_incomplete():
    s = summarize_review([_res("osv-scanner", "dependency", [], error="boom")])
    assert s.verdict == ReviewVerdict.incomplete
    assert s.crashed_count == 1


def test_quality_high_never_blocks():
    s = summarize_review([_res("complexity", "quality", [_f("high")])])
    assert s.verdict == ReviewVerdict.warnings
    assert s.blocking_count == 0


def test_security_high_blocks_when_repo_wide():
    s = summarize_review([_res("trivy", "dependency", [_f("high", "requirements.txt")])])
    assert s.verdict == ReviewVerdict.blocked
    assert s.blocking_count == 1


def test_diff_scoped_blocks_only_pr_introduced():
    results = [_res("trivy", "dependency", [_f("high", "requirements.txt")])]
    # PR did not touch requirements.txt -> advisory, not blocking
    advisory = summarize_review(results, changed_files={"README.md"})
    assert advisory.verdict == ReviewVerdict.warnings
    assert advisory.blocking_count == 0
    assert advisory.error_count == 1  # still surfaced
    # PR touched requirements.txt -> blocking
    gated = summarize_review(results, changed_files={"requirements.txt"})
    assert gated.verdict == ReviewVerdict.blocked
    assert gated.blocking_count == 1


def test_counts_match_findings():
    s = summarize_review(
        [_res("semgrep", "code", [_f("critical"), _f("medium"), _f("low"), _f("info")])]
    )
    assert (s.error_count, s.warning_count, s.note_count) == (1, 1, 2)


class TestProperties:
    def test_determinism_order_independent(self):
        a = _res("trivy", "dependency", [_f("high", "a.txt")])
        b = _res("complexity", "quality", [_f("medium")])
        c = _res("typos", "quality", [], status="skipped")
        s1 = summarize_review([a, b, c], changed_files={"a.txt"})
        s2 = summarize_review([c, b, a], changed_files={"a.txt"})
        assert s1 == s2  # Determinism: order does not matter

    def test_path_normalization_is_stable(self):
        results = [_res("trivy", "dependency", [_f("high", "src/x.py")])]
        # "./src/x.py" vs "src/x.py" must attribute identically
        assert (
            summarize_review(results, changed_files={"./src/x.py"}).verdict == ReviewVerdict.blocked
        )


# --- task-001: score/grade consistency + verdict wording -------------------------


def _complexity_result(*, critical_count: int, maintainability_index: str) -> PluginResult:
    """A 'quality' category complexity result with heavy critical findings.

    Weighted critical findings drive quality_score toward 0, while each finding
    still carries a high maintainability_index — the two signals used to disagree
    because they were computed independently.
    """
    findings = [
        {
            "id": f"cx{i}",
            "severity": "critical",
            "message": "function too complex",
            "file": "src/app.py",
            "maintainability_index": maintainability_index,
        }
        for i in range(critical_count)
    ]
    return PluginResult(
        plugin_name="complexity",
        category="quality",
        findings=findings,
        summary={"avg_cyclomatic_complexity": 5, "high_complexity_count": critical_count},
    )


def test_ac1_quality_score_zero_never_pairs_with_grade_a():
    # 20 critical quality findings (weight 10 each) drives quality_score to 0,
    # while a high maintainability_index ("A (25.0)") would previously still
    # yield maintainability_grade == "A" if computed independently.
    result = _complexity_result(critical_count=20, maintainability_index="A (25.0)")
    summary = build_review_summary([result])
    assert summary.quality_score == 0
    assert not (summary.quality_score == 0 and summary.maintainability_grade == "A")
    assert summary.maintainability_grade != "A"


def test_ac2_blocked_word_absent_when_policy_verdict_not_reject():
    result = _res("trivy", "dependency", [_f("high", "requirements.txt")])
    summary = build_review_summary([result], policy_verdict="approve")
    assert "blocked" not in summary.verdict_text.lower()


def test_ac2_blocked_word_present_when_policy_verdict_is_reject():
    result = _res("trivy", "dependency", [_f("high", "requirements.txt")])
    summary = build_review_summary([result], policy_verdict="reject")
    assert "blocked" in summary.verdict_text.lower()


def test_ac3_incomplete_plugins_listed_with_reasons():
    ok = _res("trivy", "dependency", [])
    timed_out = _res("osv-scanner", "dependency", [], status="timeout")
    not_installed = _res("scancode", "dependency", [], status="not_installed")
    crashed = _res("semgrep", "code", [], error="boom")

    summary = build_review_summary([ok, timed_out, not_installed, crashed])

    assert "incomplete" in summary.verdict_text.lower()
    assert ("osv-scanner", "timeout") in summary.incomplete_plugins
    assert ("scancode", "not_installed") in summary.incomplete_plugins
    assert ("semgrep", "crashed") in summary.incomplete_plugins
    assert len(summary.incomplete_plugins) == 3


def test_ac4_no_valueerror_for_fully_successful_scan():
    result = _res("trivy", "dependency", [])
    try:
        summary = build_review_summary([result])
    except ValueError as exc:  # pragma: no cover - documents the failure mode
        pytest.fail(f"ValueError raised for a fully-successful scan: {exc}")
    assert summary.incomplete_plugins == []
