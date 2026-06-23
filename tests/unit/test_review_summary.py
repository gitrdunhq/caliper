"""The review-output single source of truth (#output-SoT).
# tested-by: tests/unit/test_review_summary.py

DPS-12 domains: Determinism (same results+scope -> same summary, order-independent),
Integrity (the verdict reflects exactly the blocking rule — no drift between outputs),
Boundedness (counts equal the findings present).
"""

from __future__ import annotations

from caliper.core.plugin import PluginResult
from caliper.core.review_summary import ReviewVerdict, summarize_review


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
