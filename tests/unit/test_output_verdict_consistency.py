"""Every output must report the same verdict (#output-SoT regression guard).
# tested-by: tests/unit/test_output_verdict_consistency.py

The bug this prevents: the markdown PR-comment badge said BLOCKED while the CI header
said "approved" because they computed the verdict independently. Now the markdown
badge, the JSON report, and the SARIF property bag all derive from one summary; this
test fails if any path drifts.
"""

from __future__ import annotations

import json

import orjson

from caliper.core.json_report import render_json
from caliper.core.plugin import PluginResult
from caliper.core.renderer import render_comment
from caliper.core.review_summary import summarize_review
from caliper.core.sarif import to_sarif

_BADGE = {
    "blocked": "BLOCKED",
    "warnings": "PASS WITH WARNINGS",
    "incomplete": "INCOMPLETE",
    "clear": "ALL CLEAR",
}


def _scenario(name):
    f = lambda sev, file="src/app.py": {  # noqa: E731
        "id": "x",
        "severity": sev,
        "message": "m",
        "file": file,
    }
    return {
        "blocked": [PluginResult(plugin_name="trivy", category="dependency", findings=[f("high")])],
        "warnings": [
            PluginResult(plugin_name="complexity", category="quality", findings=[f("medium")])
        ],
        "incomplete": [
            PluginResult(plugin_name="osv-scanner", category="dependency", findings=[], error="x")
        ],
        "clear": [PluginResult(plugin_name="trivy", category="dependency", findings=[])],
    }[name]


import pytest


@pytest.mark.parametrize("scenario", ["blocked", "warnings", "incomplete", "clear"])
def test_markdown_json_sarif_agree(scenario):
    results = _scenario(scenario)
    summary = summarize_review(results)  # repo-wide (no diff scope)
    verdict = summary.verdict.value

    md = render_comment(results, repo="o/r", pr_num=1, title="t", verdict=verdict)
    json_doc = json.loads(render_json(results, summary=summary))
    sarif_doc = json.loads(orjson.dumps(to_sarif(results, summary=summary)))

    assert _BADGE[verdict] in md
    assert json_doc["verdict"] == verdict
    assert sarif_doc["properties"]["caliper_verdict"] == verdict


def test_counts_agree_json_sarif():
    results = _scenario("blocked")
    summary = summarize_review(results)
    json_doc = json.loads(render_json(results, summary=summary))
    sarif_doc = json.loads(orjson.dumps(to_sarif(results, summary=summary)))
    for key in ("error_count", "warning_count", "blocking_count"):
        assert json_doc[key] == sarif_doc["properties"][key] == getattr(summary, key)
