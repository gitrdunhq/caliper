"""Deterministic SARIF guards — tests that detect SARIF output bloat bugs.

# tested-by: tests/unit/test_deterministic_sarif_guards.py

These tests detect when SARIF output includes unnecessary full tool stdout,
causing bloated reports (issue #207).
"""

from __future__ import annotations

import json

import pytest

from caliper.core.plugin import PluginResult
from caliper.core.sarif import to_sarif

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)


# =============================================================================
# Issue #207: SARIF output includes full tool stdout bloating reports
# =============================================================================


@pytest.mark.xfail(
    reason="deterministic bug detector #207: SARIF output includes full tool stdout",
    strict=False,
)
def test_sarif_does_not_include_full_tool_stdout_in_summary() -> None:
    """Detect that SARIF output includes full tool stdout causing bloat.

    Bug #207: PluginResult.summary may contain full tool stdout output.
    When this gets serialized into SARIF, reports become bloated with
    unnecessary raw tool output that should be parsed into structured findings.

    The SARIF should only contain structured findings, not raw stdout.
    """
    # Simulate a plugin result with full stdout in summary (the bug pattern)
    large_stdout = """{
        \"results\": [{\"rule_id\": \"test\", \"message\": \"finding\"}],
        \"errors\": [],
        \"metadata\": {\"scan_time\": 123}
    }"""

    result = PluginResult(
        plugin_name="semgrep",
        findings=[{"rule_id": "python.flask.security.xss", "severity": "high", "message": "XSS"}],
        summary={
            "stdout": large_stdout,  # This is the bloat source
            "stderr": "",
            "exit_code": 0,
        },
    )

    sarif_doc = to_sarif([result])

    # Check if raw stdout appears anywhere in the SARIF output
    sarif_json = json.dumps(sarif_doc)

    # The bug: stdout content appears in the serialized SARIF
    if '"stdout":' in sarif_json or large_stdout[:50] in sarif_json:
        pytest.fail(
            "BUG DETECTED: SARIF output contains full tool stdout.\n"
            "Issue #207: Raw stdout is being included in SARIF reports, causing bloat.\n"
            "The summary.stdout field should not be serialized into SARIF output.\n"
            "Fix: Ensure to_sarif() only extracts structured findings, not raw tool output."
        )


@pytest.mark.xfail(
    reason="deterministic bug detector #207: SARIF output bloat from raw tool data",
    strict=False,
)
def test_sarif_size_bounded_relative_to_findings() -> None:
    """Detect SARIF bloat by verifying output size is proportional to findings count.

    Bug #207: If stdout/stderr are included, SARIF size grows with raw output
    rather than just with the number of structured findings.
    """
    # Create a result with minimal findings but large stdout
    large_stdout = "A" * 100000  # 100KB of raw output

    result = PluginResult(
        plugin_name="trivy",
        findings=[{"id": "CVE-2023-0001", "severity": "high", "message": "vuln"}],
        summary={
            "stdout": large_stdout,  # Large raw output that shouldn't be in SARIF
            "stderr": "",
        },
    )

    sarif_doc = to_sarif([result])
    sarif_json = json.dumps(sarif_doc)

    # A single finding should produce SARIF < 5KB
    # If it's > 50KB, there's definitely bloat from raw stdout
    size_kb = len(sarif_json) / 1024

    if size_kb > 50:
        pytest.fail(
            f"BUG DETECTED: SARIF output is bloated ({size_kb:.1f} KB).\n"
            "Issue #207: Single finding with large stdout produced oversized SARIF.\n"
            f"Expected: < 5KB, Got: {size_kb:.1f} KB\n"
            "Fix: Ensure raw stdout/stderr are not serialized into SARIF output."
        )


@pytest.mark.xfail(
    reason="deterministic bug detector #207: invocation data in SARIF runs",
    strict=False,
)
def test_sarif_runs_do_not_contain_invocation_stdout() -> None:
    """Detect if SARIF runs include invocation stdout/stderr fields.

    Bug #207: SARIF spec supports invocation objects that can capture stdout.
    If caliper adds invocation data to runs, it must not include full stdout.
    """
    result = PluginResult(
        plugin_name="osv-scanner",
        findings=[{"id": "GHSA-xxxx", "severity": "critical", "message": "vuln"}],
        summary={},
    )

    sarif_doc = to_sarif([result])

    # Check each run for invocation objects with stdout/stderr
    for run in sarif_doc.get("runs", []):
        # Check for invocations key (per SARIF spec)
        if "invocations" in run:
            for invocation in run["invocations"]:
                if "stdout" in invocation or "stderr" in invocation:
                    pytest.fail(
                        "BUG DETECTED: SARIF run contains invocation with stdout/stderr.\n"
                        "Issue #207: Full tool output is being included in SARIF invocations.\n"
                        "Fix: Remove stdout/stderr from SARIF invocation objects."
                    )

        # Also check tool property for any stdout contamination
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        for key in driver:
            if "stdout" in key.lower() or "stderr" in key.lower():
                pytest.fail(
                    f"BUG DETECTED: SARIF tool.driver contains {key} field.\n"
                    "Issue #207: Raw tool output should not be in SARIF tool metadata."
                )


@pytest.mark.xfail(
    reason="deterministic bug detector #207: findings metadata contains raw output",
    strict=False,
)
def test_sarif_findings_do_not_contain_raw_tool_output() -> None:
    """Detect if individual findings contain raw stdout in metadata.

    Bug #207: Findings may have metadata fields that include raw tool output.
    These should be stripped before SARIF serialization.
    """
    result = PluginResult(
        plugin_name="semgrep",
        findings=[
            {
                "rule_id": "python.lang.security",
                "severity": "high",
                "message": "security issue",
                "metadata": {
                    "raw_stdout": "A" * 5000,  # Simulated raw output in metadata
                    "scan_output": "B" * 5000,
                },
            }
        ],
        summary={},
    )

    sarif_doc = to_sarif([result])
    sarif_json = json.dumps(sarif_doc)

    # Check for raw output patterns in the serialized SARIF
    if "raw_stdout" in sarif_json or "scan_output" in sarif_json:
        pytest.fail(
            "BUG DETECTED: SARIF findings contain raw tool output in metadata.\n"
            "Issue #207: Finding metadata fields with raw stdout are being serialized.\n"
            "Fix: Strip metadata fields containing raw output before SARIF conversion."
        )
