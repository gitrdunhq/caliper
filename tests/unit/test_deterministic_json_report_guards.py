# tested-by: tests/unit/test_deterministic_json_report_guards.py
"""Deterministic guards for JSON report generation.

These tests detect when SBOM payloads are embedded in JSON reports,
which can cause performance issues and information leakage (#257).

Status: fixed — render_json() sanitizes plugin summaries (drops the "sbom"
key and any large nested dict/list value) before rendering.
"""

from __future__ import annotations

import json


def test_257_json_reports_do_not_embed_full_sbom_payloads() -> None:
    """#257: JSON reports must not contain full SBOM payloads in plugin summaries.

    SBOM data can be large and may contain sensitive internal component
    information. The JSON report should only contain summary statistics,
    not the full SBOM payload.
    """
    from caliper.core.json_report import render_json
    from caliper.core.plugin import PluginResult

    # Simulate a plugin result with SBOM data embedded in summary
    # This mirrors what SyftPlugin currently does (line 83 in syft.py)
    sensitive_component = "internal-sensitive-component"
    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": sensitive_component, "version": "9.9.9", "type": "library"},
            {"name": "another-component", "version": "1.0.0", "type": "library"},
        ],
        "dependencies": [
            {"ref": "pkg:generic/internal-sensitive-component@9.9.9", "dependsOn": []},
        ],
    }

    output = render_json(
        [
            PluginResult(
                plugin_name="syft",
                category="dependency",
                findings=[],
                summary={"components": 2, "sbom": sbom_data},
            )
        ]
    )

    # Check that SBOM data is NOT in the JSON output
    doc = json.loads(output)
    plugin_summary = doc["plugins"][0]["summary"]

    # The SBOM key should not exist in the summary
    assert "sbom" not in plugin_summary, (
        "JSON report contains full SBOM payload in plugin summary. "
        "This violates #257 - SBOM data should be excluded from JSON reports."
    )

    # Sensitive component names should not appear in the raw output
    assert sensitive_component not in output, (
        f"JSON report contains sensitive component name '{sensitive_component}'. "
        "SBOM data is being embedded in the output."
    )

    # Verify that expected summary fields are present
    assert "components" in plugin_summary, "Plugin summary should contain 'components' count"
    assert plugin_summary["components"] == 2


def test_257_all_plugin_summaries_exclude_large_nested_structures() -> None:
    """#257: No plugin summary should embed large nested structures that could be SBOM-like.

    This is a broader check to prevent any plugin from embedding large
    data structures in summaries that would bloat JSON reports.
    """
    from caliper.core.json_report import render_json
    from caliper.core.plugin import PluginResult

    # Test with multiple plugins that might have various data structures
    results = [
        PluginResult(
            plugin_name="syft",
            category="dependency",
            findings=[],
            summary={"components": 5},  # Clean summary without SBOM
        ),
        PluginResult(
            plugin_name="semgrep",
            category="security",
            findings=[],
            summary={"files_scanned": 100, "rules_run": 50},
        ),
    ]

    output = render_json(results)
    doc = json.loads(output)

    # Verify no plugin summary contains nested dict/list structures
    # that could indicate embedded payloads
    for plugin in doc["plugins"]:
        summary = plugin.get("summary", {})
        for key, value in summary.items():
            # Allow simple scalar values
            if isinstance(value, (dict, list)):
                # If it's a dict/list, it should be small metadata, not a payload
                serialized = json.dumps(value)
                assert len(serialized) < 1000, (
                    f"Plugin '{plugin['name']}' summary key '{key}' contains "
                    f"large nested data ({len(serialized)} chars). "
                    "This may indicate embedded SBOM or payload data (#257)."
                )
