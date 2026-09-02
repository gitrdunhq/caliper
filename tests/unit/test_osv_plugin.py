"""Tests for OSV Scanner plugin.
# tested-by: tests/unit/test_osv_plugin.py
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from caliper.core.plugin import PluginCategory
from caliper.core.plugin_registry import _normalize_findings
from caliper.plugins.osv_scanner import OsvScannerPlugin

OSV_RESPONSE = {
    "results": [
        {
            "packages": [
                {
                    "package": {
                        "name": "requests",
                        "version": "2.25.1",
                        "ecosystem": "PyPI",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-9hjg-9r4m-mvj7",
                            "aliases": ["CVE-2024-47081"],
                            "summary": "Requests proxy leak",
                            "database_specific": {"severity": "MODERATE"},
                            "severity": [],
                        },
                        {
                            "id": "GHSA-x4qr-2fvf-3mr5",
                            "aliases": ["CVE-2023-0286"],
                            "summary": "Vulnerable OpenSSL",
                            "database_specific": {"severity": "HIGH"},
                            "severity": [{"score": 7.5}],
                        },
                    ],
                }
            ]
        }
    ]
}


class TestOsvPlugin:
    def test_name_and_category(self):
        p = OsvScannerPlugin()
        assert p.name == "osv-scanner"
        assert p.category == PluginCategory.dependency

    def test_can_run_with_manifest(self):
        p = OsvScannerPlugin()
        assert p.can_run(["requirements.txt"], Path(".")) is True
        assert p.can_run(["package.json"], Path(".")) is True
        assert p.can_run(["go.mod"], Path(".")) is True

    def test_can_run_without_manifest(self):
        p = OsvScannerPlugin()
        assert p.can_run(["app.py"], Path(".")) is False
        assert p.can_run(["main.tf"], Path(".")) is False

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_extracts_findings_with_cve_ids(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert result.error == ""
        assert len(result.findings) == 2
        ids = [f["id"] for f in result.findings]
        assert "CVE-2024-47081" in ids
        assert "CVE-2023-0286" in ids

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_severity_mapping(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        by_id = {f["id"]: f for f in result.findings}
        assert by_id["CVE-2024-47081"]["severity"] == "medium"
        assert by_id["CVE-2023-0286"]["severity"] == "high"

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_advisory_urls(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        by_id = {f["id"]: f for f in result.findings}
        assert "nvd.nist.gov" in by_id["CVE-2023-0286"]["url"]
        assert "nvd.nist.gov" in by_id["CVE-2024-47081"]["url"]

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_ghsa_preserved(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        by_id = {f["id"]: f for f in result.findings}
        assert by_id["CVE-2023-0286"]["ghsa"] == "GHSA-x4qr-2fvf-3mr5"

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_summary_counts(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert result.summary["total"] == 2
        assert result.summary["critical_high"] == 1
        assert result.summary["medium"] == 1

    @patch(
        "caliper.plugins.osv_scanner.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_binary_not_found(self, _mock):
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert "not installed" in result.error

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_clean_repo_no_findings(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        assert result.error == ""
        assert result.findings == []

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_render_critical(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        md = p.render(result)
        assert "Critical/High" in md
        assert "CVE-2023-0286" in md
        assert "nvd.nist.gov" in md

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_render_after_registry_normalization(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE)
        p = OsvScannerPlugin()
        result = p.run(["requirements.txt"], Path("."))
        result = replace(result, findings=_normalize_findings(result.findings))

        md = p.render(result)

        assert "Critical/High" in md
        assert "CVE-2023-0286" in md
        assert "Vulnerable OpenSSL" in md

    def test_render_error(self):
        from caliper.core.plugin import PluginResult

        p = OsvScannerPlugin()
        result = PluginResult(
            plugin_name="osv-scanner",
            error="not installed",
        )
        md = p.render(result)
        assert "not installed" in md

    def test_render_empty(self):
        from caliper.core.plugin import PluginResult

        p = OsvScannerPlugin()
        result = PluginResult(plugin_name="osv-scanner")
        md = p.render(result)
        assert md == ""


def _make_osv_data(n: int) -> dict:
    """Build an OSV-format dict with n findings (one vuln per package)."""
    return {
        "results": [
            {
                "packages": [
                    {
                        "package": {
                            "name": f"pkg-{i}",
                            "version": "1.0.0",
                            "ecosystem": "pip",
                        },
                        "vulnerabilities": [
                            {
                                "id": f"GHSA-xxxx-yyyy-{i:04d}",
                                "summary": f"Vulnerability {i}",
                                "severity": [{"score": "5.0"}],
                                "database_specific": {"severity": "MEDIUM"},
                                "aliases": [],
                            }
                        ],
                    }
                    for i in range(n)
                ]
            }
        ]
    }


class TestOsvScannerFindingsCap:
    """_extract_findings must cap the result at MAX_FINDINGS to prevent OOM."""

    def test_findings_capped_at_1000(self):
        plugin = OsvScannerPlugin()
        findings = plugin._extract_findings(_make_osv_data(1500))
        assert len(findings) == 1000, f"Expected 1000 findings (MAX_FINDINGS), got {len(findings)}"

    def test_findings_below_cap_not_truncated(self):
        plugin = OsvScannerPlugin()
        findings = plugin._extract_findings(_make_osv_data(10))
        assert len(findings) == 10

    def test_findings_exactly_at_cap_not_truncated(self):
        plugin = OsvScannerPlugin()
        findings = plugin._extract_findings(_make_osv_data(1000))
        assert len(findings) == 1000


# ---------------------------------------------------------------------------
# Regression P16-4 — _resolve_severity must take the MAX across all signals
# ---------------------------------------------------------------------------


class TestResolveSeverityMaxRegression:
    """Regression for P16-4: _resolve_severity previously returned the LAST
    candidate rather than the highest severity.  A CVSS 5.0 (medium) following
    a database_specific 'HIGH' would overwrite high with medium."""

    def setup_method(self):
        self.plugin = OsvScannerPlugin()

    def test_database_specific_high_beats_cvss_medium(self):
        """database_specific HIGH must win over a CVSS 5.0 (medium) signal.

        Regression for P16-4: before the fix, the last candidate won; if CVSS
        came after database_specific the severity was downgraded to medium."""
        vuln = {
            "database_specific": {"severity": "HIGH"},
            "severity": [{"score": 5.0}],  # CVSS 5.0 → medium
        }
        result = self.plugin._resolve_severity(vuln)
        assert result == "high", (
            f"database_specific HIGH must not be downgraded by a CVSS 5.0 (medium); "
            f"got {result!r}"
        )

    def test_cvss_critical_beats_database_specific_high(self):
        """CVSS 9.5 (critical) must beat database_specific HIGH."""
        vuln = {
            "database_specific": {"severity": "HIGH"},
            "severity": [{"score": 9.5}],  # CVSS 9.5 → critical
        }
        result = self.plugin._resolve_severity(vuln)
        assert (
            result == "critical"
        ), f"CVSS 9.5 must produce critical even when database_specific=HIGH; got {result!r}"

    def test_no_severity_signals_returns_info(self):
        """A vuln with no severity signals must return 'info' (the floor)."""
        vuln: dict = {"database_specific": {}, "severity": []}
        result = self.plugin._resolve_severity(vuln)
        assert result == "info"

    def test_multiple_cvss_scores_highest_wins(self):
        """When multiple CVSS scores are present, the highest must win."""
        vuln = {
            "database_specific": {},
            "severity": [{"score": 4.5}, {"score": 7.5}, {"score": 3.0}],
        }
        result = self.plugin._resolve_severity(vuln)
        assert result == "high", f"Multiple CVSS scores — 7.5 is highest (high), got {result!r}"


# ---------------------------------------------------------------------------
# task-009 — osv-scanner findings carry file/line from source.path and
# dependency_kind metadata
# ---------------------------------------------------------------------------

# Fixture: an osv-scanner "lockfile" result carrying a `source.path` (as
# osv-scanner reports it against the scanned root) and a vulnerable package
# whose `package` sub-object carries an integer `line` — the vulnerable
# dependency's line number in the manifest.
OSV_RESPONSE_WITH_SOURCE_AND_LINE = {
    "results": [
        {
            "source": {"path": "/workspace/requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "requests",
                        "version": "2.25.1",
                        "ecosystem": "PyPI",
                        "line": 7,
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-9hjg-9r4m-mvj7",
                            "aliases": ["CVE-2024-47081"],
                            "summary": "Requests proxy leak",
                            "database_specific": {"severity": "MODERATE"},
                            "severity": [],
                        }
                    ],
                }
            ],
        }
    ]
}

# Same shape but the vulnerable package carries no `line` — osv-scanner
# doesn't always have a line number to report (e.g. ecosystem lockfiles
# without source-mapping support).
OSV_RESPONSE_WITH_SOURCE_NO_LINE = {
    "results": [
        {
            "source": {"path": "/workspace/requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "requests",
                        "version": "2.25.1",
                        "ecosystem": "PyPI",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-9hjg-9r4m-mvj7",
                            "aliases": ["CVE-2024-47081"],
                            "summary": "Requests proxy leak",
                            "database_specific": {"severity": "MODERATE"},
                            "severity": [],
                        }
                    ],
                }
            ],
        }
    ]
}


class TestTask009AC1:
    """AC1: parsing an osv-scanner result with results[0].source.path set
    produces a Finding with file= the relative manifest path (no leading
    /workspace)."""

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_ac1_parsing_an_osv_scanner_json_result_with_results_0_source_pat(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE_WITH_SOURCE_AND_LINE)
        p = OsvScannerPlugin()

        result = p.run(["requirements.txt"], Path("/workspace"))

        assert result.error == ""
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert (
            finding["file"] == "requirements.txt"
        ), f"expected relative path 'requirements.txt' with no leading /workspace, got {finding.get('file')!r}"
        assert not finding["file"].startswith("/workspace")


class TestTask009AC2:
    """AC2: Finding.line is set from the OSV result's line number when
    present, and is None when the OSV result carries no line number."""

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_ac2_when_the_osv_result_includes_a_line_number_for_the_vulnerabl(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE_WITH_SOURCE_AND_LINE)
        p = OsvScannerPlugin()

        result = p.run(["requirements.txt"], Path("/workspace"))

        assert len(result.findings) == 1
        assert result.findings[0]["line"] == 7

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_ac2_line_is_none_when_osv_result_has_no_line_number(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE_WITH_SOURCE_NO_LINE)
        p = OsvScannerPlugin()

        result = p.run(["requirements.txt"], Path("/workspace"))

        assert len(result.findings) == 1
        assert result.findings[0]["line"] is None


class TestTask009AC3:
    """AC3: every osv-scanner Finding has metadata['dependency_kind'] in
    {'direct', 'transitive', 'unknown'}, computed by calling
    manifest_discovery.classify_dependency_kind."""

    @patch("caliper.plugins.osv_scanner.classify_dependency_kind")
    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_ac3_every_osv_scanner_finding_has_metadata_dependency_kind_in_di(
        self, mock_run, mock_classify
    ):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE_WITH_SOURCE_AND_LINE)
        mock_classify.return_value = "direct"
        p = OsvScannerPlugin()

        result = p.run(["requirements.txt"], Path("/workspace"))

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert "metadata" in finding, "Finding must carry a metadata dict"
        assert finding["metadata"]["dependency_kind"] == "direct"
        mock_classify.assert_called_once()

    @patch("caliper.plugins.osv_scanner.classify_dependency_kind")
    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_ac3_dependency_kind_is_always_one_of_direct_transitive_unknown(
        self, mock_run, mock_classify
    ):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = json.dumps(OSV_RESPONSE_WITH_SOURCE_NO_LINE)
        mock_classify.return_value = "unknown"
        p = OsvScannerPlugin()

        result = p.run(["requirements.txt"], Path("/workspace"))

        assert len(result.findings) == 1
        assert result.findings[0]["metadata"]["dependency_kind"] in {
            "direct",
            "transitive",
            "unknown",
        }
