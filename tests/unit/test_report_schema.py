"""Tests for the published JSON report schema (#389).
# tested-by: tests/unit/test_report_schema.py
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from caliper.core.plugin import PluginFinding, PluginResult

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_result(
    name: str = "trivy",
    findings: list | None = None,
    error: str = "",
    skip_reason: str = "",
    skip_remediation: str = "",
    category: str = "dependency",
) -> PluginResult:
    return PluginResult(
        plugin_name=name,
        findings=findings or [],
        summary={"status": "skipped"} if skip_reason else {},
        error=error,
        category=category,
        skip_reason=skip_reason,
        skip_remediation=skip_remediation,
    )


class TestReportModel:
    def test_render_json_validates_against_model(self) -> None:
        """The emitted JSON parses into the published ReportModel."""
        from caliper.core.json_report import render_json
        from caliper.core.report_schema import ReportModel

        results = [
            _make_result("trivy", findings=[{"id": "CVE-2025-1", "severity": "critical"}]),
            _make_result("osv-scanner", skip_reason="Binary not installed"),
            _make_result("semgrep", error="TIMEOUT after 60s", category="code"),
        ]
        output = render_json(results, repo="acme/widgets", commit="abc123")
        report = ReportModel.model_validate(json.loads(output))
        assert report.repo == "acme/widgets"
        assert report.commit == "abc123"
        assert report.total_plugins == 3
        assert [p.name for p in report.plugins] == ["trivy", "osv-scanner", "semgrep"]
        assert report.plugins[0].status == "ran"
        assert report.plugins[1].status == "skipped"
        assert report.plugins[2].status == "error"

    def test_round_trip_is_lossless(self) -> None:
        """Emit -> validate -> dump reproduces the exact same document."""
        from caliper.core.json_report import render_json
        from caliper.core.report_schema import ReportModel

        results = [
            _make_result("trivy", findings=[{"id": "CVE-2025-1", "severity": "high"}]),
            _make_result("gitleaks", category="supply_chain"),
        ]
        parsed = json.loads(render_json(results, repo="r", commit="c"))
        report = ReportModel.model_validate(parsed)
        assert report.model_dump(mode="json") == parsed

    def test_schema_version_pinned(self) -> None:
        from caliper.core.json_report import render_json
        from caliper.core.report_schema import REPORT_SCHEMA_VERSION, ReportModel

        assert REPORT_SCHEMA_VERSION == "1.0"
        output = json.loads(render_json([_make_result()]))
        assert output["schema_version"] == REPORT_SCHEMA_VERSION
        assert ReportModel.model_validate(output).schema_version == REPORT_SCHEMA_VERSION

    def test_dataclass_findings_round_trip(self) -> None:
        """PluginFinding dataclasses serialize with metadata nested, as before."""
        from caliper.core.json_report import render_json

        finding = PluginFinding(
            id="CVE-2025-9",
            severity="high",
            message="boom",
            metadata={"cwe": "CWE-79"},
        )
        output = json.loads(render_json([_make_result("trivy", findings=[finding])]))
        emitted = output["plugins"][0]["findings"][0]
        assert emitted["id"] == "CVE-2025-9"
        assert emitted["severity"] == "high"
        assert emitted["metadata"] == {"cwe": "CWE-79"}

    def test_exported_from_package_root(self) -> None:
        """Consumers import the models from the caliper package root."""
        from caliper import (  # noqa: F401
            REPORT_SCHEMA_VERSION,
            FindingModel,
            PluginReportModel,
            ReportModel,
        )


class TestFindingModel:
    def test_parses_sparse_finding_and_preserves_extras(self) -> None:
        from caliper.core.report_schema import FindingModel

        finding = FindingModel.model_validate({"id": "CVE-1", "severity": "low", "cwe": "CWE-22"})
        assert finding.id == "CVE-1"
        assert finding.severity == "low"
        assert finding.model_dump()["cwe"] == "CWE-22"

    def test_parses_full_to_dict_shape(self) -> None:
        from caliper.core.report_schema import FindingModel

        raw = PluginFinding(id="X", severity="info", message="m").to_dict()
        finding = FindingModel.model_validate(raw)
        assert finding.message == "m"


class TestSchemaCommand:
    def test_schema_command_prints_json_schema(self) -> None:
        from caliper.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["schema"])
        assert result.exit_code == 0
        schema = json.loads(result.output)
        assert "schema_version" in schema["properties"]
        assert "plugins" in schema["properties"]

    def test_schema_command_writes_output_file(self, tmp_path) -> None:
        from caliper.cli.main import cli

        out = tmp_path / "report-schema.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["schema", "--output", str(out)])
        assert result.exit_code == 0
        schema = json.loads(out.read_text())
        assert "schema_version" in schema["properties"]


class TestPublishedSchemaArtifact:
    def test_checked_in_schema_matches_model(self) -> None:
        """docs/schema/report-v1.0.json stays in sync with the Pydantic model.

        Regenerate with: caliper schema --output docs/schema/report-v1.0.json
        """
        from caliper.core.report_schema import report_json_schema

        artifact = _REPO_ROOT / "docs" / "schema" / "report-v1.0.json"
        assert artifact.is_file(), f"missing published schema artifact: {artifact}"
        assert json.loads(artifact.read_text()) == report_json_schema()


class TestFindingMetadataDbFields:
    """task-017: JSON report schema gains optional db_version/db_updated_at (#task-017)."""

    def test_finding_model_declares_optional_db_updated_at_and_db_version(self) -> None:
        """AC1: FindingModel's schema declares db_updated_at/db_version as optional.

        Neither key belongs in the model's ``required`` list, and both must
        default to the empty string when omitted — matching every other
        optional scalar field already on FindingModel (e.g. ``rule_id``).
        """
        from caliper.core.report_schema import FindingModel

        schema = FindingModel.model_json_schema()
        required = schema.get("required", [])
        assert (
            "db_updated_at" in schema["properties"]
        ), "FindingModel schema is missing the optional 'db_updated_at' property"
        assert (
            "db_version" in schema["properties"]
        ), "FindingModel schema is missing the optional 'db_version' property"
        assert "db_updated_at" not in required
        assert "db_version" not in required

        finding = FindingModel.model_validate({"id": "CVE-1", "severity": "low"})
        assert finding.db_updated_at == ""
        assert finding.db_version == ""

    def test_checked_in_schema_publishes_db_updated_at_and_db_version(self) -> None:
        """AC1: the checked-in JSON schema artifact also carries the new fields.

        docs/schema/report-v1.0.json is the published, consumer-facing
        artifact — somewhere in it (however the finding/metadata schema is
        nested) both new property names must be declared as schema
        properties, not just present on the in-process Pydantic model.
        """

        def _find_property_names(node: object) -> set[str]:
            found: set[str] = set()
            if isinstance(node, dict):
                props = node.get("properties")
                if isinstance(props, dict):
                    found.update(props.keys())
                for value in node.values():
                    found |= _find_property_names(value)
            elif isinstance(node, list):
                for item in node:
                    found |= _find_property_names(item)
            return found

        artifact = _REPO_ROOT / "docs" / "schema" / "report-v1.0.json"
        published = json.loads(artifact.read_text())
        all_property_names = _find_property_names(published)
        assert (
            "db_updated_at" in all_property_names
        ), "docs/schema/report-v1.0.json declares no 'db_updated_at' property anywhere"
        assert (
            "db_version" in all_property_names
        ), "docs/schema/report-v1.0.json declares no 'db_version' property anywhere"

    def test_render_json_serializes_db_version_and_db_updated_at_when_present(self) -> None:
        """AC2: render_json emits metadata.db_version/db_updated_at when set on a finding."""
        from caliper.core.json_report import render_json

        finding = PluginFinding(
            id="CVE-2025-42",
            severity="high",
            message="stale db entry",
            metadata={"db_version": "2026-08-15", "db_updated_at": "2026-08-15T00:00:00Z"},
        )
        output = json.loads(render_json([_make_result("trivy", findings=[finding])]))
        emitted_metadata = output["plugins"][0]["findings"][0]["metadata"]
        assert emitted_metadata["db_version"] == "2026-08-15"
        assert emitted_metadata["db_updated_at"] == "2026-08-15T00:00:00Z"

        # The typed FindingModel used for downstream access must declare
        # these as real (non-extra) fields — not merely tolerate them via
        # extra="allow" — so downstream consumers get typed, documented
        # access rather than opaque dict keys nobody validates.
        from caliper.core.report_schema import FindingModel

        assert (
            "db_version" in FindingModel.model_fields
        ), "FindingModel must declare 'db_version' as a real field, not rely on extra=allow"
        assert (
            "db_updated_at" in FindingModel.model_fields
        ), "FindingModel must declare 'db_updated_at' as a real field, not rely on extra=allow"
        raw_finding = dict(output["plugins"][0]["findings"][0])
        raw_finding.update(emitted_metadata)
        parsed = FindingModel.model_validate(raw_finding)
        assert parsed.db_version == "2026-08-15"
        assert parsed.db_updated_at == "2026-08-15T00:00:00Z"

    def test_report_without_db_updated_at_metadata_still_validates(self) -> None:
        """AC3: a report with no db_updated_at/db_version metadata still validates."""
        from caliper.core.json_report import render_json
        from caliper.core.report_schema import FindingModel, ReportModel

        finding = PluginFinding(id="CVE-2025-43", severity="medium", message="no db metadata")
        output = json.loads(render_json([_make_result("trivy", findings=[finding])]))

        # The top-level report still validates end to end.
        report = ReportModel.model_validate(output)
        assert report.total_findings == 1

        # And the bare finding dict (no db_updated_at/db_version keys at all)
        # still validates against FindingModel without raising.
        raw_finding = output["plugins"][0]["findings"][0]
        assert "db_updated_at" not in raw_finding.get("metadata", {})
        parsed = FindingModel.model_validate(raw_finding)
        assert parsed.db_updated_at == ""
        assert parsed.db_version == ""
