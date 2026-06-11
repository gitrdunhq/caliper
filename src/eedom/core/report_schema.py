"""Published schema for `eedom review --format json` output (#389).
# tested-by: tests/unit/test_report_schema.py

Pydantic models describing the machine-readable review report so downstream
consumers can parse it without reverse-engineering ``core/json_report.py``.

The JSON Schema artifact lives at ``docs/schema/report-v<version>.json`` and
is regenerated with ``eedom schema --output docs/schema/report-v1.0.json``.
A unit test keeps the artifact in sync with these models.

Versioning: ``schema_version`` is embedded in every report. Changes to these
models must be additive within a major version — never rename or repurpose
existing fields.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

REPORT_SCHEMA_VERSION = "1.0"


class PluginStatus(enum.StrEnum):
    """Execution status of a single plugin in the report."""

    ran = "ran"
    skipped = "skipped"
    error = "error"


class ReportVerdict(enum.StrEnum):
    """Overall review verdict, ordered from best to worst."""

    clear = "clear"
    incomplete = "incomplete"
    warnings = "warnings"
    blocked = "blocked"


class FindingModel(BaseModel):
    """A single plugin finding.

    Findings are heterogeneous across plugins: every field is optional and
    unknown keys are preserved (``extra="allow"``). Findings emitted from
    typed ``PluginFinding`` objects nest plugin-specific keys under
    ``metadata``; plugins that return raw dicts may use any shape.
    """

    model_config = ConfigDict(extra="allow")

    id: str = ""
    severity: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    url: str = ""
    category: str = ""
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    rule_id: str = ""


class PluginReportModel(BaseModel):
    """Per-plugin section of the JSON report."""

    name: str
    category: str = ""
    status: PluginStatus
    skip_reason: str | None = None
    skip_remediation: str | None = None
    findings_count: int = 0
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Raw finding objects. Shape varies per plugin — parse individual "
            "entries with FindingModel for typed access."
        ),
    )
    summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class ReportModel(BaseModel):
    """Top-level document emitted by ``eedom review --format json``."""

    schema_version: str = REPORT_SCHEMA_VERSION
    timestamp: str = Field(description="ISO 8601 UTC timestamp of report generation.")
    repo: str = ""
    commit: str = ""
    verdict: ReportVerdict
    security_score: float = Field(description="0-100, security plugins only.")
    quality_score: float = Field(description="0-100, quality plugins only (advisory).")
    total_findings: int = 0
    total_plugins: int = 0
    plugins: list[PluginReportModel] = Field(default_factory=list)


def report_json_schema() -> dict[str, Any]:
    """Return the JSON Schema for the published report document."""
    return ReportModel.model_json_schema()
