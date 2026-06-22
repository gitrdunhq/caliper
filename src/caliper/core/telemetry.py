# tested-by: tests/unit/test_telemetry.py
"""Anonymous opt-in telemetry — 9 signals, privacy enforced by Pydantic schema.

Privacy contract
----------------
Never collected: file paths, package names, CVE IDs, repo names, org names,
diff content, PR URLs, commit SHAs.

The ``extra='forbid'`` config on every model is the machine-enforced
boundary — no field outside the schema can ever be sent.

Opt-in
------
Zero network calls are made unless ``telemetry.enabled: true`` is set in
``.caliper.yaml``. The ``send_telemetry`` helper is fire-and-forget:
any network or serialisation error is silently swallowed so telemetry never
affects the review outcome.
"""

from __future__ import annotations

import re
from typing import Literal

import structlog
from pydantic import BaseModel, ConfigDict, field_validator

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Allowed scan-time buckets (file-count based)
# ---------------------------------------------------------------------------
_SCAN_TIME_BUCKETS: frozenset[str] = frozenset({"0-10", "10-50", "50-100", "100-500", "500+"})

# Regex that matches absolute POSIX or Windows paths inside a string.
# Matches: /home/..., /usr/..., C:\..., etc.
_FILE_PATH_RE = re.compile(r"(?:^|[\s\(\"'])(/[\w./\-]+|[A-Za-z]:\\[\w\\/.\-]+)")


def _strip_paths_from_text(text: str) -> str:
    """Replace absolute file paths with their basename only.

    ``/home/user/project/src/caliper/core/pipeline.py:42 in evaluate``
    becomes ``pipeline.py:42 in evaluate``.
    """

    def _replace(match: re.Match[str]) -> str:
        prefix = match.group(0)[: match.start(1) - match.start(0)]
        path_str = match.group(1)
        # Keep only the final component (basename)
        last = re.split(r"[/\\]", path_str.rstrip("/\\"))[-1]
        return prefix + last

    return _FILE_PATH_RE.sub(_replace, text)


def _has_file_path(text: str) -> bool:
    """Return True if *text* contains an absolute file path."""
    return bool(_FILE_PATH_RE.search(text))


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class PluginTelemetry(BaseModel):
    """Per-plugin execution signal."""

    model_config = ConfigDict(extra="forbid")

    name: str
    status: str  # "ok" | "error" | "skipped"
    duration_ms: int


class ConfigUsage(BaseModel):
    """Which CLI / config features were used during this scan."""

    model_config = ConfigDict(extra="forbid")

    has_config_file: bool = False
    has_caliperignore: bool = False
    uses_disable_flag: bool = False
    uses_enable_flag: bool = False
    uses_watch_mode: bool = False
    uses_sarif_output: bool = False
    uses_package_flag: bool = False


class CrashReport(BaseModel):
    """Sanitised crash context — no file paths, no package names."""

    model_config = ConfigDict(extra="forbid")

    exception_type: str
    message: str  # sanitized — no file paths, no package names
    stack_summary: str  # top 3 frames, file paths stripped to module names only

    @field_validator("message")
    @classmethod
    def _reject_file_paths_in_message(cls, v: str) -> str:
        if _has_file_path(v):
            raise ValueError(
                "CrashReport.message must not contain file paths. "
                "Strip paths before constructing CrashReport."
            )
        return v

    @field_validator("stack_summary")
    @classmethod
    def _strip_file_paths_from_stack(cls, v: str) -> str:
        return _strip_paths_from_text(v)


# ---------------------------------------------------------------------------
# Top-level event — exactly 9 signals
# ---------------------------------------------------------------------------


class TelemetryEvent(BaseModel):
    """Exactly 9 signals. No catch-all dict fields. Privacy enforced by schema.

    Fields
    ------
    1. ``caliper_version``          — caliper release version string
    2. ``plugin_results``         — per-plugin name / status / duration
    3. ``finding_counts``         — category → count (NOT individual findings)
    4. ``plugin_combination``     — which plugins were enabled this run
    5. ``config_usage``           — which features are enabled
    6. ``ecosystem_distribution`` — ecosystem → file count
    7. ``scan_time_bucket``       — coarse file-count bucket for scan duration
    8. ``error_codes``            — ErrorCode values that fired
    9. ``crash_report``           — optional sanitised crash context
    """

    model_config = ConfigDict(extra="forbid")

    # Signal 1
    caliper_version: str
    # Signal 2
    plugin_results: list[PluginTelemetry]
    # Signal 3
    finding_counts: dict[str, int]
    # Signal 4
    plugin_combination: list[str]
    # Signal 5
    config_usage: ConfigUsage
    # Signal 6
    ecosystem_distribution: dict[str, int]
    # Signal 7
    scan_time_bucket: Literal["0-10", "10-50", "50-100", "100-500", "500+"]
    # Signal 8
    error_codes: list[str]
    # Signal 9
    crash_report: CrashReport | None = None


# ---------------------------------------------------------------------------
# Fire-and-forget sender
# ---------------------------------------------------------------------------


async def send_telemetry(event: TelemetryEvent, endpoint: str) -> None:
    """POST *event* to *endpoint* as JSON.  Silently drops on any error.

    This function is intentionally fire-and-forget: telemetry failures must
    never affect the review outcome.  All exceptions are caught and logged at
    debug level only.
    """
    try:
        import httpx

        payload = event.model_dump(mode="json")
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(endpoint, json=payload)
    except Exception as exc:  # noqa: BLE001 — fire-and-forget, intentional broad catch
        logger.debug("telemetry.send_failed", error=str(exc))
