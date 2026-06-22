"""Tests for caliper.core.telemetry — anonymous opt-in telemetry module.

# tested-by: tests/unit/test_telemetry.py
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError


class TestTelemetryEventPrivacyEnforcement:
    """TelemetryEvent rejects forbidden fields (privacy contract)."""

    def test_extra_fields_forbidden(self) -> None:
        """TelemetryEvent must reject extra fields — schema IS the privacy contract."""
        from caliper.core.telemetry import ConfigUsage, TelemetryEvent

        with pytest.raises(ValidationError):
            TelemetryEvent(
                caliper_version="1.0.0",
                plugin_results=[],
                finding_counts={},
                plugin_combination=[],
                config_usage=ConfigUsage(),
                ecosystem_distribution={},
                scan_time_bucket="0-10",
                error_codes=[],
                crash_report=None,
                file_paths=["/etc/passwd", "/home/user/secret.py"],  # FORBIDDEN extra field
            )

    def test_crash_report_rejects_file_path_in_message(self) -> None:
        """CrashReport.message must not contain file paths — privacy enforcement."""
        from caliper.core.telemetry import CrashReport

        # We expect the model to either raise ValidationError or sanitize.
        # Per spec: message is "sanitized — no file paths, no package names"
        # Implementation must raise on raw file paths in message.
        with pytest.raises((ValidationError, ValueError)):
            CrashReport(
                exception_type="FileNotFoundError",
                message="/home/user/repos/myproject/src/main.py not found",
                stack_summary="main | cli | pipeline",
            )

    def test_crash_report_strips_file_paths_from_stack_summary(self) -> None:
        """CrashReport.stack_summary strips absolute file paths to module names only."""
        from caliper.core.telemetry import CrashReport

        report = CrashReport(
            exception_type="ValueError",
            message="config error",
            stack_summary="/home/user/project/src/caliper/core/pipeline.py:42 in evaluate",
        )
        # Absolute paths must not survive in the stored stack_summary
        assert "/home" not in report.stack_summary
        assert "/project" not in report.stack_summary


class TestSendTelemetry:
    """send_telemetry fire-and-forget behaviour."""

    @pytest.mark.asyncio
    async def test_send_telemetry_silently_drops_on_network_error(self) -> None:
        """send_telemetry must not raise when the endpoint is unreachable."""
        from caliper.core.telemetry import (
            ConfigUsage,
            PluginTelemetry,
            TelemetryEvent,
            send_telemetry,
        )

        event = TelemetryEvent(
            caliper_version="1.0.0",
            plugin_results=[PluginTelemetry(name="semgrep", status="ok", duration_ms=120)],
            finding_counts={"vuln": 3},
            plugin_combination=["semgrep"],
            config_usage=ConfigUsage(),
            ecosystem_distribution={"python": 10},
            scan_time_bucket="0-10",
            error_codes=[],
            crash_report=None,
        )
        # Unreachable endpoint — must not raise
        await send_telemetry(event, endpoint="http://127.0.0.1:1")  # port 1 — unreachable

    @pytest.mark.asyncio
    async def test_send_telemetry_does_not_crash_on_valid_event(self) -> None:
        """send_telemetry completes without exception on a well-formed event."""
        from unittest.mock import AsyncMock, patch

        from caliper.core.telemetry import ConfigUsage, TelemetryEvent, send_telemetry

        event = TelemetryEvent(
            caliper_version="2.0.0",
            plugin_results=[],
            finding_counts={},
            plugin_combination=["gitleaks", "semgrep"],
            config_usage=ConfigUsage(),
            ecosystem_distribution={"python": 5, "javascript": 2},
            scan_time_bucket="10-50",
            error_codes=["SCANNER_TIMEOUT"],
            crash_report=None,
        )

        # Patch httpx so no real network call happens
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=AsyncMock(status_code=200))

        with patch("httpx.AsyncClient", return_value=mock_client):
            await send_telemetry(event, endpoint="https://telemetry.caliper.dev/v1/events")


class TestRepoConfigTelemetryDefaults:
    """Telemetry is disabled by default in RepoConfig."""

    def test_telemetry_disabled_by_default(self) -> None:
        """TelemetryConfig must default to enabled=False — zero network calls without opt-in."""
        from caliper.core.repo_config import RepoConfig

        config = RepoConfig()
        assert config.telemetry.enabled is False

    def test_telemetry_default_endpoint(self) -> None:
        """Default endpoint must be set even when telemetry is disabled."""
        from caliper.core.repo_config import RepoConfig

        config = RepoConfig()
        assert config.telemetry.endpoint == "https://telemetry.caliper.dev/v1/events"

    def test_telemetry_can_be_enabled_via_config(self) -> None:
        """TelemetryConfig can be enabled explicitly."""
        from caliper.core.repo_config import RepoConfig, TelemetryConfig

        config = RepoConfig(telemetry=TelemetryConfig(enabled=True))
        assert config.telemetry.enabled is True


class TestPluginTelemetry:
    """PluginTelemetry model acceptance and validation."""

    def test_plugin_telemetry_accepts_valid_data(self) -> None:
        """PluginTelemetry accepts name, status, and duration_ms."""
        from caliper.core.telemetry import PluginTelemetry

        pt = PluginTelemetry(name="trivy", status="ok", duration_ms=350)
        assert pt.name == "trivy"
        assert pt.status == "ok"
        assert pt.duration_ms == 350

    def test_plugin_telemetry_rejects_extra_fields(self) -> None:
        """PluginTelemetry must reject extra fields (extra='forbid')."""
        from caliper.core.telemetry import PluginTelemetry

        with pytest.raises(ValidationError):
            PluginTelemetry(
                name="trivy",
                status="ok",
                duration_ms=350,
                package_name="requests",  # FORBIDDEN extra field
            )


class TestConfigUsageDefaults:
    """ConfigUsage defaults to all-false."""

    def test_config_usage_all_false_by_default(self) -> None:
        """ConfigUsage must default every boolean flag to False."""
        from caliper.core.telemetry import ConfigUsage

        usage = ConfigUsage()
        assert usage.has_config_file is False
        assert usage.has_caliperignore is False
        assert usage.uses_disable_flag is False
        assert usage.uses_enable_flag is False
        assert usage.uses_watch_mode is False
        assert usage.uses_sarif_output is False
        assert usage.uses_package_flag is False

    def test_config_usage_rejects_extra_fields(self) -> None:
        """ConfigUsage must reject extra fields."""
        from caliper.core.telemetry import ConfigUsage

        with pytest.raises(ValidationError):
            ConfigUsage(has_config_file=True, org_name="acme")  # FORBIDDEN extra field


class TestTelemetryEventValidData:
    """TelemetryEvent accepts all 9 signals with valid data."""

    def test_all_nine_signals_valid(self) -> None:
        """TelemetryEvent accepts a complete payload with all 9 signals."""
        from caliper.core.telemetry import (
            ConfigUsage,
            CrashReport,
            PluginTelemetry,
            TelemetryEvent,
        )

        event = TelemetryEvent(
            caliper_version="1.2.3",
            plugin_results=[
                PluginTelemetry(name="semgrep", status="ok", duration_ms=200),
                PluginTelemetry(name="trivy", status="error", duration_ms=5000),
                PluginTelemetry(name="clamav", status="skipped", duration_ms=0),
            ],
            finding_counts={"vuln_high": 2, "license": 1, "secret": 0},
            plugin_combination=["semgrep", "trivy"],
            config_usage=ConfigUsage(
                has_config_file=True,
                has_caliperignore=False,
                uses_disable_flag=True,
                uses_enable_flag=False,
                uses_watch_mode=False,
                uses_sarif_output=True,
                uses_package_flag=False,
            ),
            ecosystem_distribution={"python": 12, "javascript": 4, "rust": 1},
            scan_time_bucket="10-50",
            error_codes=["SCANNER_TIMEOUT"],
            crash_report=CrashReport(
                exception_type="TimeoutError",
                message="scanner timed out after 60 seconds",
                stack_summary="pipeline.evaluate | scanners.trivy | base.run_subprocess",
            ),
        )
        assert event.caliper_version == "1.2.3"
        assert len(event.plugin_results) == 3
        assert event.finding_counts["vuln_high"] == 2
        assert event.scan_time_bucket == "10-50"
        assert event.crash_report is not None
        assert event.crash_report.exception_type == "TimeoutError"

    def test_telemetry_event_crash_report_optional(self) -> None:
        """crash_report defaults to None (most runs have no crash)."""
        from caliper.core.telemetry import ConfigUsage, TelemetryEvent

        event = TelemetryEvent(
            caliper_version="1.0.0",
            plugin_results=[],
            finding_counts={},
            plugin_combination=[],
            config_usage=ConfigUsage(),
            ecosystem_distribution={},
            scan_time_bucket="0-10",
            error_codes=[],
        )
        assert event.crash_report is None


class TestScanTimeBucket:
    """scan_time_bucket validates against known bucket values."""

    @pytest.mark.parametrize(
        "bucket",
        ["0-10", "10-50", "50-100", "100-500", "500+"],
    )
    def test_valid_buckets_accepted(self, bucket: str) -> None:
        """All defined scan time buckets must be accepted."""
        from caliper.core.telemetry import ConfigUsage, TelemetryEvent

        event = TelemetryEvent(
            caliper_version="1.0.0",
            plugin_results=[],
            finding_counts={},
            plugin_combination=[],
            config_usage=ConfigUsage(),
            ecosystem_distribution={},
            scan_time_bucket=bucket,
            error_codes=[],
        )
        assert event.scan_time_bucket == bucket

    def test_invalid_bucket_rejected(self) -> None:
        """An unknown scan_time_bucket value must be rejected."""
        from caliper.core.telemetry import ConfigUsage, TelemetryEvent

        with pytest.raises(ValidationError):
            TelemetryEvent(
                caliper_version="1.0.0",
                plugin_results=[],
                finding_counts={},
                plugin_combination=[],
                config_usage=ConfigUsage(),
                ecosystem_distribution={},
                scan_time_bucket="unknown",  # not in allowed set
                error_codes=[],
            )
