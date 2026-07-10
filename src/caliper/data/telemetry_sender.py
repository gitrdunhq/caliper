"""Fire-and-forget telemetry transport.
# tested-by: tests/unit/test_telemetry.py

Split out of ``caliper.core.telemetry`` (DPS-101): the event models stay in
core as pure data; the actual network POST lives here, in data/, since it is
the only part of the telemetry feature that performs real I/O.
"""

from __future__ import annotations

import httpx
import structlog

from caliper.core.telemetry import TelemetryEvent

logger = structlog.get_logger()


async def send_telemetry(event: TelemetryEvent, endpoint: str) -> None:
    """POST *event* to *endpoint* as JSON.  Silently drops on any error.

    This function is intentionally fire-and-forget: telemetry failures must
    never affect the review outcome.  All exceptions are caught and logged at
    debug level only.
    """
    try:
        payload = event.model_dump(mode="json")
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(endpoint, json=payload)
    except Exception as exc:  # noqa: BLE001 — fire-and-forget, intentional broad catch
        logger.debug("telemetry.send_failed", error=str(exc))
