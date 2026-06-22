"""Deterministic guards for orchestrator wall-clock timeout — Issue #241 / Parent #207.

Bug: The orchestrator uses ThreadPoolExecutor as a context manager. When
as_completed() raises TimeoutError, the 'with' block __exit__ still waits for
all running futures before returning — so a slow scanner can hold CI past the
combined_scanner_timeout budget despite the TimeoutError being caught.

These are xfail until the executor shutdown is made explicit with
shutdown(wait=False, cancel_futures=True). See issues #207 and #241.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #207 — "
        "ThreadPoolExecutor context manager waits for futures on __exit__ even "
        "after TimeoutError; fix with explicit shutdown(wait=False, cancel_futures=True)"
    ),
    strict=False,
)

from caliper.core.orchestrator import ScanOrchestrator


class TestOrchestratorWallClockBound:
    """ScanOrchestrator must not wait for running futures after the combined timeout fires."""

    def test_orchestrator_does_not_rely_solely_on_context_manager_for_shutdown(self) -> None:
        """ScanOrchestrator must explicitly cancel futures on timeout, not just exit the 'with' block.

        When as_completed() raises TimeoutError inside 'with ThreadPoolExecutor() as executor:',
        the executor's __exit__ calls shutdown(wait=True) — which blocks until all
        running threads finish. A single hung scanner can therefore hold CI past
        combined_scanner_timeout. Fix: manage executor lifecycle explicitly and call
        shutdown(wait=False, cancel_futures=True) when the timeout fires.
        """
        source = inspect.getsource(ScanOrchestrator.run)
        assert "cancel_futures" in source or "shutdown" in source, (
            "ScanOrchestrator.run() does not call executor.shutdown() explicitly. "
            "Using ThreadPoolExecutor as a context manager means __exit__ blocks until "
            "all futures complete — a hung scanner keeps CI running past the timeout budget. "
            "Fix: call executor.shutdown(wait=False, cancel_futures=True) when TimeoutError "
            "fires. See issue #207."
        )

    def test_orchestrator_cancels_futures_on_timeout(self) -> None:
        """ScanOrchestrator must cancel pending futures when combined_scanner_timeout fires."""
        source = inspect.getsource(ScanOrchestrator.run)
        assert "cancel_futures=True" in source, (
            "ScanOrchestrator.run() does not pass cancel_futures=True to shutdown(). "
            "Without this, already-submitted futures that have not started will still execute "
            "after the timeout fires, wasting CI resources. See issue #207."
        )
