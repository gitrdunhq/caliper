"""Deterministic guards for timeout propagation — Issue #243 / Parent #209.

Bug: Scanner classes and OpaRegoAdapter use hardcoded timeout constants instead
of accepting configurable values from CaliperSettings. Operators cannot tune tool
budgets for large repos or constrained CI environments despite scanner_timeout
and opa_timeout being declared in config.

These are xfail until adapters accept timeout parameters wired from settings.
See issues #209 and #243.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #209 — "
        "OpaRegoAdapter and scanner classes hardcode timeout constants rather "
        "than accepting configurable values; fix by adding timeout parameters"
    ),
    strict=False,
)

from caliper.core.opa_adapter import OpaRegoAdapter
from caliper.data.scanners.syft import SyftScanner
from caliper.data.scanners.trivy import TrivyScanner


class TestOpaAdapterTimeoutIsConfigurable:
    """OpaRegoAdapter must expose a timeout parameter rather than hardcoding one."""

    def test_opa_adapter_init_accepts_timeout_parameter(self) -> None:
        """OpaRegoAdapter.__init__() must accept a timeout parameter.

        config.py declares opa_timeout but OpaRegoAdapter hardcodes _OPA_TIMEOUT=10.
        Without a constructor parameter the pipeline cannot pass the configured
        value to the adapter — operators cannot tune OPA budget for slow policies.
        Fix: add timeout: int = 10 to __init__ and use it in the eval invocation.
        """
        sig = inspect.signature(OpaRegoAdapter.__init__)
        assert "timeout" in sig.parameters, (
            f"OpaRegoAdapter.__init__ has no 'timeout' parameter. "
            f"Parameters found: {list(sig.parameters)}. "
            "config.py exposes opa_timeout but the adapter ignores it. "
            "Fix: add timeout to __init__ and wire it from CaliperSettings. "
            "See issue #209."
        )


class TestScannerTimeoutsAreConfigurable:
    """Scanner classes must expose a timeout parameter rather than hardcoding one."""

    def test_syft_scanner_init_accepts_timeout_parameter(self) -> None:
        """SyftScanner.__init__() must accept a timeout parameter.

        SyftScanner hardcodes _TIMEOUT=60. Large repos may need longer budgets;
        constrained CI may need shorter. Fix: add timeout to __init__ and use it
        in run_subprocess_with_timeout(). See issue #209.
        """
        sig = inspect.signature(SyftScanner.__init__)
        assert "timeout" in sig.parameters, (
            f"SyftScanner.__init__ has no 'timeout' parameter. "
            f"Parameters found: {list(sig.parameters)}. "
            "Hardcoded _TIMEOUT=60 cannot be tuned from CaliperSettings. "
            "Fix: add timeout to __init__ and wire it from scanner_timeout config. "
            "See issue #209."
        )

    def test_trivy_scanner_init_accepts_timeout_parameter(self) -> None:
        """TrivyScanner.__init__() must accept a timeout parameter."""
        sig = inspect.signature(TrivyScanner.__init__)
        assert "timeout" in sig.parameters, (
            f"TrivyScanner.__init__ has no 'timeout' parameter. "
            f"Parameters found: {list(sig.parameters)}. "
            "See issue #209."
        )
