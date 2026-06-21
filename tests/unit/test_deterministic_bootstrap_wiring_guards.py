"""Deterministic guards for bootstrap wiring — Issue #238 / Parent #204.

Bug: The production bootstrap() wires _FakePackageIndex and _make_audit_sink /
_make_publisher unconditionally return NullAuditSink / NullPublisher regardless
of settings. Audit, publishing, and package metadata guarantees silently
disappear in the production composition path.

These are xfail until the bootstrap wires real adapters conditioned on settings.
See issues #204 and #238.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #204 — "
        "bootstrap() wires _FakePackageIndex and unconditional Null adapters; "
        "fix the composition root, then these go green"
    ),
    strict=False,
)

from eedom.composition.bootstrap import _make_audit_sink, _make_publisher, bootstrap


class TestBootstrapDoesNotWireFakeAdapters:
    """production bootstrap() must not use Fake or unconditional Null adapters."""

    def test_bootstrap_does_not_wire_fake_package_index(self) -> None:
        """bootstrap() must not use _FakePackageIndex.

        _FakePackageIndex ignores all package metadata queries. Wiring it in
        the production composition root means package-age, malicious-package,
        and transitive-count checks always evaluate against empty/fake data.
        Fix: wire a real PyPI adapter or PypiPackageIndex from settings.
        """
        source = inspect.getsource(bootstrap)
        assert "_FakePackageIndex" not in source, (
            "bootstrap() references _FakePackageIndex — a placeholder adapter "
            "that returns empty/stub package metadata. All package-policy "
            "checks silently evaluate against fake data in production. "
            "Fix: wire a real package index from EedomSettings. See issue #204."
        )

    def test_make_audit_sink_is_not_unconditionally_null(self) -> None:
        """_make_audit_sink() must not unconditionally return NullAuditSink.

        An unconditional NullAuditSink means no audit events are ever recorded
        in production, regardless of settings. The function must check settings
        and return a real sink when one is configured.
        """
        source = inspect.getsource(_make_audit_sink)
        # Fixed state: function must check settings before returning NullAuditSink
        assert "if " in source, (
            "_make_audit_sink() has no conditional logic — it unconditionally returns "
            "NullAuditSink regardless of settings. "
            "Fix: check settings for an audit backend and return a real sink conditionally. "
            "See issue #204."
        )

    def test_make_publisher_is_not_unconditionally_null(self) -> None:
        """_make_publisher() must not unconditionally return NullPublisher.

        An unconditional NullPublisher means PR comments are never posted in
        production, regardless of whether a GitHub token is configured.
        """
        source = inspect.getsource(_make_publisher)
        assert "if " in source, (
            "_make_publisher() has no conditional logic — it unconditionally returns "
            "NullPublisher regardless of settings. "
            "Fix: check settings for GitHub credentials and return a real publisher conditionally. "
            "See issue #204."
        )
