# tested-by: tests/unit/test_bootstrap_wiring.py
"""Wiring tests for ApplicationContext persistence adapters — RED phase for #187.

Verifies that:
  1. ApplicationContext carries both `audit_sink` and `publisher` fields.
  2. bootstrap_test() satisfies all three persistence-layer port protocols.
  3. The `publisher` field (not `pr_publisher`) is the canonical name.

Currently failing assertions:
  - ApplicationContext has no `publisher` field (field is named `pr_publisher`)
  - bootstrap_test() context has no `.publisher` attribute
  - isinstance check against PullRequestPublisherPort via `.publisher` raises AttributeError
"""

from __future__ import annotations

import dataclasses

# ---------------------------------------------------------------------------
# ApplicationContext field presence
# ---------------------------------------------------------------------------


class TestApplicationContextPersistenceFields:
    def test_application_context_has_audit_sink_field(self) -> None:
        """audit_sink field must be present on ApplicationContext."""
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert "audit_sink" in fields, "ApplicationContext must have an 'audit_sink' field"

    def test_application_context_has_publisher_field(self) -> None:
        """publisher field must be present on ApplicationContext.

        FAILS: the field is currently named 'pr_publisher', not 'publisher'.
        """
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert "publisher" in fields, (
            "ApplicationContext must have a 'publisher' field; " f"found fields: {fields}"
        )


# ---------------------------------------------------------------------------
# bootstrap_test() — persistence port satisfaction
# ---------------------------------------------------------------------------


class TestBootstrapTestPersistencePortSatisfaction:
    def test_bootstrap_test_all_persistence_ports_satisfied(self) -> None:
        """All three persistence adapters must implement their port protocols."""
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import AuditSinkPort, DecisionStorePort, EvidenceStorePort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.evidence_store, EvidenceStorePort
        ), "bootstrap_test().evidence_store must satisfy EvidenceStorePort"
        assert isinstance(
            ctx.audit_sink, AuditSinkPort
        ), "bootstrap_test().audit_sink must satisfy AuditSinkPort"
        assert isinstance(
            ctx.decision_store, DecisionStorePort
        ), "bootstrap_test().decision_store must satisfy DecisionStorePort"

    def test_bootstrap_test_evidence_store_satisfies_evidence_store_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import EvidenceStorePort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.evidence_store, EvidenceStorePort
        ), "bootstrap_test().evidence_store must satisfy EvidenceStorePort"

    def test_bootstrap_test_audit_sink_satisfies_audit_sink_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import AuditSinkPort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.audit_sink, AuditSinkPort
        ), "bootstrap_test().audit_sink must satisfy AuditSinkPort"

    def test_bootstrap_test_decision_store_satisfies_decision_store_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import DecisionStorePort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.decision_store, DecisionStorePort
        ), "bootstrap_test().decision_store must satisfy DecisionStorePort"


# ---------------------------------------------------------------------------
# bootstrap_test() — publisher field wiring
# ---------------------------------------------------------------------------


class TestBootstrapTestPublisherField:
    def test_bootstrap_test_publisher_is_not_none(self) -> None:
        """bootstrap_test().publisher must be non-None.

        FAILS: AttributeError — ApplicationContext has no 'publisher' attribute
        (field is 'pr_publisher').
        """
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        assert (
            ctx.publisher is not None
        ), "bootstrap_test().publisher must be wired to a non-None adapter"

    def test_bootstrap_test_publisher_satisfies_pull_request_publisher_port(self) -> None:
        """bootstrap_test().publisher must satisfy PullRequestPublisherPort.

        FAILS: AttributeError — ApplicationContext has no 'publisher' attribute
        (field is 'pr_publisher').
        """
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import PullRequestPublisherPort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.publisher, PullRequestPublisherPort
        ), "bootstrap_test().publisher must satisfy PullRequestPublisherPort"
