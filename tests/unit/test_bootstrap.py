"""Contract tests for the bootstrap composition root.
# tested-by: tests/unit/test_bootstrap.py

RED phase for issue #160 — all tests import from eedom.composition.bootstrap which
does not exist yet. Every test is expected to fail with ImportError until the
production code is added.

Defines the contract for:
  - ApplicationContext dataclass (holds all wired port dependencies)
  - bootstrap(settings) -> ApplicationContext (constructs concrete adapters)
  - bootstrap_test() -> ApplicationContext (returns all-fake context for unit tests)
"""

from __future__ import annotations

import dataclasses

# ---------------------------------------------------------------------------
# ApplicationContext dataclass
# ---------------------------------------------------------------------------


class TestApplicationContextDataclass:
    def test_application_context_can_be_imported(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext  # noqa: F401

    def test_application_context_is_a_dataclass(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        assert dataclasses.is_dataclass(ApplicationContext)

    def test_application_context_has_analyzer_registry_field(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert (
            "analyzer_registry" in fields
        ), "ApplicationContext must have an 'analyzer_registry' field"

    def test_application_context_has_policy_engine_field(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert "policy_engine" in fields, "ApplicationContext must have a 'policy_engine' field"

    def test_application_context_has_tool_runner_field(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert "tool_runner" in fields, "ApplicationContext must have a 'tool_runner' field"

    def test_application_context_has_decision_store_field(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert "decision_store" in fields, "ApplicationContext must have a 'decision_store' field"

    def test_application_context_has_evidence_store_field(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert "evidence_store" in fields, "ApplicationContext must have an 'evidence_store' field"

    def test_application_context_has_package_index_field(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        fields = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert "package_index" in fields, "ApplicationContext must have a 'package_index' field"

    def test_application_context_has_exactly_eight_fields(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext

        field_names = {f.name for f in dataclasses.fields(ApplicationContext)}
        assert (
            len(field_names) == 8
        ), f"ApplicationContext must have exactly 8 fields, got: {field_names}"


# ---------------------------------------------------------------------------
# bootstrap_test() — fake context for unit tests
# ---------------------------------------------------------------------------


class TestBootstrapTestFunction:
    def test_bootstrap_test_can_be_imported(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test  # noqa: F401

    def test_bootstrap_test_returns_application_context(self) -> None:
        from eedom.composition.bootstrap import ApplicationContext, bootstrap_test

        ctx = bootstrap_test()
        assert isinstance(ctx, ApplicationContext)

    def test_bootstrap_test_analyzer_registry_is_not_none(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        assert ctx.analyzer_registry is not None

    def test_bootstrap_test_policy_engine_is_not_none(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        assert ctx.policy_engine is not None

    def test_bootstrap_test_tool_runner_is_not_none(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        assert ctx.tool_runner is not None

    def test_bootstrap_test_decision_store_is_not_none(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        assert ctx.decision_store is not None

    def test_bootstrap_test_evidence_store_is_not_none(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        assert ctx.evidence_store is not None

    def test_bootstrap_test_package_index_is_not_none(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        assert ctx.package_index is not None


# ---------------------------------------------------------------------------
# bootstrap_test() port protocol satisfaction
# ---------------------------------------------------------------------------


class TestBootstrapTestPortSatisfaction:
    def test_analyzer_registry_satisfies_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import AnalyzerRegistryPort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.analyzer_registry, AnalyzerRegistryPort
        ), "bootstrap_test().analyzer_registry must satisfy AnalyzerRegistryPort"

    def test_policy_engine_satisfies_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.policy_port import PolicyEnginePort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.policy_engine, PolicyEnginePort
        ), "bootstrap_test().policy_engine must satisfy PolicyEnginePort"

    def test_tool_runner_satisfies_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.tool_runner import ToolRunnerPort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.tool_runner, ToolRunnerPort
        ), "bootstrap_test().tool_runner must satisfy ToolRunnerPort"

    def test_decision_store_satisfies_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import DecisionStorePort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.decision_store, DecisionStorePort
        ), "bootstrap_test().decision_store must satisfy DecisionStorePort"

    def test_evidence_store_satisfies_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import EvidenceStorePort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.evidence_store, EvidenceStorePort
        ), "bootstrap_test().evidence_store must satisfy EvidenceStorePort"

    def test_package_index_satisfies_port(self) -> None:
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.ports import PackageIndexPort

        ctx = bootstrap_test()
        assert isinstance(
            ctx.package_index, PackageIndexPort
        ), "bootstrap_test().package_index must satisfy PackageIndexPort"


# ---------------------------------------------------------------------------
# bootstrap_test() usable without real infrastructure
# ---------------------------------------------------------------------------


class TestBootstrapTestNoInfrastructure:
    def test_bootstrap_test_analyzer_registry_run_all_returns_list(self) -> None:
        """Fake registry must not reach out to real scanners."""
        from pathlib import Path

        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        result = ctx.analyzer_registry.run_all(files=[], repo_path=Path("/tmp/fake"))
        assert isinstance(result, list)

    def test_bootstrap_test_decision_store_save_decision_does_not_raise(self) -> None:
        """Fake store must not reach out to a real DB."""
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        ctx.decision_store.save_decision({"verdict": "approve", "id": "test-001"})

    def test_bootstrap_test_evidence_store_write_artifact_returns_str(self) -> None:
        """Fake evidence store must not hit the filesystem."""
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        ref = ctx.evidence_store.write_artifact("test/sbom.xml", b"<sbom/>")
        assert isinstance(ref, str)

    def test_bootstrap_test_package_index_get_package_info_returns_dict(self) -> None:
        """Fake index must not make real network calls."""
        from eedom.composition.bootstrap import bootstrap_test

        ctx = bootstrap_test()
        info = ctx.package_index.get_package_info("requests", "pypi")
        assert isinstance(info, dict)

    def test_bootstrap_test_tool_runner_run_returns_tool_result(self) -> None:
        """Fake tool runner must not execute real subprocesses."""
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.tool_runner import ToolInvocation, ToolResult

        ctx = bootstrap_test()
        invocation = ToolInvocation(cmd=["echo", "hi"], cwd="/tmp", timeout=5)
        result = ctx.tool_runner.run(invocation)
        assert isinstance(result, ToolResult)

    def test_bootstrap_test_policy_engine_evaluate_returns_policy_decision(self) -> None:
        """Fake policy engine must not invoke OPA."""
        from eedom.composition.bootstrap import bootstrap_test
        from eedom.core.policy_port import PolicyDecision, PolicyInput

        ctx = bootstrap_test()
        policy_input = PolicyInput(findings=[], packages=[], config={})
        decision = ctx.policy_engine.evaluate(policy_input)
        assert isinstance(decision, PolicyDecision)


# ---------------------------------------------------------------------------
# bootstrap(settings) function
# ---------------------------------------------------------------------------


class TestBootstrapFunction:
    def test_bootstrap_can_be_imported(self) -> None:
        from eedom.composition.bootstrap import bootstrap  # noqa: F401

    def test_bootstrap_accepts_eedom_settings(self) -> None:
        """bootstrap() must accept an EedomSettings instance (signature check only)."""
        import inspect

        from eedom.composition.bootstrap import bootstrap

        sig = inspect.signature(bootstrap)
        assert "settings" in sig.parameters, "bootstrap() must accept a 'settings' parameter"

    def test_bootstrap_returns_application_context_type(self) -> None:
        """bootstrap() return annotation must be ApplicationContext."""
        import inspect

        from eedom.composition.bootstrap import ApplicationContext, bootstrap

        sig = inspect.signature(bootstrap)
        annotation = sig.return_annotation
        assert (
            annotation is ApplicationContext or annotation == "ApplicationContext"
        ), "bootstrap() must be annotated to return ApplicationContext"


# ---------------------------------------------------------------------------
# _make_decision_store() — wiring logic
# ---------------------------------------------------------------------------


class TestMakeDecisionStore:
    """Verify _make_decision_store wires the correct store based on settings.db_dsn."""

    def test_no_dsn_returns_null_decision_store(self) -> None:
        """When db_dsn is empty/None, _make_decision_store must return NullDecisionStore."""
        from unittest.mock import MagicMock

        from eedom.adapters.persistence import NullDecisionStore
        from eedom.composition.bootstrap import _make_decision_store

        settings = MagicMock()
        settings.db_dsn = None
        result = _make_decision_store(settings)
        assert isinstance(result, NullDecisionStore)

    def test_with_dsn_does_not_return_null_decision_store(self) -> None:
        """When db_dsn is set and connection succeeds, must NOT return NullDecisionStore."""
        from unittest.mock import MagicMock, patch

        from eedom.adapters.persistence import NullDecisionStore
        from eedom.composition.bootstrap import _make_decision_store

        settings = MagicMock()
        settings.db_dsn = "postgresql://user:pass@localhost:5432/eedom"

        with patch("eedom.data.db.DecisionRepository.connect", return_value=True):
            result = _make_decision_store(settings)

        assert not isinstance(result, NullDecisionStore), (
            "When db_dsn is set and connection succeeds, _make_decision_store must "
            "return a real store, not NullDecisionStore"
        )

    def test_with_dsn_returns_decision_repository(self) -> None:
        """When db_dsn is set and connection succeeds, must return a DecisionRepository."""
        from unittest.mock import MagicMock, patch

        from eedom.composition.bootstrap import _make_decision_store
        from eedom.data.db import DecisionRepository

        settings = MagicMock()
        settings.db_dsn = "postgresql://user:pass@localhost:5432/eedom"

        with patch("eedom.data.db.DecisionRepository.connect", return_value=True):
            result = _make_decision_store(settings)

        assert isinstance(result, DecisionRepository)

    def test_with_dsn_and_failed_connection_falls_back_to_null(self) -> None:
        """When db_dsn is set but connection fails, must fall back to NullDecisionStore."""
        from unittest.mock import MagicMock, patch

        from eedom.adapters.persistence import NullDecisionStore
        from eedom.composition.bootstrap import _make_decision_store

        settings = MagicMock()
        settings.db_dsn = "postgresql://user:pass@badhost:5432/eedom"

        with patch("eedom.data.db.DecisionRepository.connect", return_value=False):
            result = _make_decision_store(settings)

        assert isinstance(
            result, NullDecisionStore
        ), "When db_dsn is set but connection fails, must fall back to NullDecisionStore"

    def test_with_dsn_and_exception_falls_back_to_null(self) -> None:
        """When DecisionRepository raises during construction, must fall back to NullDecisionStore."""
        from unittest.mock import MagicMock, patch

        from eedom.adapters.persistence import NullDecisionStore
        from eedom.composition.bootstrap import _make_decision_store

        settings = MagicMock()
        settings.db_dsn = "postgresql://user:pass@localhost:5432/eedom"

        with patch("eedom.data.db.DecisionRepository.connect", side_effect=RuntimeError("boom")):
            result = _make_decision_store(settings)

        assert isinstance(
            result, NullDecisionStore
        ), "When DecisionRepository.connect raises, must fall back to NullDecisionStore"
