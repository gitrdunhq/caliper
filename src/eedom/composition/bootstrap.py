# tested-by: tests/unit/test_bootstrap_wiring.py
"""Application composition root — wires concrete adapters behind port contracts.

This is the presentation-side composition tier: it may legally import
``data`` / ``adapters`` / ``plugins`` to construct the core
``ApplicationContext``.  Core depends on the *type* (``eedom.core.context``),
never on this wiring.

Public symbols:
  - ApplicationContext — re-exported from core for call-site convenience
  - bootstrap(settings) -> ApplicationContext — production wiring
  - bootstrap_test() -> ApplicationContext — in-memory fakes for unit tests
  - bootstrap_review() -> ApplicationContext — minimal context for review
  - build_*(settings) — per-adapter production wiring helpers

NOTE: registry-backed adapter dispatch for the decision-store / evidence /
package-index / publisher / policy / tool-runner areas lands in Phase 7
(#411) once those registries exist; today these helpers construct adapters
directly (which is legal in this tier).  The analyzer registry is already
registry-backed via ``eedom.plugins.ANALYZERS``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from eedom.core.context import ApplicationContext
from eedom.core.policy_port import PolicyDecision, PolicyInput
from eedom.core.ports import (
    AuditSinkPort,
    DecisionStorePort,
    PullRequestPublisherPort,
)
from eedom.core.tool_runner import ToolInvocation, ToolResult

if TYPE_CHECKING:
    from eedom.core.config import EedomSettings

__all__ = [
    "ApplicationContext",
    "bootstrap",
    "bootstrap_review",
    "bootstrap_test",
    "build_audit_sink",
    "build_decision_store",
    "build_package_index",
    "build_publisher",
]


# ---------------------------------------------------------------------------
# Fake implementations for bootstrap_test() and bootstrap_review()
# ---------------------------------------------------------------------------


class _FakeAnalyzerRegistry:
    """No-op analyzer registry — never reaches real scanners."""

    def run_all(self, files: list, repo_path: Path, **kwargs) -> list:
        return []

    def list(self, category=None, names=None) -> list:
        return []


class _FakePolicyEngine:
    """Always-approve policy engine — never invokes OPA."""

    def evaluate(self, input: PolicyInput) -> PolicyDecision:
        return PolicyDecision(verdict="approve")


class _FakePackageIndex:
    """No-op package index — never makes real network calls."""

    def get_package_info(self, name: str, ecosystem: str) -> dict:
        return {}


class _FakeToolRunner:
    """No-op tool runner — never spawns real subprocesses."""

    def run(self, invocation: ToolInvocation) -> ToolResult:
        return ToolResult(exit_code=0, stdout="", stderr="")


# ---------------------------------------------------------------------------
# bootstrap_test()
# ---------------------------------------------------------------------------


def bootstrap_test() -> ApplicationContext:
    """Return an ApplicationContext wired with all-fake implementations.

    Safe to call without any real infrastructure (no DB, no OPA, no
    subprocesses, no filesystem side-effects).
    """
    from eedom.adapters.github_publisher import NullPublisher
    from eedom.adapters.persistence import NullAuditSink, NullDecisionStore, NullEvidenceStore

    return ApplicationContext(
        analyzer_registry=_FakeAnalyzerRegistry(),
        policy_engine=_FakePolicyEngine(),
        tool_runner=_FakeToolRunner(),
        decision_store=NullDecisionStore(),
        evidence_store=NullEvidenceStore(),
        package_index=_FakePackageIndex(),
        audit_sink=NullAuditSink(),
        publisher=NullPublisher(),
    )


# ---------------------------------------------------------------------------
# bootstrap_review() — minimal context for plugin review command
# ---------------------------------------------------------------------------


def bootstrap_review(registry_factory=None) -> ApplicationContext:
    """Return an ApplicationContext suitable for the review command.

    Uses the real plugin registry (or *registry_factory* when provided) for
    the analyzer and no-op adapters for everything else.  Does NOT require
    EedomSettings so it works without a full production configuration.
    """
    from eedom.adapters.github_publisher import NullPublisher
    from eedom.adapters.persistence import NullAuditSink, NullDecisionStore, NullEvidenceStore
    from eedom.core.subprocess_runner import SubprocessToolRunner

    if registry_factory is None:
        from eedom.plugins import get_default_registry

        registry_factory = get_default_registry

    return ApplicationContext(
        analyzer_registry=registry_factory(),
        policy_engine=_FakePolicyEngine(),
        tool_runner=SubprocessToolRunner(),
        decision_store=NullDecisionStore(),
        evidence_store=NullEvidenceStore(),
        package_index=_FakePackageIndex(),
        audit_sink=NullAuditSink(),
        publisher=NullPublisher(),
    )


# ---------------------------------------------------------------------------
# Production adapter helpers — keep Null* instantiation out of bootstrap()
# ---------------------------------------------------------------------------


def build_decision_store(settings: EedomSettings) -> DecisionStorePort:
    """Return the appropriate DecisionStorePort for *settings*.

    Returns a real DecisionRepository when *settings.db_dsn* is set and a
    connection can be established.  Falls back to NullDecisionStore (with a
    warning) when no DSN is configured or the connection attempt fails, so the
    pipeline always proceeds regardless of persistence availability.
    """
    import structlog

    from eedom.adapters.persistence import NullDecisionStore

    log = structlog.get_logger()
    dsn = getattr(settings, "db_dsn", None)
    if not dsn:
        log.warning(
            "decision_store_null",
            msg="No EEDOM_DB_DSN configured — decisions will not be persisted",
        )
        return NullDecisionStore()

    try:
        from eedom.data.db import DecisionRepository

        repo = DecisionRepository(dsn=dsn)
        if not repo.connect():
            log.warning(
                "decision_store_null",
                msg="DB connection failed — falling back to NullDecisionStore",
            )
            return NullDecisionStore()
        return repo
    except Exception:
        log.warning(
            "decision_store_null",
            msg="Failed to initialise DecisionRepository — falling back to NullDecisionStore",
            exc_info=True,
        )
        return NullDecisionStore()


def build_audit_sink(settings: EedomSettings) -> AuditSinkPort:
    """Return EvidenceStore-backed audit sink when evidence_path is set, NullAuditSink otherwise."""
    import structlog

    from eedom.adapters.persistence import NullAuditSink

    log = structlog.get_logger()
    evidence_path = getattr(settings, "evidence_path", None)
    if evidence_path:
        from eedom.data.evidence import EvidenceStore

        return EvidenceStore(root_path=str(evidence_path))
    log.warning("audit_sink_null", msg="No EEDOM_EVIDENCE_PATH — audit events not persisted")
    return NullAuditSink()


def build_publisher(settings: EedomSettings) -> PullRequestPublisherPort:
    """Return GitHubPublisher when EEDOM_GITHUB_TOKEN is set, NullPublisher otherwise."""
    import structlog

    from eedom.adapters.github_publisher import NullPublisher

    log = structlog.get_logger()
    token = getattr(settings, "github_token", None)
    if token:
        secret = token.get_secret_value() if hasattr(token, "get_secret_value") else str(token)
        if secret:
            from eedom.adapters.github_publisher import GitHubPublisher

            return GitHubPublisher(token=secret)
    log.warning("publisher_null", msg="No EEDOM_GITHUB_TOKEN — PR comments will not be posted")
    return NullPublisher()


def build_package_index(settings: EedomSettings):
    """Return a real PyPI package index."""
    from eedom.data.pypi import PyPIClient

    return PyPIClient(timeout=getattr(settings, "pypi_timeout", 30))


# Backward-compatible aliases. The epic renames `_make_*` -> `build_*`; these
# keep existing imports and inspect-based wiring guards working unchanged.
_make_decision_store = build_decision_store
_make_audit_sink = build_audit_sink
_make_publisher = build_publisher
_make_package_index = build_package_index


# ---------------------------------------------------------------------------
# bootstrap(settings)
# ---------------------------------------------------------------------------


def bootstrap(settings: EedomSettings) -> ApplicationContext:
    """Wire concrete adapters from *settings* and return an ApplicationContext.

    All heavy imports are deferred to this function so that import-time cost
    is only paid when the production composition root is actually needed.
    """
    from eedom.adapters.persistence import FileEvidenceStore
    from eedom.core.opa_adapter import OpaRegoAdapter
    from eedom.core.subprocess_runner import SubprocessToolRunner
    from eedom.plugins import get_default_registry

    tool_runner = SubprocessToolRunner()
    registry = get_default_registry()

    # OPA policy path — use the bundled policies directory by default.
    policy_path = str(Path(__file__).parent.parent.parent.parent / "policies" / "policy.rego")

    policy_engine = OpaRegoAdapter(
        policy_path=policy_path,
        tool_runner=tool_runner,
        timeout=getattr(settings, "opa_timeout", 10),
    )

    return ApplicationContext(
        analyzer_registry=registry,
        policy_engine=policy_engine,
        tool_runner=tool_runner,
        decision_store=build_decision_store(settings),
        evidence_store=FileEvidenceStore(base_dir=Path(settings.evidence_path)),
        package_index=build_package_index(settings),
        audit_sink=build_audit_sink(settings),
        publisher=build_publisher(settings),
    )
