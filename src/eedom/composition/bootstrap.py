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
from eedom.core.ports import (
    AuditSinkPort,
    DecisionStorePort,
    PullRequestPublisherPort,
)
from eedom.core.registries import (
    DECISION_STORES,
    EVIDENCE_STORES,
    PACKAGE_INDEXES,
    POLICY_ENGINES,
    PUBLISHERS,
)
from eedom.core.tool_runner import ToolInvocation, ToolResult

if TYPE_CHECKING:
    from eedom.core.config import EedomSettings

__all__ = [
    "ApplicationContext",
    "bootstrap",
    "bootstrap_review",
    "bootstrap_test",
    "load_adapters",
    "build_audit_sink",
    "build_audit_log_appender",
    "build_decision_repository",
    "build_decision_store",
    "build_evidence_writer",
    "build_package_index",
    "build_package_metadata",
    "build_publisher",
    "build_scanners",
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


class _FakePackageIndex:
    """No-op PackageIndexPort (vestigial get_package_info) — for the package_index field."""

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
    from eedom.adapters.persistence import NullAuditSink

    load_adapters()
    return ApplicationContext(
        analyzer_registry=_FakeAnalyzerRegistry(),
        policy_engine=POLICY_ENGINES.create("fake"),
        tool_runner=_FakeToolRunner(),
        decision_store=DECISION_STORES.create("null"),
        evidence_store=EVIDENCE_STORES.create("null"),
        package_index=_FakePackageIndex(),
        audit_sink=NullAuditSink(),
        publisher=PUBLISHERS.create("null"),
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
    from eedom.adapters.persistence import NullAuditSink
    from eedom.core.subprocess_runner import SubprocessToolRunner

    load_adapters()
    if registry_factory is None:
        from eedom.plugins import get_default_registry

        registry_factory = get_default_registry

    return ApplicationContext(
        analyzer_registry=registry_factory(),
        policy_engine=POLICY_ENGINES.create("fake"),
        tool_runner=SubprocessToolRunner(),
        decision_store=DECISION_STORES.create("null"),
        evidence_store=EVIDENCE_STORES.create("null"),
        package_index=_FakePackageIndex(),
        audit_sink=NullAuditSink(),
        publisher=PUBLISHERS.create("null"),
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

    log = structlog.get_logger()
    load_adapters()
    dsn = getattr(settings, "db_dsn", None)
    if not dsn:
        log.warning(
            "decision_store_null",
            msg="No EEDOM_DB_DSN configured — decisions will not be persisted",
        )
        return DECISION_STORES.create("null")

    try:
        repo = DECISION_STORES.create("postgres", dsn=dsn)
        if not repo.connect():
            log.warning(
                "decision_store_null",
                msg="DB connection failed — falling back to NullDecisionStore",
            )
            return DECISION_STORES.create("null")
        return repo
    except Exception:
        log.warning(
            "decision_store_null",
            msg="Failed to initialise DecisionRepository — falling back to NullDecisionStore",
            exc_info=True,
        )
        return DECISION_STORES.create("null")


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

    log = structlog.get_logger()
    load_adapters()
    token = getattr(settings, "github_token", None)
    if token:
        secret = token.get_secret_value() if hasattr(token, "get_secret_value") else str(token)
        if secret:
            return PUBLISHERS.create("github", token=secret)
    log.warning("publisher_null", msg="No EEDOM_GITHUB_TOKEN — PR comments will not be posted")
    return PUBLISHERS.create("null")


def build_package_index(settings: EedomSettings):
    """Return a real PyPI package metadata client via the registry."""
    load_adapters()
    return PACKAGE_INDEXES.create("pypi", timeout=getattr(settings, "pypi_timeout", 30))


# ---------------------------------------------------------------------------
# Review-pipeline collaborators — supplied to the pipeline via ApplicationContext
# ---------------------------------------------------------------------------

# config.enabled_scanners uses the analyzer-style names; map them to SCANNERS keys.
_SCANNER_REGISTRY_KEYS = {
    "syft": "syft",
    "osv-scanner": "osv",
    "trivy": "trivy",
    "scancode": "scancode",
}


def build_enrichers(settings: EedomSettings) -> list:
    """Build the enabled finding enrichers from the ENRICHERS registry (ADR-006).

    Detect-then-enrich: these run as a sequential post-detection pass (see
    ``core.enrich.enrich_findings``) attaching deterministic context to each
    finding. Unknown keys are skipped so config can name enrichers a given build
    doesn't ship. The factories do no I/O — enrichers build tool state lazily.
    """
    from eedom.core.registries import ENRICHERS

    enrichers: list = []
    for name in settings.enabled_enrichers:
        if name in ENRICHERS:
            enrichers.append(ENRICHERS.create(name))
    return enrichers


def build_default_enrichers() -> list:
    """Build the on-by-default enrichers without a full settings object (ADR-006).

    For standalone presentation paths (the GATEKEEPER agent's ``scan_code``) that run
    a single plugin outside the wired ``ApplicationContext`` but still want findings
    enriched. Triggers ``load_adapters`` so the registry is populated, then resolves
    the ``DEFAULT_ENRICHERS`` keys (semgrep stays opt-in).
    """
    from eedom.core.config import DEFAULT_ENRICHERS
    from eedom.core.registries import ENRICHERS

    load_adapters()
    return [ENRICHERS.create(k) for k in DEFAULT_ENRICHERS if k in ENRICHERS]


def run_supply_chain_scan(diff_text: str, settings: EedomSettings, *, sources=None) -> list:
    """Composition entry point for the gated supply-chain-diff step.

    Keeps the presentation tier (the CLI command) from importing ``eedom.data``
    directly: composition is the only tier allowed to reach into ``data`` to wire
    the fetch+diff orchestration. Returns the deterministic supply_chain findings.
    """
    load_adapters()  # ensure PACKAGE_SOURCES (pypi/npm) are registered
    from eedom.data.supply_chain_scan import run_supply_chain_diff

    return run_supply_chain_diff(diff_text, settings, sources=sources)


def build_scanners(settings: EedomSettings) -> list:
    """Build the enabled scanners from the SCANNERS registry.

    Reproduces the pipeline's former scanner-selection logic, now in the
    composition tier: per-scanner timeouts/paths are threaded through the
    registry factories (which do no I/O).
    """
    from eedom.data.scanners import SCANNERS

    evidence_path = Path(settings.evidence_path)
    scanners: list = []
    for name in settings.enabled_scanners:
        key = _SCANNER_REGISTRY_KEYS.get(name)
        if key is None:
            continue
        if key == "syft":
            scanners.append(SCANNERS.create("syft", evidence_dir=evidence_path))
        elif key == "osv":
            scanners.append(SCANNERS.create("osv", exclude_paths=settings.osv_exclude_paths))
        elif key == "trivy":
            scanners.append(SCANNERS.create("trivy"))
        elif key == "scancode":
            scanners.append(
                SCANNERS.create(
                    "scancode",
                    evidence_dir=evidence_path,
                    timeout=settings.scancode_timeout,
                    license_score=settings.scancode_license_score,
                )
            )
    return scanners


def build_evidence_writer(settings: EedomSettings):
    """Return the per-run evidence bundle writer (EvidenceWriterPort)."""
    from eedom.data.evidence import EvidenceStore

    return EvidenceStore(root_path=settings.evidence_path)


def build_package_metadata(settings: EedomSettings):
    """Return the package-metadata client (PackageMetadataPort) via the registry."""
    load_adapters()
    return PACKAGE_INDEXES.create("pypi", timeout=settings.pypi_timeout)


def build_decision_repository(settings: EedomSettings):
    """Return a connected DecisionRepository, or NullRepository on failure.

    The connect/fallback logic moves here from the pipeline so core never
    constructs data-tier objects; the returned repo is ready to record to.
    """
    import structlog

    from eedom.data.db import DecisionRepository, NullRepository

    log = structlog.get_logger()
    try:
        repo = DecisionRepository(dsn=settings.db_dsn, query_timeout=10)
        if not repo.connect():
            log.warning("db_unavailable", msg="Falling back to NullRepository")
            return NullRepository()
        return repo
    except Exception:
        log.warning("db_init_failed", msg="Falling back to NullRepository")
        return NullRepository()


def build_audit_log_appender():
    """Return the parquet audit-log append function."""
    from eedom.data.parquet_writer import append_decisions

    return append_decisions


# Backward-compatible aliases. The epic renames `_make_*` -> `build_*`; these
# keep existing imports and inspect-based wiring guards working unchanged.
_make_decision_store = build_decision_store
_make_audit_sink = build_audit_sink
_make_publisher = build_publisher
_make_package_index = build_package_index


# ---------------------------------------------------------------------------
# bootstrap(settings)
# ---------------------------------------------------------------------------


def load_adapters() -> None:
    """Import every adapter module so its ``@REGISTRY.register`` factories run.

    ``autodiscover`` cannot cross tier boundaries (core may not import
    data/adapters), so the composition tier explicitly imports the adapter
    modules to populate the core-owned registries in ``eedom.core.registries``.
    Idempotent — imports are cached in ``sys.modules``.
    """
    import eedom.adapters.github_publisher  # noqa: F401
    import eedom.adapters.persistence  # noqa: F401
    import eedom.adapters.repo_snapshot  # noqa: F401
    import eedom.core.fake  # noqa: F401
    import eedom.core.file_source  # noqa: F401
    import eedom.core.json_report  # noqa: F401
    import eedom.core.opa_adapter  # noqa: F401
    import eedom.core.renderer  # noqa: F401
    import eedom.core.sarif  # noqa: F401
    import eedom.data.db  # noqa: F401
    import eedom.data.pkgsrc  # noqa: F401  (registers pypi/npm PACKAGE_SOURCES)
    import eedom.data.pypi  # noqa: F401
    import eedom.detectors.enrichers.enclosing_symbol  # noqa: F401
    import eedom.plugins._runners.graph_builder  # noqa: F401
    import eedom.plugins._runners.semgrep_runner  # noqa: F401
    import eedom.plugins.enrichers.code_graph  # noqa: F401
    import eedom.plugins.enrichers.semgrep  # noqa: F401
    import eedom.plugins.enrichers.supply_chain_threat  # noqa: F401


def bootstrap(settings: EedomSettings) -> ApplicationContext:
    """Wire concrete adapters from *settings* and return an ApplicationContext.

    All heavy imports are deferred to this function so that import-time cost
    is only paid when the production composition root is actually needed.
    """
    from eedom.core.subprocess_runner import SubprocessToolRunner
    from eedom.plugins import get_default_registry

    load_adapters()
    tool_runner = SubprocessToolRunner()
    registry = get_default_registry()

    # OPA policy path — use the bundled policies directory by default.
    policy_path = str(Path(__file__).parent.parent.parent.parent / "policies" / "policy.rego")

    policy_engine = POLICY_ENGINES.create(
        "opa",
        policy_path=policy_path,
        tool_runner=tool_runner,
        timeout=getattr(settings, "opa_timeout", 10),
    )

    # Single PyPI client serves both the narrow package_index port and the
    # pipeline's richer package_metadata collaborator.
    package_client = build_package_index(settings)

    return ApplicationContext(
        analyzer_registry=registry,
        policy_engine=policy_engine,
        tool_runner=tool_runner,
        decision_store=build_decision_store(settings),
        evidence_store=EVIDENCE_STORES.create("file", base_dir=Path(settings.evidence_path)),
        package_index=package_client,
        audit_sink=build_audit_sink(settings),
        publisher=build_publisher(settings),
        scanners=build_scanners(settings),
        evidence_writer=build_evidence_writer(settings),
        package_metadata=package_client,
        decision_repository=build_decision_repository(settings),
        audit_log_appender=build_audit_log_appender(),
        enrichers=build_enrichers(settings),
    )
