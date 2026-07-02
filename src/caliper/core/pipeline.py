"""Review pipeline — orchestrates scanners, policy eval, and decision assembly.

# tested-by: tests/unit/test_pipeline.py

Extracted from cli/main.py to keep the presentation layer thin and make the
core pipeline logic independently testable.
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path
from typing import TYPE_CHECKING

import orjson
import structlog

from caliper.core.accessors import (
    get_audit_log_appender,
    get_decision_repository,
    get_evidence_writer,
    get_package_metadata,
    get_scanners,
)
from caliper.core.config import CaliperSettings
from caliper.core.decision import assemble_decision
from caliper.core.diff import DependencyDiffDetector
from caliper.core.memo import generate_memo
from caliper.core.models import (
    DecisionVerdict,
    OperatingMode,
    PolicyEvaluation,
    ReviewDecision,
)
from caliper.core.normalizer import normalize_findings
from caliper.core.orchestrator import ScanOrchestrator
from caliper.core.pipeline_helpers import (  # noqa: F401
    count_transitive_deps_from_scan,
    parse_changes,
    resolve_git_sha,
    sbom_changes_to_requests,
)
from caliper.core.sbom_diff import diff_sboms
from caliper.core.seal import create_seal, find_previous_seal_hash

if TYPE_CHECKING:
    from collections.abc import Callable

    from caliper.core.context import ApplicationContext
    from caliper.core.ports import (
        DecisionRepositoryPort,
        EvidenceWriterPort,
        PackageMetadataPort,
    )

logger = structlog.get_logger()


def _build_package_metadata(req, pypi_meta: dict, transitive_dep_count: int | None) -> dict:
    """Assemble the ``package_metadata`` dict passed into policy evaluation.

    Extracts PyPI-derived signals from ``pypi_meta`` (already fetched by the
    caller) and merges them with request-derived fields. Both ``evaluate()``
    and ``evaluate_sbom()`` build this exact shape before it flows through
    ``_policy_evaluation`` -> OPA's ``input.pkg`` (SEAM-6) -- this is the one
    place it happens.
    """
    first_published_date = (
        pypi_meta.get("first_published_date") if pypi_meta.get("available") else None
    )
    last_release_date = pypi_meta.get("last_release_date") if pypi_meta.get("available") else None

    return {
        "name": req.package_name,
        "version": req.target_version,
        "ecosystem": req.ecosystem,
        "scope": req.scope,
        "first_published_date": first_published_date,
        "last_release_date": last_release_date,
        "transitive_dep_count": transitive_dep_count,
    }


def _policy_evaluation(
    context: ApplicationContext,
    config: CaliperSettings,
    findings: list,
    package_metadata: dict,
    repo_path: Path,
) -> PolicyEvaluation:
    """Evaluate findings through the injected policy engine port.

    Adapts the scan ``Finding`` list into the policy port's ``PolicyInput``,
    runs the enabled scribes (ADR-006/ADR-009 — e.g. reachability) over the
    adapted findings so opt-in policy exemptions (T-348) have something to
    read, and maps the returned ``PolicyDecision`` verdict onto a
    ``PolicyEvaluation``.
    """
    from caliper.core.accessors import get_scribes
    from caliper.core.plugin import PluginFinding
    from caliper.core.policy_port import PolicyInput
    from caliper.core.scribe import ScribeContext
    from caliper.core.scribe_pass import scribe_findings

    plugin_findings = [
        PluginFinding(
            id=f.advisory_id or "",
            severity=f.severity.value,
            message=f.description,
            category=f.category.value,
            package=f.package_name,
            version=f.version,
            metadata={
                "advisory_id": f.advisory_id or "",
                "source_tool": f.source_tool,
                "link_type": f.link_type,
                **({"license_id": f.license_id} if f.license_id else {}),
            },
        )
        for f in findings
    ]
    scribes = get_scribes(context)
    if scribes:
        plugin_findings = scribe_findings(
            plugin_findings,
            scribes,
            ScribeContext(repo_path=str(repo_path), scribe_timeout=config.scribe_timeout),
        )
    pd = context.policy_engine.evaluate(
        PolicyInput(findings=plugin_findings, packages=[package_metadata], config={})
    )
    verdict_str = getattr(pd, "verdict", "needs_review")
    try:
        verdict = DecisionVerdict(verdict_str)
    except (ValueError, AttributeError):
        verdict = DecisionVerdict.needs_review
    deny_reasons = list(getattr(pd, "deny_reasons", []) or [])
    warn_reasons = list(getattr(pd, "warn_reasons", []) or [])
    triggered = list(getattr(pd, "triggered_rules", []) or []) or (deny_reasons + warn_reasons)
    return PolicyEvaluation(
        decision=verdict,
        triggered_rules=triggered,
        # warn_reasons are the constraints surfaced under approve_with_constraints;
        # without this they render empty.
        constraints=warn_reasons,
        policy_bundle_version="port-injected",
    )


class ReviewPipeline:
    """End-to-end review pipeline — stateless per call.

    All data-tier collaborators (scanners, decision repository, evidence
    writer, package-metadata client, audit-log appender, policy engine) are
    received through the injected ``ApplicationContext`` and reached via the
    ``caliper.core.accessors`` get_* functions — core constructs nothing.
    """

    def __init__(self, config: CaliperSettings, context: ApplicationContext | None = None) -> None:
        self._config = config
        self._context = context

    def _require_context(self) -> ApplicationContext:
        if self._context is None:
            raise ValueError(
                "ReviewPipeline requires an ApplicationContext to evaluate changes; "
                "build one via caliper.composition.bootstrap.bootstrap(settings)."
            )
        return self._context

    def _run_requests(
        self,
        context: ApplicationContext,
        config: CaliperSettings,
        requests: list,
        repo_path: Path,
        run_id: str,
        pipeline_start: float,
        orchestrator: ScanOrchestrator,
        evidence: EvidenceWriterPort,
        pypi_client: PackageMetadataPort,
        db: DecisionRepositoryPort,
        log_event: str,
    ) -> list[ReviewDecision]:
        """Run scanners once, then evaluate each request through
        scan -> normalize -> policy -> decision -> memo, persisting each step.

        Shared by evaluate() and evaluate_sbom() (previously two independently
        drifting copies of this loop).
        """
        from datetime import date

        from caliper.core.baseline import filter_findings, finding_fingerprint, load_baseline
        from caliper.core.repo_config import load_repo_config

        decisions: list[ReviewDecision] = []
        scan_results = orchestrator.run(repo_path)

        repo_config = load_repo_config(repo_path)
        baseline = load_baseline(repo_path / repo_config.baseline.path)
        today = date.today()

        for req in requests:
            # Pipeline timeout enforcement (F-007)
            elapsed = time.monotonic() - pipeline_start
            if elapsed >= config.pipeline_timeout:
                logger.warning(
                    "pipeline_timeout_reached",
                    package=req.package_name,
                    elapsed=elapsed,
                )
                break

            logger.info(
                log_event,
                package=req.package_name,
                version=req.target_version,
                ecosystem=req.ecosystem,
            )

            try:
                db.save_request(req)
                db.save_scan_results(req.request_id, scan_results)

                findings, _summary = normalize_findings(scan_results)
                findings, suppressed, expired = filter_findings(findings, baseline, today)

                # Populate OPA metadata (F-012)
                pypi_meta = pypi_client.fetch_metadata(req.package_name, req.target_version)
                transitive_dep_count = count_transitive_deps_from_scan(scan_results)
                package_metadata = _build_package_metadata(req, pypi_meta, transitive_dep_count)

                policy_eval = _policy_evaluation(
                    context, config, findings, package_metadata, repo_path
                )
                db.save_policy_evaluation(req.request_id, policy_eval)

                pipeline_duration = time.monotonic() - pipeline_start
                evidence_bundle_path = evidence.get_path(run_id, req.package_name)

                decision = assemble_decision(
                    request=req,
                    findings=findings,
                    scan_results=scan_results,
                    policy_evaluation=policy_eval,
                    evidence_bundle_path=evidence_bundle_path,
                    pipeline_duration=pipeline_duration,
                )
                decision.baseline_suppressed_count = len(suppressed)
                decision.baseline_expired_count = len(expired)

                memo = generate_memo(decision)
                decision.memo_text = memo

                db.save_decision(req.request_id, decision)

                evidence.store(
                    run_id,
                    f"{req.package_name}/decision.json",
                    orjson.dumps(decision.model_dump(mode="json"), option=orjson.OPT_INDENT_2),
                )
                evidence.store(run_id, f"{req.package_name}/memo.md", memo)
                if suppressed or expired:
                    evidence.store(
                        run_id,
                        f"{req.package_name}/baseline.json",
                        orjson.dumps(
                            {
                                "suppressed": [finding_fingerprint(f) for f in suppressed],
                                "expired": [finding_fingerprint(f) for f in expired],
                            },
                            option=orjson.OPT_INDENT_2,
                        ),
                    )

                decisions.append(decision)

            except Exception:
                logger.exception("package_evaluation_failed", package=req.package_name)
                decisions.append(
                    ReviewDecision(
                        request=req,
                        decision=DecisionVerdict.needs_review,
                        findings=[],
                        scan_results=scan_results,
                        policy_evaluation=PolicyEvaluation(
                            decision=DecisionVerdict.needs_review,
                            triggered_rules=["package evaluation failed unexpectedly"],
                            policy_bundle_version="unknown",
                        ),
                        pipeline_duration_seconds=time.monotonic() - pipeline_start,
                    )
                )

        return decisions

    def _finalize(
        self,
        append_decisions: Callable,
        config: CaliperSettings,
        decisions: list[ReviewDecision],
        run_id: str,
        commit_sha: str | None,
    ) -> None:
        """Append decisions to the parquet audit log and seal evidence (both fail-open).

        Shared by evaluate() and evaluate_sbom() so the append/seal sequence and
        commit_sha stamping can never drift between the two entry points again
        (P01-1: evaluate_sbom() previously left commit_sha unstamped here).
        """
        # Append decisions to the parquet audit log (fail-open)
        append_decisions(Path(config.evidence_path), decisions, run_id)

        # Seal all evidence artifacts for this run (fail-open)
        try:
            evidence_run_dir = Path(config.evidence_path) / run_id
            previous_hash = find_previous_seal_hash(Path(config.evidence_path), run_id)
            create_seal(evidence_run_dir, run_id, commit_sha, previous_hash)
        except Exception:
            logger.exception("seal_creation_failed", run_id=run_id)

    def evaluate(
        self,
        diff_text: str,
        pr_url: str,
        team: str,
        mode: OperatingMode,
        repo_path: Path,
        commit_sha: str | None = None,
    ) -> list[ReviewDecision]:
        """Run the full review pipeline on dependency changes.

        Returns a list of ReviewDecision objects (one per changed package).
        Returns an empty list if no dependency changes are detected.
        """
        from datetime import UTC, datetime

        config = self._config
        pipeline_start = time.monotonic()

        if commit_sha is None:
            commit_sha = resolve_git_sha(repo_path)

        run_ts = datetime.now(UTC).strftime("%Y%m%d%H%M")
        short_sha = (commit_sha or "unknown")[:12]
        run_id = f"{short_sha}/{run_ts}"

        detector = DependencyDiffDetector()
        changed_files = detector.detect_changed_files(diff_text)
        if not changed_files:
            return []

        req_changes = parse_changes(detector, diff_text, changed_files)
        if not req_changes:
            return []

        requests = detector.create_requests(
            changes=req_changes,
            ecosystem="pypi",
            team=team,
            pr_url=pr_url,
            operating_mode=mode,
        )
        for req in requests:
            req.commit_sha = commit_sha
        if not requests:
            return []

        context = self._require_context()
        orchestrator = ScanOrchestrator(
            scanners=get_scanners(context),
            combined_timeout=config.combined_scanner_timeout,
        )
        evidence = get_evidence_writer(context)
        pypi_client = get_package_metadata(context)
        db = get_decision_repository(context)
        append_decisions = get_audit_log_appender(context)

        try:
            decisions = self._run_requests(
                context,
                config,
                requests,
                repo_path,
                run_id,
                pipeline_start,
                orchestrator,
                evidence,
                pypi_client,
                db,
                log_event="evaluating_package",
            )
            self._finalize(append_decisions, config, decisions, run_id, commit_sha)
        finally:
            db.close()
            with contextlib.suppress(Exception):
                pypi_client.close()

        return decisions

    def evaluate_sbom(
        self,
        before_sbom: dict,
        after_sbom: dict,
        pr_url: str,
        team: str,
        mode: OperatingMode,
        repo_path: Path,
        commit_sha: str | None = None,
    ) -> list[ReviewDecision]:
        """Evaluate dependency changes using SBOM diff. Ecosystem-agnostic.

        Diffs two CycloneDX SBOMs (before/after) to discover changed packages
        across any ecosystem Syft supports, then runs them through the same
        scanner → normalize → OPA → decision → memo pipeline as evaluate().

        Returns a list of ReviewDecision objects (one per changed package).
        Returns an empty list when no dependency changes are found.
        """
        from datetime import UTC, datetime

        config = self._config
        pipeline_start = time.monotonic()

        if commit_sha is None:
            commit_sha = resolve_git_sha(repo_path)

        run_ts = datetime.now(UTC).strftime("%Y%m%d%H%M")
        short_sha = (commit_sha or "unknown")[:12]
        run_id = f"{short_sha}/{run_ts}"

        changes = diff_sboms(before_sbom, after_sbom)
        if not changes:
            return []

        requests = sbom_changes_to_requests(
            changes=changes,
            team=team,
            pr_url=pr_url,
            operating_mode=mode,
        )
        if not requests:
            return []

        # Stamp the resolved commit SHA on each request so audit/parquet records it.
        # evaluate() does this; evaluate_sbom() left it None (P01-1).
        for req in requests:
            req.commit_sha = commit_sha

        context = self._require_context()
        orchestrator = ScanOrchestrator(
            scanners=get_scanners(context),
            combined_timeout=config.combined_scanner_timeout,
        )
        evidence = get_evidence_writer(context)
        pypi_client = get_package_metadata(context)
        db = get_decision_repository(context)
        append_decisions = get_audit_log_appender(context)

        try:
            decisions = self._run_requests(
                context,
                config,
                requests,
                repo_path,
                run_id,
                pipeline_start,
                orchestrator,
                evidence,
                pypi_client,
                db,
                log_event="evaluating_package_sbom",
            )
            self._finalize(append_decisions, config, decisions, run_id, commit_sha)
        finally:
            db.close()
            with contextlib.suppress(Exception):
                pypi_client.close()

        return decisions
