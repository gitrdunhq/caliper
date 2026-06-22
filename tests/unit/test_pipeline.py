"""Tests for caliper.core.pipeline — ReviewPipeline."""

# tested-by: tests/unit/test_pipeline.py

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class _FakeRepo:
    """Rich decision-repository stand-in (DecisionRepositoryPort)."""

    def __init__(self) -> None:
        self.closed = False

    def connect(self) -> bool:
        return True

    def save_request(self, request) -> None: ...

    def save_scan_results(self, request_id, results) -> None: ...

    def save_policy_evaluation(self, request_id, evaluation) -> None: ...

    def save_decision(self, request_id, decision) -> None: ...

    def close(self) -> None:
        self.closed = True


class _FakeEvidenceWriter:
    def get_path(self, run_id: str, package: str) -> str:
        return f"{run_id}/{package}"

    def store(self, run_id: str, rel_path: str, content) -> None:
        return None


class _FakePyPI:
    def __init__(self) -> None:
        self.closed = False

    def fetch_metadata(self, name: str, version: str) -> dict:
        return {"available": False}

    def close(self) -> None:
        self.closed = True


def _fake_pipeline_context(scanners=None):
    """An all-fake ApplicationContext with the pipeline collaborators wired."""
    from caliper.composition.bootstrap import bootstrap_test

    ctx = bootstrap_test()
    ctx.scanners = scanners if scanners is not None else []
    ctx.evidence_writer = _FakeEvidenceWriter()
    ctx.package_metadata = _FakePyPI()
    ctx.decision_repository = _FakeRepo()
    ctx.audit_log_appender = lambda evidence_path, decisions, run_id: None
    return ctx


DIFF_NO_DEPS = """\
diff --git a/src/app.py b/src/app.py
index 000..111 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1 +1,2 @@
+print("hello")
"""

DIFF_WITH_REQUIREMENTS = """\
diff --git a/requirements.txt b/requirements.txt
index 000..111 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 flask==2.0.0
-requests==2.25.1
+requests==2.26.0
+numpy==1.21.0
"""


def _make_config(tmp_path: Path):
    """Build a minimal CaliperSettings pointing at tmp_path."""
    from caliper.core.config import CaliperSettings

    return CaliperSettings(
        db_dsn="postgresql://test:test@localhost/test",
        evidence_path=str(tmp_path / "evidence"),
        opa_policy_path=str(tmp_path / "policies"),
        enabled_scanners=[],
        pipeline_timeout=300,
        combined_scanner_timeout=180,
    )


class TestReviewPipelineNoDependencyChanges:
    """Pipeline returns empty list when no dependency files changed."""

    def test_no_dependency_changes_returns_empty_list(self, tmp_path: Path) -> None:
        """When the diff has no dependency files, evaluate returns []."""
        from caliper.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        pipeline = ReviewPipeline(config)

        decisions = pipeline.evaluate(
            diff_text=DIFF_NO_DEPS,
            pr_url="https://github.com/org/repo/pull/1",
            team="platform",
            mode=__import__(
                "caliper.core.models", fromlist=["OperatingMode"]
            ).OperatingMode.monitor,
            repo_path=tmp_path,
        )

        assert decisions == []

    def test_empty_diff_returns_empty_list(self, tmp_path: Path) -> None:
        """An empty diff string returns no decisions."""
        from caliper.core.models import OperatingMode
        from caliper.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        pipeline = ReviewPipeline(config)

        decisions = pipeline.evaluate(
            diff_text="",
            pr_url="https://github.com/org/repo/pull/1",
            team="platform",
            mode=OperatingMode.monitor,
            repo_path=tmp_path,
        )

        assert decisions == []


class TestReviewPipelineConstruction:
    """ReviewPipeline can be constructed without raising."""

    def test_constructor_does_not_raise(self, tmp_path: Path) -> None:
        """Importing and constructing ReviewPipeline with valid config raises nothing."""
        from caliper.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        pipeline = ReviewPipeline(config)

        assert pipeline is not None

    def test_scanner_constructors_are_correct(self, tmp_path: Path) -> None:
        """Scanner instantiation with correct signatures does not raise."""
        from caliper.data.scanners.osv import OsvScanner
        from caliper.data.scanners.scancode import ScanCodeScanner
        from caliper.data.scanners.syft import SyftScanner
        from caliper.data.scanners.trivy import TrivyScanner

        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # These must not raise — verifies correct constructor signatures
        syft = SyftScanner(evidence_dir=evidence_dir)
        scancode = ScanCodeScanner(evidence_dir=evidence_dir)
        osv = OsvScanner()
        trivy = TrivyScanner()

        assert syft.name == "syft"
        assert scancode.name == "scancode"
        assert osv.name == "osv-scanner"
        assert trivy.name == "trivy"


class TestReviewPipelineTimeoutEnforcement:
    """Pipeline breaks the per-package loop when pipeline_timeout is exceeded."""

    def test_timeout_breaks_loop(self, tmp_path: Path) -> None:
        """When pipeline_timeout=0, the loop exits before processing any package."""
        from caliper.core.config import CaliperSettings
        from caliper.core.models import OperatingMode
        from caliper.core.pipeline import ReviewPipeline

        config = CaliperSettings(
            db_dsn="postgresql://test:test@localhost/test",
            evidence_path=str(tmp_path / "evidence"),
            opa_policy_path=str(tmp_path / "policies"),
            enabled_scanners=[],
            pipeline_timeout=0,  # immediate timeout
            combined_scanner_timeout=180,
        )

        pipeline = ReviewPipeline(config, context=_fake_pipeline_context())

        # Patch orchestrator.run to return empty results quickly
        with patch(
            "caliper.core.pipeline.ScanOrchestrator.run",
            return_value=[],
        ):
            decisions = pipeline.evaluate(
                diff_text=DIFF_WITH_REQUIREMENTS,
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                mode=OperatingMode.monitor,
                repo_path=tmp_path,
            )

        # With timeout=0 and scan_results=[], all packages are skipped
        assert decisions == []


class TestReviewPipelineRequiresContext:
    """The pipeline raises a clear error if it reaches real work without a context."""

    def test_evaluate_without_context_raises_on_real_changes(self, tmp_path: Path) -> None:
        from caliper.core.models import OperatingMode
        from caliper.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        # No context, but the diff carries real dependency changes.
        with pytest.raises(ValueError, match="ApplicationContext"):
            ReviewPipeline(config).evaluate(
                diff_text=DIFF_WITH_REQUIREMENTS,
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                mode=OperatingMode.monitor,
                repo_path=tmp_path,
            )


class TestReviewPipelineUsesInjectedCollaborators:
    """End-to-end-ish: the pipeline drives the injected fakes, no data imports."""

    def test_injected_repo_and_pypi_are_closed(self, tmp_path: Path) -> None:
        from caliper.core.models import OperatingMode
        from caliper.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        ctx = _fake_pipeline_context()
        with patch("caliper.core.pipeline.ScanOrchestrator.run", return_value=[]):
            ReviewPipeline(config, context=ctx).evaluate(
                diff_text=DIFF_WITH_REQUIREMENTS,
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                mode=OperatingMode.monitor,
                repo_path=tmp_path,
            )

        assert ctx.decision_repository.closed is True
        assert ctx.package_metadata.closed is True


class TestCountTransitiveDepsFromScan:
    """count_transitive_deps_from_scan extracts component count from Syft result."""

    def test_extracts_count_from_syft_message(self) -> None:
        """Parses component count from well-formed Syft message."""
        from caliper.core.models import ScanResult, ScanResultStatus
        from caliper.core.pipeline_helpers import count_transitive_deps_from_scan

        results = [
            ScanResult(
                tool_name="syft",
                status=ScanResultStatus.success,
                findings=[],
                message="SBOM generated: 42 components detected",
                duration_seconds=1.0,
            )
        ]

        assert count_transitive_deps_from_scan(results) == 42

    def test_returns_none_when_syft_not_in_results(self) -> None:
        """Returns None when no Syft result is present."""
        from caliper.core.pipeline_helpers import count_transitive_deps_from_scan

        assert count_transitive_deps_from_scan([]) is None

    def test_returns_none_when_syft_failed(self) -> None:
        """Returns None when Syft result status is failed."""
        from caliper.core.models import ScanResult, ScanResultStatus
        from caliper.core.pipeline_helpers import count_transitive_deps_from_scan

        results = [
            ScanResult(
                tool_name="syft",
                status=ScanResultStatus.failed,
                findings=[],
                message="SBOM generated: 10 components detected",
                duration_seconds=0.5,
            )
        ]

        assert count_transitive_deps_from_scan(results) is None


# ---------------------------------------------------------------------------
# Regression P03-3 — PolicyEvaluation.constraints must be populated from
# warn_reasons so approve_with_constraints surfaces readable context.
# ---------------------------------------------------------------------------


class TestPolicyEvaluationConstraintsRegression:
    def test_constraints_populated_from_warn_reasons(self) -> None:
        """When OPA returns warn messages, PolicyEvaluation.constraints must be
        populated (regression for P03-3: previously constraints was always [])."""
        from unittest.mock import MagicMock

        from caliper.core.models import DecisionVerdict, PolicyEvaluation
        from caliper.core.pipeline import _policy_evaluation
        from caliper.core.policy_port import PolicyDecision

        warn_msgs = ["package age < 30 days", "high transitive dep count"]

        fake_engine = MagicMock()
        fake_engine.evaluate.return_value = PolicyDecision(
            verdict="approve_with_constraints",
            deny_reasons=[],
            warn_reasons=warn_msgs,
            triggered_rules=warn_msgs,
        )

        fake_ctx = MagicMock()
        fake_ctx.policy_engine = fake_engine

        result = _policy_evaluation(fake_ctx, [], {})

        assert isinstance(result, PolicyEvaluation)
        assert result.decision == DecisionVerdict.approve_with_constraints
        assert set(warn_msgs).issubset(set(result.constraints)), (
            "PolicyEvaluation.constraints must be populated from warn_reasons — "
            f"expected {warn_msgs!r} in constraints, got {result.constraints!r}"
        )

    def test_constraints_empty_on_full_approve(self) -> None:
        """constraints must be empty when OPA approves unconditionally."""
        from unittest.mock import MagicMock

        from caliper.core.models import DecisionVerdict
        from caliper.core.pipeline import _policy_evaluation
        from caliper.core.policy_port import PolicyDecision

        fake_engine = MagicMock()
        fake_engine.evaluate.return_value = PolicyDecision(
            verdict="approve",
            deny_reasons=[],
            warn_reasons=[],
            triggered_rules=[],
        )

        fake_ctx = MagicMock()
        fake_ctx.policy_engine = fake_engine

        result = _policy_evaluation(fake_ctx, [], {})

        assert result.decision == DecisionVerdict.approve
        assert result.constraints == []


# ---------------------------------------------------------------------------
# Regression P01-1 — evaluate_sbom must stamp commit_sha onto each request
# ---------------------------------------------------------------------------

_BEFORE_SBOM: dict = {"components": []}
_AFTER_SBOM: dict = {
    "components": [
        {
            "name": "requests",
            "version": "2.32.0",
            "purl": "pkg:pypi/requests@2.32.0",
            "type": "library",
        }
    ]
}


class TestEvaluateSbomCommitShaRegression:
    """Regression for P01-1: evaluate_sbom left req.commit_sha=None."""

    def test_evaluate_sbom_stamps_resolved_commit_sha(self, tmp_path: Path) -> None:
        """Each ReviewRequest produced by evaluate_sbom must carry the resolved
        commit SHA (not None).  Before the fix, commit_sha was never assigned
        inside evaluate_sbom(), so audit/parquet records had no commit reference.
        """
        from caliper.core.models import OperatingMode
        from caliper.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        ctx = _fake_pipeline_context()

        # Capture the requests actually built during the run so we can assert
        # their commit_sha field after the pipeline completes.
        captured_requests: list = []
        original_save = ctx.decision_repository.save_request

        def _capturing_save(req) -> None:
            captured_requests.append(req)
            return original_save(req)

        ctx.decision_repository.save_request = _capturing_save

        fixed_sha = "deadbeef1234567890abcdef12345678deadbeef"

        with (
            patch("caliper.core.pipeline.ScanOrchestrator.run", return_value=[]),
            patch("caliper.core.pipeline.resolve_git_sha", return_value=fixed_sha),
        ):
            decisions = ReviewPipeline(config, context=ctx).evaluate_sbom(
                before_sbom=_BEFORE_SBOM,
                after_sbom=_AFTER_SBOM,
                pr_url="https://github.com/org/repo/pull/7",
                team="platform",
                mode=OperatingMode.monitor,
                repo_path=tmp_path,
            )

        assert len(decisions) >= 1, "Expected at least one decision from the sbom diff"
        assert len(captured_requests) >= 1, "Expected at least one request to be saved"

        for req in captured_requests:
            assert req.commit_sha == fixed_sha, (
                f"P01-1 regression: req.commit_sha should be {fixed_sha!r} "
                f"but got {req.commit_sha!r}. evaluate_sbom() must stamp commit_sha "
                "on each ReviewRequest before the per-package loop."
            )

    def test_evaluate_sbom_commit_sha_explicit_arg_not_overridden(self, tmp_path: Path) -> None:
        """When commit_sha is passed explicitly it must be used as-is, not
        overridden by resolve_git_sha."""
        from caliper.core.models import OperatingMode
        from caliper.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        ctx = _fake_pipeline_context()

        captured_requests: list = []
        original_save = ctx.decision_repository.save_request

        def _capturing_save(req) -> None:
            captured_requests.append(req)
            return original_save(req)

        ctx.decision_repository.save_request = _capturing_save

        explicit_sha = "aaaa0000bbbb1111cccc2222dddd3333eeee4444"

        with patch("caliper.core.pipeline.ScanOrchestrator.run", return_value=[]):
            ReviewPipeline(config, context=ctx).evaluate_sbom(
                before_sbom=_BEFORE_SBOM,
                after_sbom=_AFTER_SBOM,
                pr_url="https://github.com/org/repo/pull/8",
                team="platform",
                mode=OperatingMode.monitor,
                repo_path=tmp_path,
                commit_sha=explicit_sha,
            )

        for req in captured_requests:
            assert req.commit_sha == explicit_sha, (
                f"P01-1 regression: explicit commit_sha {explicit_sha!r} "
                f"was not stamped; got {req.commit_sha!r}"
            )
