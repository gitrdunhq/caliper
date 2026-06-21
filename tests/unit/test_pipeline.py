"""Tests for eedom.core.pipeline — ReviewPipeline."""

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
    from eedom.composition.bootstrap import bootstrap_test

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
    """Build a minimal EedomSettings pointing at tmp_path."""
    from eedom.core.config import EedomSettings

    return EedomSettings(
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
        from eedom.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        pipeline = ReviewPipeline(config)

        decisions = pipeline.evaluate(
            diff_text=DIFF_NO_DEPS,
            pr_url="https://github.com/org/repo/pull/1",
            team="platform",
            mode=__import__("eedom.core.models", fromlist=["OperatingMode"]).OperatingMode.monitor,
            repo_path=tmp_path,
        )

        assert decisions == []

    def test_empty_diff_returns_empty_list(self, tmp_path: Path) -> None:
        """An empty diff string returns no decisions."""
        from eedom.core.models import OperatingMode
        from eedom.core.pipeline import ReviewPipeline

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
        from eedom.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        pipeline = ReviewPipeline(config)

        assert pipeline is not None

    def test_scanner_constructors_are_correct(self, tmp_path: Path) -> None:
        """Scanner instantiation with correct signatures does not raise."""
        from eedom.data.scanners.osv import OsvScanner
        from eedom.data.scanners.scancode import ScanCodeScanner
        from eedom.data.scanners.syft import SyftScanner
        from eedom.data.scanners.trivy import TrivyScanner

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
        from eedom.core.config import EedomSettings
        from eedom.core.models import OperatingMode
        from eedom.core.pipeline import ReviewPipeline

        config = EedomSettings(
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
            "eedom.core.pipeline.ScanOrchestrator.run",
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
        from eedom.core.models import OperatingMode
        from eedom.core.pipeline import ReviewPipeline

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
        from eedom.core.models import OperatingMode
        from eedom.core.pipeline import ReviewPipeline

        config = _make_config(tmp_path)
        ctx = _fake_pipeline_context()
        with patch("eedom.core.pipeline.ScanOrchestrator.run", return_value=[]):
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
        from eedom.core.models import ScanResult, ScanResultStatus
        from eedom.core.pipeline_helpers import count_transitive_deps_from_scan

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
        from eedom.core.pipeline_helpers import count_transitive_deps_from_scan

        assert count_transitive_deps_from_scan([]) is None

    def test_returns_none_when_syft_failed(self) -> None:
        """Returns None when Syft result status is failed."""
        from eedom.core.models import ScanResult, ScanResultStatus
        from eedom.core.pipeline_helpers import count_transitive_deps_from_scan

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
