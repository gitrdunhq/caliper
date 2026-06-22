"""Contract tests for AnalyzerRegistryPort, DecisionStorePort, EvidenceStorePort, PackageIndexPort.
# tested-by: tests/unit/test_ports.py

RED phase for issue #159 — these tests import symbols that do not exist yet.
All imports come from caliper.core.ports which does not yet exist.
Every test is expected to fail with ImportError until the production code is added.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# AnalyzerRegistryPort
# ---------------------------------------------------------------------------


class TestAnalyzerRegistryPortIsProtocol:
    def test_analyzer_registry_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import AnalyzerRegistryPort

        assert hasattr(AnalyzerRegistryPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(AnalyzerRegistryPort, "__mro__", [])
        )

    def test_analyzer_registry_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import AnalyzerRegistryPort

        try:
            isinstance(object(), AnalyzerRegistryPort)
        except TypeError as exc:
            pytest.fail(
                f"AnalyzerRegistryPort is not @runtime_checkable — isinstance() raised: {exc}"
            )

    def test_analyzer_registry_port_has_run_all_method(self) -> None:
        from caliper.core.ports import AnalyzerRegistryPort

        assert hasattr(
            AnalyzerRegistryPort, "run_all"
        ), "AnalyzerRegistryPort must declare a 'run_all' method"


class TestFakeAnalyzerRegistrySatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import AnalyzerRegistryPort

        class FakeRegistry:
            def run_all(self, files: list, repo_path: Path, **kwargs) -> list:
                return []

            def list(self, category=None, names=None) -> list:
                return []

        assert isinstance(FakeRegistry(), AnalyzerRegistryPort)

    def test_fake_returns_list_of_plugin_results(self) -> None:
        from caliper.core.ports import AnalyzerRegistryPort

        class FakeRegistry:
            def run_all(self, files: list, repo_path: Path, **kwargs) -> list:
                return []

            def list(self, category=None, names=None) -> list:
                return []

        registry = FakeRegistry()
        assert isinstance(registry, AnalyzerRegistryPort)
        result = registry.run_all(files=["/repo/foo.py"], repo_path=Path("/repo"))
        assert isinstance(result, list)

    def test_object_without_run_all_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import AnalyzerRegistryPort

        class NotARegistry:
            def execute_all(self) -> list:
                return []

        assert not isinstance(NotARegistry(), AnalyzerRegistryPort)


# ---------------------------------------------------------------------------
# DecisionStorePort
# ---------------------------------------------------------------------------


class TestDecisionStorePortIsProtocol:
    def test_decision_store_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import DecisionStorePort

        assert hasattr(DecisionStorePort, "__protocol_attrs__") or (
            typing.Protocol in getattr(DecisionStorePort, "__mro__", [])
        )

    def test_decision_store_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import DecisionStorePort

        try:
            isinstance(object(), DecisionStorePort)
        except TypeError as exc:
            pytest.fail(f"DecisionStorePort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_decision_store_port_has_save_decision_method(self) -> None:
        from caliper.core.ports import DecisionStorePort

        assert hasattr(
            DecisionStorePort, "save_decision"
        ), "DecisionStorePort must declare a 'save_decision' method"


class TestFakeDecisionStoreSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import DecisionStorePort

        class FakeStore:
            def save_decision(self, decision) -> None:
                pass

        assert isinstance(FakeStore(), DecisionStorePort)

    def test_fake_save_decision_accepts_any(self) -> None:
        from caliper.core.ports import DecisionStorePort

        saved: list = []

        class CapturingStore:
            def save_decision(self, decision) -> None:
                saved.append(decision)

        store = CapturingStore()
        assert isinstance(store, DecisionStorePort)
        store.save_decision({"id": "abc", "verdict": "approve"})
        assert len(saved) == 1
        assert saved[0]["verdict"] == "approve"

    def test_object_without_save_decision_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import DecisionStorePort

        class NotAStore:
            def persist(self, data) -> None:
                pass

        assert not isinstance(NotAStore(), DecisionStorePort)


# ---------------------------------------------------------------------------
# EvidenceStorePort
# ---------------------------------------------------------------------------


class TestEvidenceStorePortIsProtocol:
    def test_evidence_store_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import EvidenceStorePort

        assert hasattr(EvidenceStorePort, "__protocol_attrs__") or (
            typing.Protocol in getattr(EvidenceStorePort, "__mro__", [])
        )

    def test_evidence_store_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import EvidenceStorePort

        try:
            isinstance(object(), EvidenceStorePort)
        except TypeError as exc:
            pytest.fail(f"EvidenceStorePort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_evidence_store_port_has_write_artifact_method(self) -> None:
        from caliper.core.ports import EvidenceStorePort

        assert hasattr(
            EvidenceStorePort, "write_artifact"
        ), "EvidenceStorePort must declare a 'write_artifact' method"


class TestFakeEvidenceStoreSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import EvidenceStorePort

        class FakeEvidence:
            def write_artifact(self, path: str, content: bytes) -> str:
                return f"/evidence/{path}"

        assert isinstance(FakeEvidence(), EvidenceStorePort)

    def test_fake_write_artifact_returns_artifact_ref_string(self) -> None:
        from caliper.core.ports import EvidenceStorePort

        class FakeEvidence:
            def write_artifact(self, path: str, content: bytes) -> str:
                return f"/evidence/{path}"

        store = FakeEvidence()
        assert isinstance(store, EvidenceStorePort)
        ref = store.write_artifact("sbom.xml", b"<sbom/>")
        assert isinstance(ref, str)
        assert "sbom.xml" in ref

    def test_object_without_write_artifact_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import EvidenceStorePort

        class NotAnEvidenceStore:
            def store(self, key: str, name: str, content: bytes) -> str:
                return ""

        assert not isinstance(NotAnEvidenceStore(), EvidenceStorePort)


# ---------------------------------------------------------------------------
# PackageIndexPort
# ---------------------------------------------------------------------------


class TestPackageIndexPortIsProtocol:
    def test_package_index_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import PackageIndexPort

        assert hasattr(PackageIndexPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(PackageIndexPort, "__mro__", [])
        )

    def test_package_index_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import PackageIndexPort

        try:
            isinstance(object(), PackageIndexPort)
        except TypeError as exc:
            pytest.fail(f"PackageIndexPort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_package_index_port_has_get_package_info_method(self) -> None:
        from caliper.core.ports import PackageIndexPort

        assert hasattr(
            PackageIndexPort, "get_package_info"
        ), "PackageIndexPort must declare a 'get_package_info' method"


class TestFakePackageIndexSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import PackageIndexPort

        class FakeIndex:
            def get_package_info(self, name: str, ecosystem: str) -> dict:
                return {"name": name, "ecosystem": ecosystem, "latest_version": "1.0.0"}

        assert isinstance(FakeIndex(), PackageIndexPort)

    def test_fake_get_package_info_returns_dict(self) -> None:
        from caliper.core.ports import PackageIndexPort

        class FakeIndex:
            def get_package_info(self, name: str, ecosystem: str) -> dict:
                return {"name": name, "ecosystem": ecosystem, "latest_version": "2.3.4"}

        index = FakeIndex()
        assert isinstance(index, PackageIndexPort)
        info = index.get_package_info("requests", "pypi")
        assert isinstance(info, dict)
        assert info["name"] == "requests"
        assert info["ecosystem"] == "pypi"

    def test_fake_get_package_info_accepts_name_and_ecosystem(self) -> None:
        from caliper.core.ports import PackageIndexPort

        calls: list[tuple[str, str]] = []

        class RecordingIndex:
            def get_package_info(self, name: str, ecosystem: str) -> dict:
                calls.append((name, ecosystem))
                return {}

        index = RecordingIndex()
        assert isinstance(index, PackageIndexPort)
        index.get_package_info("lodash", "npm")
        assert calls == [("lodash", "npm")]

    def test_object_without_get_package_info_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import PackageIndexPort

        class NotAnIndex:
            def fetch(self, name: str) -> dict:
                return {}

        assert not isinstance(NotAnIndex(), PackageIndexPort)


# ---------------------------------------------------------------------------
# RepoSnapshotPort  (#175)
# ---------------------------------------------------------------------------


class TestRepoSnapshotPortIsProtocol:
    def test_repo_snapshot_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import RepoSnapshotPort

        assert hasattr(RepoSnapshotPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(RepoSnapshotPort, "__mro__", [])
        )

    def test_repo_snapshot_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import RepoSnapshotPort

        try:
            isinstance(object(), RepoSnapshotPort)
        except TypeError as exc:
            pytest.fail(f"RepoSnapshotPort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_repo_snapshot_port_has_checkout_ref_method(self) -> None:
        from caliper.core.ports import RepoSnapshotPort

        assert hasattr(
            RepoSnapshotPort, "checkout_ref"
        ), "RepoSnapshotPort must declare a 'checkout_ref' method"

    def test_repo_snapshot_port_has_cleanup_method(self) -> None:
        from caliper.core.ports import RepoSnapshotPort

        assert hasattr(
            RepoSnapshotPort, "cleanup"
        ), "RepoSnapshotPort must declare a 'cleanup' method"


class TestFakeRepoSnapshotSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import RepoSnapshotPort

        class FakeSnapshot:
            def checkout_ref(self, ref: str) -> Path:
                return Path(f"/tmp/snapshots/{ref}")

            def cleanup(self) -> None:
                pass

        assert isinstance(FakeSnapshot(), RepoSnapshotPort)

    def test_fake_checkout_ref_returns_path(self) -> None:
        from caliper.core.ports import RepoSnapshotPort

        class FakeSnapshot:
            def checkout_ref(self, ref: str) -> Path:
                return Path(f"/snapshots/{ref}")

            def cleanup(self) -> None:
                pass

        snap = FakeSnapshot()
        assert isinstance(snap, RepoSnapshotPort)
        result = snap.checkout_ref("abc123")
        assert isinstance(result, Path)
        assert "abc123" in str(result)

    def test_fake_cleanup_is_callable(self) -> None:
        from caliper.core.ports import RepoSnapshotPort

        cleaned: list[bool] = []

        class FakeSnapshot:
            def checkout_ref(self, ref: str) -> Path:
                return Path("/snapshots/HEAD")

            def cleanup(self) -> None:
                cleaned.append(True)

        snap = FakeSnapshot()
        assert isinstance(snap, RepoSnapshotPort)
        snap.cleanup()
        assert cleaned == [True]

    def test_object_without_cleanup_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import RepoSnapshotPort

        class MissingCleanup:
            def checkout_ref(self, ref: str) -> Path:
                return Path("/snapshots")

        assert not isinstance(MissingCleanup(), RepoSnapshotPort)

    def test_object_without_checkout_ref_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import RepoSnapshotPort

        class MissingCheckout:
            def cleanup(self) -> None:
                pass

        assert not isinstance(MissingCheckout(), RepoSnapshotPort)


# ---------------------------------------------------------------------------
# PullRequestPublisherPort  (#166)
# ---------------------------------------------------------------------------


class TestPullRequestPublisherPortIsProtocol:
    def test_pull_request_publisher_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import PullRequestPublisherPort

        assert hasattr(PullRequestPublisherPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(PullRequestPublisherPort, "__mro__", [])
        )

    def test_pull_request_publisher_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import PullRequestPublisherPort

        try:
            isinstance(object(), PullRequestPublisherPort)
        except TypeError as exc:
            pytest.fail(
                f"PullRequestPublisherPort is not @runtime_checkable — isinstance() raised: {exc}"
            )

    def test_pull_request_publisher_port_has_post_comment_method(self) -> None:
        from caliper.core.ports import PullRequestPublisherPort

        assert hasattr(
            PullRequestPublisherPort, "post_comment"
        ), "PullRequestPublisherPort must declare a 'post_comment' method"

    def test_pull_request_publisher_port_has_post_review_method(self) -> None:
        from caliper.core.ports import PullRequestPublisherPort

        assert hasattr(
            PullRequestPublisherPort, "post_review"
        ), "PullRequestPublisherPort must declare a 'post_review' method"

    def test_pull_request_publisher_port_has_add_label_method(self) -> None:
        from caliper.core.ports import PullRequestPublisherPort

        assert hasattr(
            PullRequestPublisherPort, "add_label"
        ), "PullRequestPublisherPort must declare an 'add_label' method"


class TestFakePullRequestPublisherSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import PullRequestPublisherPort

        class FakePublisher:
            def post_comment(self, repo: str, pr_num: int, body: str) -> bool:
                return True

            def post_review(self, repo: str, pr_num: int, review: dict) -> bool:
                return True

            def add_label(self, repo: str, pr_num: int, label: str) -> bool:
                return True

        assert isinstance(FakePublisher(), PullRequestPublisherPort)

    def test_fake_post_comment_returns_bool(self) -> None:
        from caliper.core.ports import PullRequestPublisherPort

        class FakePublisher:
            def post_comment(self, repo: str, pr_num: int, body: str) -> bool:
                return True

            def post_review(self, repo: str, pr_num: int, review: dict) -> bool:
                return True

            def add_label(self, repo: str, pr_num: int, label: str) -> bool:
                return True

        pub = FakePublisher()
        assert isinstance(pub, PullRequestPublisherPort)
        result = pub.post_comment("org/repo", 42, "looks good")
        assert isinstance(result, bool)
        assert result is True

    def test_fake_post_review_returns_bool(self) -> None:

        class FakePublisher:
            def post_comment(self, repo: str, pr_num: int, body: str) -> bool:
                return False

            def post_review(self, repo: str, pr_num: int, review: dict) -> bool:
                return True

            def add_label(self, repo: str, pr_num: int, label: str) -> bool:
                return True

        pub = FakePublisher()
        result = pub.post_review("org/repo", 7, {"event": "APPROVE"})
        assert isinstance(result, bool)

    def test_fake_add_label_returns_bool(self) -> None:

        class FakePublisher:
            def post_comment(self, repo: str, pr_num: int, body: str) -> bool:
                return True

            def post_review(self, repo: str, pr_num: int, review: dict) -> bool:
                return True

            def add_label(self, repo: str, pr_num: int, label: str) -> bool:
                return True

        pub = FakePublisher()
        result = pub.add_label("org/repo", 99, "security")
        assert isinstance(result, bool)

    def test_object_without_all_three_methods_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import PullRequestPublisherPort

        class PartialPublisher:
            def post_comment(self, repo: str, pr_num: int, body: str) -> bool:
                return True

        assert not isinstance(PartialPublisher(), PullRequestPublisherPort)


# ---------------------------------------------------------------------------
# ReviewReport dataclass + ReportRendererPort  (#168)
# ---------------------------------------------------------------------------


class TestReviewReportIsDataclass:
    def test_review_report_is_a_dataclass(self) -> None:
        import dataclasses

        from caliper.core.ports import ReviewReport

        assert dataclasses.is_dataclass(ReviewReport), "ReviewReport must be a dataclass"

    def test_review_report_has_verdict_field(self) -> None:
        import dataclasses

        from caliper.core.ports import ReviewReport

        field_names = {f.name for f in dataclasses.fields(ReviewReport)}
        assert "verdict" in field_names, "ReviewReport must have a 'verdict' field"

    def test_review_report_has_security_score_field(self) -> None:
        import dataclasses

        from caliper.core.ports import ReviewReport

        field_names = {f.name for f in dataclasses.fields(ReviewReport)}
        assert "security_score" in field_names, "ReviewReport must have a 'security_score' field"

    def test_review_report_has_quality_score_field(self) -> None:
        import dataclasses

        from caliper.core.ports import ReviewReport

        field_names = {f.name for f in dataclasses.fields(ReviewReport)}
        assert "quality_score" in field_names, "ReviewReport must have a 'quality_score' field"

    def test_review_report_has_plugin_results_field(self) -> None:
        import dataclasses

        from caliper.core.ports import ReviewReport

        field_names = {f.name for f in dataclasses.fields(ReviewReport)}
        assert "plugin_results" in field_names, "ReviewReport must have a 'plugin_results' field"

    def test_review_report_has_actionability_field(self) -> None:
        import dataclasses

        from caliper.core.ports import ReviewReport

        field_names = {f.name for f in dataclasses.fields(ReviewReport)}
        assert "actionability" in field_names, "ReviewReport must have an 'actionability' field"

    def test_review_report_can_be_instantiated(self) -> None:
        from caliper.core.ports import ReviewReport

        report = ReviewReport(
            verdict="approve",
            security_score=9.5,
            quality_score=8.0,
            plugin_results=[{"plugin": "trivy", "findings": []}],
            actionability={"critical": 0, "high": 1},
        )
        assert report.verdict == "approve"
        assert report.security_score == 9.5
        assert report.quality_score == 8.0
        assert isinstance(report.plugin_results, list)
        assert isinstance(report.actionability, dict)


class TestReportRendererPortIsProtocol:
    def test_report_renderer_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import ReportRendererPort

        assert hasattr(ReportRendererPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(ReportRendererPort, "__mro__", [])
        )

    def test_report_renderer_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import ReportRendererPort

        try:
            isinstance(object(), ReportRendererPort)
        except TypeError as exc:
            pytest.fail(
                f"ReportRendererPort is not @runtime_checkable — isinstance() raised: {exc}"
            )

    def test_report_renderer_port_has_render_method(self) -> None:
        from caliper.core.ports import ReportRendererPort

        assert hasattr(
            ReportRendererPort, "render"
        ), "ReportRendererPort must declare a 'render' method"


class TestFakeReportRendererSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import ReportRendererPort, ReviewReport

        class FakeRenderer:
            def render(self, report: ReviewReport) -> str:
                return f"verdict={report.verdict}"

        assert isinstance(FakeRenderer(), ReportRendererPort)

    def test_fake_render_returns_string(self) -> None:
        from caliper.core.ports import ReportRendererPort, ReviewReport

        class FakeRenderer:
            def render(self, report: ReviewReport) -> str:
                return f"## Review\nverdict: {report.verdict}\nsecurity: {report.security_score}"

        renderer = FakeRenderer()
        assert isinstance(renderer, ReportRendererPort)
        report = ReviewReport(
            verdict="reject",
            security_score=2.0,
            quality_score=5.5,
            plugin_results=[],
            actionability={},
        )
        output = renderer.render(report)
        assert isinstance(output, str)
        assert "reject" in output

    def test_object_without_render_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import ReportRendererPort

        class NotARenderer:
            def to_html(self, data) -> str:
                return "<html/>"

        assert not isinstance(NotARenderer(), ReportRendererPort)


# ---------------------------------------------------------------------------
# AuditSinkPort  (#172)
# ---------------------------------------------------------------------------


class TestAuditSinkPortIsProtocol:
    def test_audit_sink_port_is_a_protocol(self) -> None:
        import typing

        from caliper.core.ports import AuditSinkPort

        assert hasattr(AuditSinkPort, "__protocol_attrs__") or (
            typing.Protocol in getattr(AuditSinkPort, "__mro__", [])
        )

    def test_audit_sink_port_is_runtime_checkable(self) -> None:
        import pytest

        from caliper.core.ports import AuditSinkPort

        try:
            isinstance(object(), AuditSinkPort)
        except TypeError as exc:
            pytest.fail(f"AuditSinkPort is not @runtime_checkable — isinstance() raised: {exc}")

    def test_audit_sink_port_has_seal_method(self) -> None:
        from caliper.core.ports import AuditSinkPort

        assert hasattr(AuditSinkPort, "seal"), "AuditSinkPort must declare a 'seal' method"

    def test_audit_sink_port_has_append_audit_log_method(self) -> None:
        from caliper.core.ports import AuditSinkPort

        assert hasattr(
            AuditSinkPort, "append_audit_log"
        ), "AuditSinkPort must declare an 'append_audit_log' method"


class TestFakeAuditSinkSatisfiesPort:
    def test_fake_is_instance_of_protocol(self) -> None:
        from caliper.core.ports import AuditSinkPort

        class FakeSink:
            def seal(self, artifact_refs: list[str]) -> str:
                return "sha256:deadbeef"

            def append_audit_log(self, entry: dict) -> None:
                pass

        assert isinstance(FakeSink(), AuditSinkPort)

    def test_fake_seal_returns_hash_string(self) -> None:
        from caliper.core.ports import AuditSinkPort

        class FakeSink:
            def seal(self, artifact_refs: list[str]) -> str:
                return f"sha256:{''.join(artifact_refs)}"

            def append_audit_log(self, entry: dict) -> None:
                pass

        sink = FakeSink()
        assert isinstance(sink, AuditSinkPort)
        result = sink.seal(["ref1", "ref2"])
        assert isinstance(result, str)
        assert "sha256:" in result

    def test_fake_append_audit_log_accepts_dict(self) -> None:
        from caliper.core.ports import AuditSinkPort

        log: list[dict] = []

        class CapturingSink:
            def seal(self, artifact_refs: list[str]) -> str:
                return "sha256:0000"

            def append_audit_log(self, entry: dict) -> None:
                log.append(entry)

        sink = CapturingSink()
        assert isinstance(sink, AuditSinkPort)
        entry = {"action": "scan_complete", "repo": "org/repo", "sha": "abc123"}
        sink.append_audit_log(entry)
        assert len(log) == 1
        assert log[0]["action"] == "scan_complete"

    def test_object_without_seal_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import AuditSinkPort

        class MissingSeal:
            def append_audit_log(self, entry: dict) -> None:
                pass

        assert not isinstance(MissingSeal(), AuditSinkPort)

    def test_object_without_append_audit_log_does_not_satisfy_protocol(self) -> None:
        from caliper.core.ports import AuditSinkPort

        class MissingAppend:
            def seal(self, artifact_refs: list[str]) -> str:
                return "sha256:0000"

        assert not isinstance(MissingAppend(), AuditSinkPort)
