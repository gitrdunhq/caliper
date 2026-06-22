"""Deterministic regression contracts for known runtime bug rules.

# tested-by: tests/unit/test_deterministic_runtime_contracts.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

_REQUIREMENTS_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
index 000..111 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -0,0 +1 @@
+requests==2.31.0
"""


def _make_config(tmp_path: Path, **overrides: object):
    from caliper.core.config import CaliperSettings

    defaults: dict[str, object] = {
        "db_dsn": "postgresql://test:test@localhost/test",
        "evidence_path": str(tmp_path / "evidence"),
        "opa_policy_path": str(tmp_path / "policy.rego"),
        "enabled_scanners": [],
        "scanner_timeout": 13,
        "combined_scanner_timeout": 17,
        "opa_timeout": 19,
        "pipeline_timeout": 300,
        "pypi_timeout": 23,
    }
    defaults.update(overrides)
    return CaliperSettings(**defaults)


def _component(name: str, version: str, purl: str) -> dict[str, str]:
    return {"type": "library", "name": name, "version": version, "purl": purl}


def _sbom(*components: dict[str, str]) -> dict[str, object]:
    return {"bomFormat": "CycloneDX", "components": list(components)}


def _make_review_decision(verdict=None):
    from caliper.core.models import (
        DecisionVerdict,
        OperatingMode,
        PolicyEvaluation,
        RequestType,
        ReviewDecision,
        ReviewRequest,
    )

    decision = verdict or DecisionVerdict.reject
    request = ReviewRequest(
        request_type=RequestType.upgrade,
        ecosystem="pypi",
        package_name="dangerlib",
        current_version="1.0.0",
        target_version="1.0.1",
        team="platform",
        pr_url="https://github.com/org/repo/pull/1",
        operating_mode=OperatingMode.advise,
    )
    policy = PolicyEvaluation(
        decision=decision,
        triggered_rules=["deterministic policy reject"],
        policy_bundle_version="test",
    )
    return ReviewDecision(
        request=request,
        decision=decision,
        findings=[],
        scan_results=[],
        policy_evaluation=policy,
        pipeline_duration_seconds=0.01,
    )


class _FakeDb:
    instances: list[_FakeDb] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.closed = False
        self.saved_requests: list[object] = []
        _FakeDb.instances.append(self)

    def connect(self) -> bool:
        return True

    def save_request(self, request: object) -> None:
        self.saved_requests.append(request)

    def save_scan_results(self, request_id: object, scan_results: list[object]) -> None:
        return None

    def save_policy_evaluation(self, request_id: object, policy_eval: object) -> None:
        return None

    def save_decision(self, request_id: object, decision: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeEvidence:
    def __init__(self, root_path: str) -> None:
        self.root = Path(root_path)
        self.stored: list[tuple[str, str]] = []

    def get_path(self, key: str, artifact_name: str) -> str:
        return str(self.root / key / artifact_name)

    def store(self, key: str, artifact_name: str, content: bytes | str) -> str:
        self.stored.append((key, artifact_name))
        target = self.root / key / artifact_name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
        return str(target)


class _FakePyPIClient:
    instances: list[_FakePyPIClient] = []

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self.closed = False
        _FakePyPIClient.instances.append(self)

    def fetch_metadata(self, package_name: str, version: str | None = None) -> dict[str, object]:
        return {"available": False}

    def close(self) -> None:
        self.closed = True


class _FakePolicyEnginePort:
    """Fake PolicyEnginePort — returns an 'approve' PolicyDecision via the port."""

    instances: list[_FakePolicyEnginePort] = []

    def __init__(self) -> None:
        _FakePolicyEnginePort.instances.append(self)

    def evaluate(self, policy_input: object):
        from caliper.core.policy_port import PolicyDecision

        return PolicyDecision(verdict="approve")


class _FakeOrchestrator:
    instances: list[_FakeOrchestrator] = []

    def __init__(self, scanners: list[object], combined_timeout: int) -> None:
        self.scanners = scanners
        self.combined_timeout = combined_timeout
        _FakeOrchestrator.instances.append(self)

    def run(self, repo_path: Path) -> list[object]:
        return []


def _patch_pipeline_runtime(
    monkeypatch: pytest.MonkeyPatch,
    config: object,
    append_calls: list[tuple[Path, list[object], str]] | None = None,
):
    """Patch the orchestrator and return an all-fake ApplicationContext.

    Post-inversion (#409) the pipeline pulls its data collaborators from the
    injected context, so the harness builds a fake context the test passes to
    ``ReviewPipeline(config, context=...)`` instead of monkeypatching internals.
    """
    import caliper.core.pipeline as pipeline_mod
    from caliper.composition.bootstrap import bootstrap_test

    _FakeDb.instances.clear()
    _FakePyPIClient.instances.clear()
    _FakePolicyEnginePort.instances.clear()
    _FakeOrchestrator.instances.clear()

    def append_decisions(evidence_root: Path, decisions: list[object], run_id: str = "") -> Path:
        if append_calls is not None:
            append_calls.append((evidence_root, decisions, run_id))
        return evidence_root / "decisions.parquet"

    monkeypatch.setattr(pipeline_mod, "ScanOrchestrator", _FakeOrchestrator)

    ctx = bootstrap_test()
    ctx.policy_engine = _FakePolicyEnginePort()
    ctx.scanners = []
    ctx.evidence_writer = _FakeEvidence(str(config.evidence_path))
    ctx.package_metadata = _FakePyPIClient()
    ctx.decision_repository = _FakeDb()
    ctx.audit_log_appender = append_decisions
    return ctx


def test_202_bootstrapped_opa_input_matches_bundled_policy_schema() -> None:
    """Critical findings must reach OPA with the schema that policy.rego can deny."""
    from caliper.core.opa_adapter import OpaRegoAdapter
    from caliper.core.plugin import PluginFinding
    from caliper.core.policy_port import PolicyInput
    from caliper.core.tool_runner import ToolInvocation, ToolResult

    class CapturingRunner:
        def __init__(self) -> None:
            self.payload: dict[str, object] | None = None

        def run(self, invocation: ToolInvocation) -> ToolResult:
            input_path = Path(invocation.cmd[invocation.cmd.index("-i") + 1])
            self.payload = json.loads(input_path.read_text())
            stdout = json.dumps({"result": [{"expressions": [{"value": {"deny": []}}]}]})
            return ToolResult(exit_code=0, stdout=stdout, stderr="")

    runner = CapturingRunner()
    adapter = OpaRegoAdapter(policy_path="/fake/policy.rego", tool_runner=runner)
    finding = PluginFinding(
        id="CVE-2026-0001",
        severity="high",
        message="critical vulnerability",
        category="vulnerability",
        package="dangerlib",
        version="1.0.0",
        metadata={"advisory_id": "CVE-2026-0001"},
    )

    adapter.evaluate(
        PolicyInput(
            findings=[finding],
            packages=[{"name": "dangerlib", "version": "1.0.0", "ecosystem": "pypi"}],
            config={},
        )
    )

    assert runner.payload is not None
    assert runner.payload["pkg"] == {
        "name": "dangerlib",
        "version": "1.0.0",
        "ecosystem": "pypi",
    }
    assert runner.payload["config"]["rules_enabled"]["critical_vuln"] is True
    opa_finding = runner.payload["findings"][0]
    assert opa_finding["category"] == "vulnerability"
    assert opa_finding["package_name"] == "dangerlib"
    assert opa_finding["advisory_id"] == "CVE-2026-0001"


def test_204_production_bootstrap_does_not_wire_null_or_fake_adapters(tmp_path: Path) -> None:
    from caliper.composition.bootstrap import bootstrap

    ctx = bootstrap(_make_config(tmp_path))
    wired = {
        "decision_store": ctx.decision_store,
        "evidence_store": ctx.evidence_store,
        "package_index": ctx.package_index,
        "audit_sink": ctx.audit_sink,
        "publisher": ctx.publisher,
    }

    offenders = {
        name: type(adapter).__name__
        for name, adapter in wired.items()
        if type(adapter).__name__.startswith(("_Fake", "Fake", "Null"))
    }
    assert offenders == {}


def test_205_block_mode_accepts_typed_review_decisions_not_llm_response_shape() -> None:
    from caliper.agent.main import ForemanAgent
    from caliper.core.models import DecisionVerdict

    agent = ForemanAgent(config=object())
    response = SimpleNamespace(value={"decisions": [_make_review_decision(DecisionVerdict.reject)]})

    agent._extract_reject_from_tool_results(response)

    assert agent._decisions_have_reject is True


def test_206_base_sbom_generation_does_not_checkout_active_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from caliper.agent import tool_helpers

    commands: list[list[str]] = []

    @dataclass
    class Completed:
        stdout: str = ""
        returncode: int = 0

    def fake_run(cmd: list[str], **kwargs: object) -> Completed:
        commands.append(cmd)
        if cmd[:4] == ["git", "-C", str(tmp_path), "merge-base"]:
            return Completed(stdout="base-sha\n")
        if cmd[:4] == ["git", "-C", str(tmp_path), "rev-parse"]:
            return Completed(stdout="current-sha\n")
        return Completed()

    monkeypatch.setattr(tool_helpers.subprocess, "run", fake_run)
    monkeypatch.setattr(tool_helpers, "run_syft", lambda repo_path: {"components": []})

    tool_helpers._generate_base_sbom(str(tmp_path))

    checkout_commands = [cmd for cmd in commands if len(cmd) > 3 and cmd[3] == "checkout"]
    assert checkout_commands == []


def test_208_evidence_store_creates_parent_dirs_for_package_artifacts(tmp_path: Path) -> None:
    from caliper.data.evidence import EvidenceStore

    store = EvidenceStore(root_path=str(tmp_path))

    result = store.store("run-123", "dangerlib/decision.json", b'{"decision":"reject"}')

    assert result
    assert Path(result).read_bytes() == b'{"decision":"reject"}'


def test_209_composition_passes_scanner_timeout_to_each_scanner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Scanner construction moved to the composition tier (#409); build_scanners
    # resolves enabled scanners from the SCANNERS registry. This detector asserts
    # every scanner receives the configured timeout.
    from caliper.composition.bootstrap import build_scanners

    scanner_calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def scanner_class(name: str) -> type:
        class RecordingScanner:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.name = name
                scanner_calls.append((name, args, kwargs))

        return RecordingScanner

    # The registry factories resolve the scanner classes from their modules at
    # call time, so patching the module attribute records the construction.
    monkeypatch.setattr("caliper.data.scanners.syft.SyftScanner", scanner_class("syft"))
    monkeypatch.setattr("caliper.data.scanners.osv.OsvScanner", scanner_class("osv-scanner"))
    monkeypatch.setattr("caliper.data.scanners.trivy.TrivyScanner", scanner_class("trivy"))
    monkeypatch.setattr("caliper.data.scanners.scancode.ScanCodeScanner", scanner_class("scancode"))

    config = _make_config(
        tmp_path,
        enabled_scanners=["syft", "osv-scanner", "trivy", "scancode"],
        scancode_timeout=7,
    )

    build_scanners(config)

    assert {name for name, _args, _kwargs in scanner_calls} == {
        "syft",
        "osv-scanner",
        "trivy",
        "scancode",
    }
    assert all(kwargs.get("timeout") == 7 for _name, _args, kwargs in scanner_calls)


def test_209_bootstrap_passes_opa_timeout_to_policy_adapter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import caliper.core.opa_adapter as opa_adapter_mod
    from caliper.composition.bootstrap import bootstrap

    seen: dict[str, object] = {}

    class SpyOpaRegoAdapter:
        def __init__(
            self,
            policy_path: str,
            tool_runner: object,
            timeout: int | None = None,
        ) -> None:
            seen["policy_path"] = policy_path
            seen["timeout"] = timeout

    monkeypatch.setattr(opa_adapter_mod, "OpaRegoAdapter", SpyOpaRegoAdapter)

    bootstrap(_make_config(tmp_path, opa_timeout=29))

    assert seen["timeout"] == 29


@pytest.mark.parametrize(
    "filename,after_line",
    [
        ("setup.py", "install_requires=['requests==2.31.0']"),
        ("setup.cfg", "install_requires = requests==2.31.0"),
        ("Pipfile", 'requests = "==2.31.0"'),
        ("Pipfile.lock", '"requests": {"version": "==2.31.0"}'),
        ("poetry.lock", 'name = "requests"'),
    ],
)
def test_210_detected_dependency_manifests_have_parser_coverage(
    filename: str, after_line: str
) -> None:
    from caliper.core.diff import DependencyDiffDetector
    from caliper.core.pipeline_helpers import parse_changes

    diff = (
        f"diff --git a/{filename} b/{filename}\n"
        "index 000..111 100644\n"
        f"--- a/{filename}\n"
        f"+++ b/{filename}\n"
        "@@ -0,0 +1 @@\n"
        f"+{after_line}\n"
    )
    detector = DependencyDiffDetector()
    changed_files = detector.detect_changed_files(diff)
    changes = parse_changes(detector, diff, changed_files)

    assert (
        not changed_files or changes
    ), f"{filename} is detected as a dependency manifest but has no parser coverage"


def test_211_plugin_errors_are_degraded_not_blocking_pr_review_changes() -> None:
    from caliper.core.pr_review import sarif_to_review

    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "trivy"}},
                "results": [
                    {
                        "ruleId": "caliper-plugin-error",
                        "level": "error",
                        "message": {"text": "trivy timed out after 60s"},
                    }
                ],
            }
        ]
    }

    review = sarif_to_review(sarif, diff_files=set())

    assert review.event != "REQUEST_CHANGES"


def test_217_evaluate_sbom_appends_parquet_and_seals_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import caliper.core.pipeline as pipeline_mod
    from caliper.core.models import OperatingMode
    from caliper.core.pipeline import ReviewPipeline

    append_calls: list[tuple[Path, list[object], str]] = []
    seal_calls: list[tuple[Path, str, str | None, str]] = []
    config = _make_config(tmp_path)
    ctx = _patch_pipeline_runtime(monkeypatch, config, append_calls=append_calls)
    monkeypatch.setattr(pipeline_mod, "find_previous_seal_hash", lambda root, run_id: "prev")
    monkeypatch.setattr(
        pipeline_mod,
        "create_seal",
        lambda evidence_dir, run_id, commit_sha, previous_hash: seal_calls.append(
            (evidence_dir, run_id, commit_sha, previous_hash)
        ),
    )

    decisions = ReviewPipeline(config, context=ctx).evaluate_sbom(
        before_sbom=_sbom(),
        after_sbom=_sbom(_component("leftpad", "1.0.0", "pkg:npm/leftpad@1.0.0")),
        pr_url="https://github.com/org/repo/pull/1",
        team="platform",
        mode=OperatingMode.monitor,
        repo_path=tmp_path,
        commit_sha="abcdef123456",
    )

    assert decisions
    assert append_calls, "evaluate_sbom must append decisions to the parquet audit log"
    assert seal_calls, "evaluate_sbom must seal evidence artifacts like evaluate()"


def test_218_cli_evaluate_uses_sbom_path_for_non_python_dependency_diffs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from click.testing import CliRunner

    import caliper.composition.bootstrap as bootstrap_mod
    import caliper.core.pipeline as pipeline_mod
    from caliper.cli.main import cli

    calls: list[str] = []

    class FakePipeline:
        def __init__(self, config: object, context: object = None) -> None:
            return None

        def evaluate(self, **kwargs: object) -> list[object]:
            calls.append("evaluate")
            return []

        def evaluate_sbom(self, **kwargs: object) -> list[object]:
            calls.append("evaluate_sbom")
            return [_make_review_decision()]

    monkeypatch.setattr(bootstrap_mod, "bootstrap", lambda config: object())
    monkeypatch.setattr(pipeline_mod, "ReviewPipeline", FakePipeline)

    diff_path = tmp_path / "package.diff"
    diff_path.write_text(
        "diff --git a/package.json b/package.json\n"
        "index 000..111 100644\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -0,0 +1 @@\n"
        '+{"dependencies":{"leftpad":"1.0.0"}}\n'
    )
    result = CliRunner().invoke(
        cli,
        [
            "evaluate",
            "--repo-path",
            str(tmp_path),
            "--diff",
            str(diff_path),
            "--pr-url",
            "https://github.com/org/repo/pull/1",
            "--team",
            "platform",
            "--operating-mode",
            "monitor",
        ],
        env={
            "CALIPER_ALLOW_GLOBAL": "1",
            "CALIPER_DB_DSN": "postgresql://test:test@localhost/test",
        },
    )

    assert result.exit_code == 0
    assert "evaluate_sbom" in calls


def test_221_pipeline_closes_single_pypi_client_per_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from caliper.core.models import OperatingMode
    from caliper.core.pipeline import ReviewPipeline

    config = _make_config(tmp_path)
    ctx = _patch_pipeline_runtime(monkeypatch, config)

    ReviewPipeline(config, context=ctx).evaluate(
        diff_text=_REQUIREMENTS_DIFF,
        pr_url="https://github.com/org/repo/pull/1",
        team="platform",
        mode=OperatingMode.monitor,
        repo_path=tmp_path,
        commit_sha="abcdef123456",
    )

    assert len(_FakePyPIClient.instances) == 1
    assert _FakePyPIClient.instances[0].closed is True


def test_222_parquet_append_does_not_read_and_rewrite_existing_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import caliper.data.parquet_writer as parquet_writer

    class FakeTable:
        def __init__(self, num_rows: int) -> None:
            self.num_rows = num_rows

    class FakePa:
        class Table:
            @staticmethod
            def from_pylist(rows: list[dict[str, object]], schema: object) -> FakeTable:
                return FakeTable(len(rows))

        def schema(self, fields: list[object]) -> object:
            return fields

        def string(self) -> str:
            return "string"

        def int32(self) -> str:
            return "int32"

        def float64(self) -> str:
            return "float64"

        def timestamp(self, unit: str, tz: str) -> tuple[str, str, str]:
            return ("timestamp", unit, tz)

        def list_(self, value_type: object) -> tuple[str, object]:
            return ("list", value_type)

        def concat_tables(self, tables: list[FakeTable]) -> FakeTable:
            return FakeTable(sum(table.num_rows for table in tables))

    class FakePq:
        def __init__(self) -> None:
            self.read_calls = 0

        def read_table(self, path: Path, schema: object) -> FakeTable:
            self.read_calls += 1
            return FakeTable(1)

        def write_table(self, table: FakeTable, path: Path) -> None:
            path.write_bytes(b"parquet")

    fake_pq = FakePq()
    monkeypatch.setattr(parquet_writer, "pa", FakePa())
    monkeypatch.setattr(parquet_writer, "pq", fake_pq)
    (tmp_path / parquet_writer.PARQUET_FILENAME).write_bytes(b"existing")

    parquet_writer.append_decisions(tmp_path, [_make_review_decision()], run_id="run-1")

    assert fake_pq.read_calls == 0


def test_223_json_report_omits_full_sbom_payloads() -> None:
    from caliper.core.json_report import render_json
    from caliper.core.plugin import PluginResult

    sensitive_component = "internal-sensitive-component"
    output = render_json(
        [
            PluginResult(
                plugin_name="syft",
                category="dependency",
                findings=[],
                summary={
                    "components": 1,
                    "sbom": {"components": [{"name": sensitive_component, "version": "9.9.9"}]},
                },
            )
        ]
    )
    doc = json.loads(output)

    assert "sbom" not in doc["plugins"][0]["summary"]
    assert sensitive_component not in output


def test_228_package_config_merge_preserves_root_telemetry(tmp_path: Path) -> None:
    from caliper.core.repo_config import load_merged_config

    (tmp_path / ".caliper.yaml").write_text(
        "telemetry:\n"
        "  enabled: true\n"
        "  endpoint: https://telemetry.example.test/v1/events\n"
        "plugins:\n"
        "  disabled:\n"
        "    - trivy\n"
    )
    package_root = tmp_path / "packages" / "api"
    package_root.mkdir(parents=True)
    (package_root / ".caliper.yaml").write_text(
        "thresholds:\n" "  semgrep:\n" "    max_findings: 0\n"
    )

    merged = load_merged_config(tmp_path, package_root=package_root)

    assert merged.telemetry.enabled is True
    assert merged.telemetry.endpoint == "https://telemetry.example.test/v1/events"


def test_230_seal_verification_fails_on_unexpected_added_files(tmp_path: Path) -> None:
    from caliper.core.seal import create_seal, verify_seal

    evidence_dir = tmp_path / "abcdef123456" / "202604281200"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "decision.json").write_text('{"decision":"approve"}')
    create_seal(evidence_dir, "abcdef123456/202604281200", "abcdef123456")

    (evidence_dir / "unexpected.txt").write_text("added after seal creation")
    verification = verify_seal(evidence_dir)

    assert verification["valid"] is False


def test_232_file_evidence_store_rejects_traversal_without_writing_outside(
    tmp_path: Path,
) -> None:
    from caliper.adapters.persistence import FileEvidenceStore

    base_dir = tmp_path / "evidence"
    store = FileEvidenceStore(base_dir=base_dir)
    outside = tmp_path / "escape.txt"

    try:
        result = store.write_artifact("../escape.txt", b"owned")
    except Exception as exc:  # pragma: no cover - documents the contract in failure output
        pytest.fail(f"FileEvidenceStore must fail closed without raising: {exc}")

    assert result == ""
    assert not outside.exists()


def test_234_normalizer_keeps_unadvised_findings_from_distinct_sources() -> None:
    from caliper.core.models import (
        Finding,
        FindingCategory,
        FindingSeverity,
        ScanResult,
        ScanResultStatus,
    )
    from caliper.core.normalizer import normalize_findings

    first = Finding(
        severity=FindingSeverity.medium,
        category=FindingCategory.vulnerability,
        description="heuristic vulnerability from scanner A",
        source_tool="scanner-a",
        package_name="dangerlib",
        version="1.0.0",
        advisory_id=None,
    )
    second = Finding(
        severity=FindingSeverity.high,
        category=FindingCategory.vulnerability,
        description="independent vulnerability from scanner B",
        source_tool="scanner-b",
        package_name="dangerlib",
        version="1.0.0",
        advisory_id=None,
    )
    findings, _summary = normalize_findings(
        [
            ScanResult(
                tool_name="scanner-a",
                status=ScanResultStatus.success,
                findings=[first],
                duration_seconds=0.01,
            ),
            ScanResult(
                tool_name="scanner-b",
                status=ScanResultStatus.success,
                findings=[second],
                duration_seconds=0.01,
            ),
        ]
    )

    assert {finding.source_tool for finding in findings} == {"scanner-a", "scanner-b"}
