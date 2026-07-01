"""Tests for caliper.data.parquet_writer.

# tested-by: tests/unit/test_parquet_writer.py  (self-referential — this is the test file)
"""

from __future__ import annotations

from pathlib import Path

import pytest

pq = pytest.importorskip("pyarrow.parquet", reason="pyarrow not installed (caliper[parquet])")
from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.models import (
    DecisionVerdict,
    Finding,
    FindingCategory,
    FindingSeverity,
    OperatingMode,
    PolicyEvaluation,
    RequestType,
    ReviewDecision,
    ReviewRequest,
    ScanResult,
    ScanResultStatus,
)
from caliper.data.parquet_writer import (
    _build_schema,
    append_decisions,
    decision_to_row,
    read_decisions,
)

SCHEMA = _build_schema()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _request(
    mode: str = "advise",
    ecosystem: str = "pypi",
    package_name: str = "requests",
    target_version: str = "2.31.0",
    team: str = "platform",
    scope: str = "runtime",
    commit_sha: str | None = "abc123def456",
    pr_url: str | None = "https://github.com/org/repo/pull/42",
) -> ReviewRequest:
    return ReviewRequest(
        request_type=RequestType.new_package,
        ecosystem=ecosystem,
        package_name=package_name,
        target_version=target_version,
        team=team,
        scope=scope,
        operating_mode=OperatingMode(mode),
        commit_sha=commit_sha,
        pr_url=pr_url,
    )


def _policy_eval(
    decision: str = "approve",
    rules: list[str] | None = None,
    constraints: list[str] | None = None,
    policy_version: str = "1.0.0",
) -> PolicyEvaluation:
    return PolicyEvaluation(
        decision=DecisionVerdict(decision),
        triggered_rules=rules or [],
        constraints=constraints or [],
        policy_bundle_version=policy_version,
    )


def _finding(
    severity: str = "high",
    advisory_id: str | None = "CVE-2024-1234",
    category: str = "vulnerability",
    package_name: str = "requests",
) -> Finding:
    return Finding(
        severity=FindingSeverity(severity),
        category=FindingCategory(category),
        description=f"Test vulnerability {advisory_id}",
        source_tool="osv-scanner",
        package_name=package_name,
        version="2.30.0",
        advisory_id=advisory_id,
    )


def _scan_result(
    tool: str = "osv-scanner",
    status: str = "success",
) -> ScanResult:
    return ScanResult(
        tool_name=tool,
        status=ScanResultStatus(status),
        findings=[],
        duration_seconds=1.5,
    )


def _decision(
    findings: list[Finding] | None = None,
    scan_results: list[ScanResult] | None = None,
    policy: PolicyEvaluation | None = None,
    mode: str = "advise",
    verdict: str = "approve",
    memo: str | None = "Test memo.",
    duration: float = 5.0,
    package_name: str = "requests",
    target_version: str = "2.31.0",
) -> ReviewDecision:
    req = _request(mode=mode, package_name=package_name, target_version=target_version)
    pol = policy or _policy_eval(decision=verdict)
    return ReviewDecision(
        request=req,
        decision=DecisionVerdict(verdict),
        findings=findings or [],
        scan_results=scan_results or [_scan_result()],
        policy_evaluation=pol,
        pipeline_duration_seconds=duration,
        memo_text=memo,
    )


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_mode_st = st.sampled_from(list(OperatingMode))
_request_type_st = st.sampled_from(list(RequestType))
_verdict_st = st.sampled_from(list(DecisionVerdict))
_severity_st = st.sampled_from(list(FindingSeverity))
_category_st = st.sampled_from(list(FindingCategory))
_status_st = st.sampled_from(list(ScanResultStatus))

_safe_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=1,
    max_size=30,
)

_finding_st = st.builds(
    Finding,
    severity=_severity_st,
    category=_category_st,
    description=_safe_text,
    source_tool=_safe_text,
    package_name=_safe_text,
    version=_safe_text,
    advisory_id=st.one_of(st.none(), _safe_text),
)

_scan_result_st = st.builds(
    ScanResult,
    tool_name=_safe_text,
    status=_status_st,
    findings=st.just([]),
    duration_seconds=st.floats(
        min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False
    ),
)


@st.composite
def _decision_strategy(draw: st.DrawFn) -> ReviewDecision:
    verdict = draw(_verdict_st)
    req = ReviewRequest(
        request_type=draw(_request_type_st),
        ecosystem=draw(_safe_text),
        package_name=draw(_safe_text),
        target_version=draw(_safe_text),
        team=draw(_safe_text),
        scope=draw(_safe_text),
        operating_mode=draw(_mode_st),
        commit_sha=draw(st.one_of(st.none(), _safe_text)),
        pr_url=draw(st.one_of(st.none(), _safe_text)),
    )
    pol = PolicyEvaluation(
        decision=verdict,
        triggered_rules=draw(st.lists(_safe_text, max_size=5)),
        constraints=draw(st.lists(_safe_text, max_size=3)),
        policy_bundle_version=draw(_safe_text),
    )
    return ReviewDecision(
        request=req,
        decision=verdict,
        findings=draw(st.lists(_finding_st, max_size=5)),
        scan_results=draw(st.lists(_scan_result_st, max_size=3)),
        policy_evaluation=pol,
        pipeline_duration_seconds=draw(
            st.floats(min_value=0.0, max_value=300.0, allow_nan=False, allow_infinity=False)
        ),
        memo_text=draw(st.one_of(st.none(), _safe_text)),
    )


# ---------------------------------------------------------------------------
# Tests: decision_to_row
# ---------------------------------------------------------------------------


class TestDecisionToRow:
    def test_decision_to_row_flattens_correctly(self) -> None:
        """All fields from the decision appear correctly in the row dict."""
        pol = _policy_eval(
            decision="reject",
            rules=["CRITICAL vuln found"],
            constraints=["no-runtime-secrets"],
            policy_version="2.0.0",
        )
        findings = [_finding(severity="critical", advisory_id="CVE-2024-999")]
        scans = [_scan_result(tool="osv-scanner", status="success")]
        dec = ReviewDecision(
            request=_request(
                mode="advise",
                commit_sha="abc123",
                pr_url="https://github.com/org/repo/pull/1",
            ),
            decision=DecisionVerdict.reject,
            findings=findings,
            scan_results=scans,
            policy_evaluation=pol,
            pipeline_duration_seconds=7.5,
            memo_text="Critical vuln detected.",
        )

        row = decision_to_row(dec, run_id="run-001")

        assert row["decision_id"] == str(dec.decision_id)
        assert row["commit_sha"] == "abc123"
        assert row["run_id"] == "run-001"
        assert row["package_name"] == "requests"
        assert row["package_version"] == "2.31.0"
        assert row["ecosystem"] == "pypi"
        assert row["team"] == "platform"
        assert row["scope"] == "runtime"
        assert row["pr_url"] == "https://github.com/org/repo/pull/1"
        assert row["request_type"] == "new_package"
        assert row["operating_mode"] == "advise"
        assert row["decision"] == "reject"
        assert row["vuln_critical"] == 1
        assert row["vuln_high"] == 0
        assert row["vuln_medium"] == 0
        assert row["vuln_low"] == 0
        assert row["vuln_info"] == 0
        assert row["finding_count"] == 1
        assert row["triggered_rules"] == ["CRITICAL vuln found"]
        assert row["constraints"] == ["no-runtime-secrets"]
        assert row["policy_version"] == "2.0.0"
        assert row["pipeline_duration_seconds"] == 7.5
        assert row["scanner_names"] == ["osv-scanner"]
        assert row["scanner_statuses"] == ["success"]
        assert row["advisory_ids"] == ["CVE-2024-999"]
        assert row["memo_text"] == "Critical vuln detected."

    def test_severity_counts_correct(self) -> None:
        """Row has correct vuln_critical/vuln_high counts from findings."""
        findings = [
            _finding(severity="critical", advisory_id="CVE-2024-001"),
            _finding(severity="critical", advisory_id="CVE-2024-002"),
            _finding(severity="high", advisory_id="CVE-2024-003"),
        ]
        dec = _decision(findings=findings)
        row = decision_to_row(dec, run_id="test")

        assert row["vuln_critical"] == 2
        assert row["vuln_high"] == 1
        assert row["vuln_medium"] == 0
        assert row["vuln_low"] == 0
        assert row["vuln_info"] == 0
        assert row["finding_count"] == 3

    def test_advisory_ids_collected(self) -> None:
        """All advisory IDs from findings appear in row.advisory_ids."""
        findings = [
            _finding(advisory_id="CVE-2024-001"),
            _finding(advisory_id="CVE-2024-002"),
            _finding(advisory_id="CVE-2024-003"),
        ]
        dec = _decision(findings=findings)
        row = decision_to_row(dec, run_id="test")

        assert set(row["advisory_ids"]) == {"CVE-2024-001", "CVE-2024-002", "CVE-2024-003"}
        assert len(row["advisory_ids"]) == 3

    def test_advisory_ids_skips_none(self) -> None:
        """Findings without advisory_id are not added to advisory_ids list."""
        findings = [
            _finding(advisory_id="CVE-2024-001"),
            _finding(advisory_id=None),
        ]
        dec = _decision(findings=findings)
        row = decision_to_row(dec, run_id="test")

        assert row["advisory_ids"] == ["CVE-2024-001"]

    def test_scanner_names_and_statuses(self) -> None:
        """Row has scanner_names and scanner_statuses matching scan results."""
        scan_results = [
            _scan_result(tool="osv-scanner", status="success"),
            _scan_result(tool="trivy", status="failed"),
        ]
        dec = _decision(scan_results=scan_results)
        row = decision_to_row(dec, run_id="test")

        assert row["scanner_names"] == ["osv-scanner", "trivy"]
        assert row["scanner_statuses"] == ["success", "failed"]

    def test_commit_sha_defaults_to_empty_string(self) -> None:
        """When commit_sha is None on request, row has empty string."""
        req = _request(commit_sha=None)
        pol = _policy_eval()
        dec = ReviewDecision(
            request=req,
            decision=DecisionVerdict.approve,
            findings=[],
            scan_results=[_scan_result()],
            policy_evaluation=pol,
            pipeline_duration_seconds=1.0,
        )
        row = decision_to_row(dec)
        assert row["commit_sha"] == ""

    def test_pr_url_defaults_to_empty_string(self) -> None:
        """When pr_url is None on request, row has empty string."""
        req = _request(pr_url=None)
        pol = _policy_eval()
        dec = ReviewDecision(
            request=req,
            decision=DecisionVerdict.approve,
            findings=[],
            scan_results=[_scan_result()],
            policy_evaluation=pol,
            pipeline_duration_seconds=1.0,
        )
        row = decision_to_row(dec)
        assert row["pr_url"] == ""


# ---------------------------------------------------------------------------
# Tests: append_decisions
# ---------------------------------------------------------------------------


class TestAppendDecisions:
    def test_append_creates_new_file(self, tmp_path: Path) -> None:
        """When no decisions dataset exists, append creates it with 1 row."""
        dec = _decision()
        result = append_decisions(tmp_path, [dec], run_id="run-1")

        assert result is not None
        assert result.name == "decisions.parquet"
        assert result.exists()
        assert result.is_dir()

        table = read_decisions(tmp_path)
        assert table.num_rows == 1

    def test_append_appends_to_existing(self, tmp_path: Path) -> None:
        """Appending to an existing file results in cumulative rows."""
        dec1 = _decision(package_name="requests", target_version="2.31.0")
        dec2 = _decision(package_name="httpx", target_version="0.27.0")

        append_decisions(tmp_path, [dec1], run_id="run-1")
        append_decisions(tmp_path, [dec2], run_id="run-2")

        table = read_decisions(tmp_path)
        assert table.num_rows == 2

    def test_append_empty_list_returns_none(self, tmp_path: Path) -> None:
        """Empty decisions list returns None and creates no file."""
        result = append_decisions(tmp_path, [], run_id="run-1")

        assert result is None
        assert not (tmp_path / "decisions.parquet").exists()

    def test_append_multiple_decisions_in_one_call(self, tmp_path: Path) -> None:
        """Multiple decisions in a single call are all written."""
        decs = [
            _decision(package_name="requests"),
            _decision(package_name="httpx"),
            _decision(package_name="pydantic"),
        ]
        result = append_decisions(tmp_path, decs, run_id="run-1")

        assert result is not None
        table = read_decisions(tmp_path)
        assert table.num_rows == 3

    def test_parquet_readable_by_duckdb(self, tmp_path: Path) -> None:
        """Written parquet is readable by pyarrow and schema matches SCHEMA."""
        dec1 = _decision(
            findings=[_finding(severity="critical")],
            verdict="reject",
            memo="Critical issue found.",
        )
        dec2 = _decision(findings=[], verdict="approve", memo="Clean scan.")

        append_decisions(tmp_path, [dec1, dec2], run_id="run-analytics")

        table = read_decisions(tmp_path)

        assert table.num_rows == 2

        # Verify all expected columns are present
        for field in SCHEMA:
            assert field.name in table.schema.names, f"Column '{field.name}' missing"

        # Verify specific field values round-trip correctly
        decisions_col = table.column("decision").to_pylist()
        assert "reject" in decisions_col
        assert "approve" in decisions_col

        run_ids = table.column("run_id").to_pylist()
        assert all(r == "run-analytics" for r in run_ids)

    def test_append_survives_prior_corrupt_part(self, tmp_path: Path) -> None:
        """A corrupted earlier part-file must never block a later append.

        True append semantics mean append_decisions() never reads (or even
        looks at) prior part-files, so a corrupt sibling part cannot fail —
        or slow down — a later append call.
        """
        parts_dir = tmp_path / "decisions.parquet"

        dec = _decision()
        append_decisions(tmp_path, [dec], run_id="run-1")
        assert parts_dir.exists()

        # Corrupt a "previous" part file directly.
        (parts_dir / "part-corrupt.parquet").write_bytes(
            b"this is not a valid parquet file at all\x00\xff\xfe"
        )

        # A new append must still succeed — it never touches existing parts.
        dec2 = _decision(package_name="httpx")
        result = append_decisions(tmp_path, [dec2], run_id="run-2")

        assert result is not None
        assert result == parts_dir

    def test_read_decisions_fails_open_on_corrupt_part(self, tmp_path: Path) -> None:
        """read_decisions() fails open (returns None, no crash) on a corrupt part."""
        dec = _decision()
        append_decisions(tmp_path, [dec], run_id="run-1")

        parts_dir = tmp_path / "decisions.parquet"
        (parts_dir / "part-corrupt.parquet").write_bytes(
            b"this is not a valid parquet file at all\x00\xff\xfe"
        )

        assert read_decisions(tmp_path) is None

    def test_read_decisions_missing_dataset_returns_none(self, tmp_path: Path) -> None:
        """read_decisions() returns None when nothing has ever been appended."""
        assert read_decisions(tmp_path) is None

    def test_append_creates_parent_directories(self, tmp_path: Path) -> None:
        """append_decisions creates missing parent directories."""
        nested = tmp_path / "a" / "b" / "c"
        assert not nested.exists()

        dec = _decision()
        result = append_decisions(nested, [dec], run_id="run-1")

        assert result is not None
        assert nested.exists()
        assert result.exists()

    def test_append_preserves_existing_rows(self, tmp_path: Path) -> None:
        """Existing rows are not lost when appending new rows."""
        dec1 = _decision(package_name="requests")
        append_decisions(tmp_path, [dec1], run_id="run-1")

        dec2 = _decision(package_name="httpx")
        append_decisions(tmp_path, [dec2], run_id="run-2")

        table = read_decisions(tmp_path)
        names = table.column("package_name").to_pylist()
        assert "requests" in names
        assert "httpx" in names

    def test_append_run_id_recorded_per_batch(self, tmp_path: Path) -> None:
        """Each batch gets the run_id passed to append_decisions."""
        dec1 = _decision()
        dec2 = _decision()

        append_decisions(tmp_path, [dec1], run_id="run-A")
        append_decisions(tmp_path, [dec2], run_id="run-B")

        table = read_decisions(tmp_path)
        run_ids = set(table.column("run_id").to_pylist())
        assert run_ids == {"run-A", "run-B"}


# ---------------------------------------------------------------------------
# Hypothesis property tests
# ---------------------------------------------------------------------------


@given(_decision_strategy())
@settings(max_examples=50)
def test_any_valid_decision_converts_to_row(decision: ReviewDecision) -> None:
    """decision_to_row never raises for any valid ReviewDecision."""
    row = decision_to_row(decision, run_id="hypothesis-run")

    # All SCHEMA field names must be present in the row
    for field in SCHEMA:
        assert field.name in row, f"Field '{field.name}' missing from row"

    # Severity counts are non-negative integers
    for key in ("vuln_critical", "vuln_high", "vuln_medium", "vuln_low", "vuln_info"):
        assert isinstance(row[key], int)
        assert row[key] >= 0

    # finding_count matches actual findings list length
    assert row["finding_count"] == len(decision.findings)

    # advisory_ids is always a list
    assert isinstance(row["advisory_ids"], list)

    # scanner_names and scanner_statuses have equal length
    assert len(row["scanner_names"]) == len(row["scanner_statuses"])
    assert len(row["scanner_names"]) == len(decision.scan_results)
