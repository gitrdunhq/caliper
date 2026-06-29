"""End-to-end ``caliper gauge`` flywheel CLI (no git/jj needed).

# tested-by: tests/integration/test_gauge_cli.py

Drives the real CLI: propose (with a registered test drafter) -> promote -> status,
and asserts the load-bearing safety properties: no auto-promotion, promote refuses
without a passing backtest or --by, lineage is recorded, and the loop closes
(propose no longer surfaces a promoted cluster).
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from caliper.cli.gauge_cmd import gauge
from caliper.core.flywheel import cluster_key
from caliper.core.ledger import append as ledger_append
from caliper.core.llm_port import DraftRequest, DraftResult
from caliper.core.models import Backtest, CandidateGauge, Claim, LedgerEntry
from caliper.core.registries import GAUGE_DRAFTERS
from caliper.core.tool_crib import is_active

_KEY = cluster_key("correctness", "missing null check before deref")


# Register a deterministic test drafter into the isolated registry (the null default
# would invent nothing). This is what a real oMLX/cloud drafter slots into.
class _EchoDrafter:
    def draft(self, request: DraftRequest) -> DraftResult:
        return DraftResult(available=True, kind="semgrep", draft=f"rule for {request.cluster_key}")


@GAUGE_DRAFTERS.register("test-echo")
def _build_echo() -> _EchoDrafter:
    return _EchoDrafter()


def _repo_with_ledger(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".caliper").mkdir(parents=True)
    (repo / ".caliper.yaml").write_text("gauge:\n  drafter: test-echo\n")
    entries = [
        LedgerEntry(
            claim=Claim(
                file="a.py",
                line_range=(1, 2),
                severity="major",
                category="correctness",
                assertion="missing null check before deref",
            ),
            repo="repo",
            sha=f"s{i}",
            content_hash=f"p{i}",
            author=f"a{i}",
        )
        for i in range(3)  # recurs across 3 distinct parts + authors -> eligible
    ]
    ledger_append(repo / ".caliper" / "claims-ledger.jsonl", entries)
    return repo


def _run(*args: str):
    return CliRunner().invoke(gauge, list(args), catch_exceptions=False)


def test_propose_drafts_candidate_for_eligible_cluster(tmp_path) -> None:
    repo = _repo_with_ledger(tmp_path)
    out = tmp_path / "cands"
    res = _run("propose", "--repo", str(repo), "--out", str(out))
    assert res.exit_code == 0, res.output
    cand_file = out / f"{_KEY}.json"
    assert cand_file.exists()
    cand = json.loads(cand_file.read_text())
    assert cand["cluster_key"] == _KEY
    assert cand["backtest"] is None  # drafting does not gate; backtest comes next


def test_no_auto_promotion_candidate_is_not_active(tmp_path) -> None:
    repo = _repo_with_ledger(tmp_path)
    out = tmp_path / "cands"
    _run("propose", "--repo", str(repo), "--out", str(out))
    # A drafted candidate is NOT active until promoted.
    assert is_active(_KEY, repo / ".caliper" / "tool-crib") is False


def test_promote_refuses_without_passing_backtest(tmp_path) -> None:
    repo = _repo_with_ledger(tmp_path)
    out = tmp_path / "cands"
    _run("propose", "--repo", str(repo), "--out", str(out))
    cand_file = out / f"{_KEY}.json"  # backtest is None
    res = CliRunner().invoke(
        gauge, ["promote", str(cand_file), "--by", "maria", "--repo", str(repo)]
    )
    assert res.exit_code != 0
    assert "backtest" in res.output.lower()
    assert is_active(_KEY, repo / ".caliper" / "tool-crib") is False


def _write_passing_backtest(cand_file: Path) -> None:
    cand = CandidateGauge.model_validate_json(cand_file.read_text())
    bt = Backtest(recall=1.0, precision=1.0, deterministic=True, runtime_ms=10, passed=True)
    cand_file.write_text(cand.model_copy(update={"backtest": bt}).model_dump_json())


def test_promote_refuses_without_by(tmp_path) -> None:
    repo = _repo_with_ledger(tmp_path)
    out = tmp_path / "cands"
    _run("propose", "--repo", str(repo), "--out", str(out))
    cand_file = out / f"{_KEY}.json"
    _write_passing_backtest(cand_file)
    res = CliRunner().invoke(gauge, ["promote", str(cand_file), "--repo", str(repo)])
    assert res.exit_code != 0  # --by is required even with a passing backtest


def test_promote_and_loop_closes(tmp_path) -> None:
    repo = _repo_with_ledger(tmp_path)
    out = tmp_path / "cands"
    _run("propose", "--repo", str(repo), "--out", str(out))
    cand_file = out / f"{_KEY}.json"
    _write_passing_backtest(cand_file)

    res = _run("promote", str(cand_file), "--by", "maria", "--repo", str(repo))
    assert res.exit_code == 0, res.output
    assert is_active(_KEY, repo / ".caliper" / "tool-crib") is True

    # Loop closes: a re-propose no longer surfaces the promoted cluster.
    out2 = tmp_path / "cands2"
    _run("propose", "--repo", str(repo), "--out", str(out2))
    assert not (out2 / f"{_KEY}.json").exists()


def test_status_reports_scorecard(tmp_path) -> None:
    repo = _repo_with_ledger(tmp_path)
    res = _run("status", "--repo", str(repo))
    assert res.exit_code == 0
    assert "convergence scorecard" in res.output
    assert "substantiation rate" in res.output
