"""End-to-end ``caliper inspect`` over a fixture cut list (git-only, no jj).

# tested-by: tests/integration/test_inspect_cli.py

Builds a git repo, produces a real cut list (via the parting producer/consumer),
and drives the actual ``caliper inspect`` CLI. Screen is made hermetic for the
test by routing no analyzers (``bucket_gauges: {}``) so it depends on no scanner
binaries; the gauge logic itself is unit-tested with fakes. Covers per-part +
integration reports, ``--no-llm`` determinism, the null backend fail-soft, and
``--explain``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from caliper.cli.inspect_cmd import inspect
from caliper.core.repo_config import PartingConfig
from caliper.plugins._parting import PartingPlugin

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="requires git on PATH")

_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def _git(args: list[str], cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=cwd, env={**os.environ, **_ENV}, capture_output=True, text=True
    )
    assert proc.returncode == 0, f"git {' '.join(args)}\n{proc.stderr}"
    return proc.stdout


# Hermetic Screen: no analyzers routed, missing gauges tolerated.
_CALIPER_YAML = "inspect:\n  bucket_gauges: {}\n  allow_missing_gauges: true\n"


@pytest.fixture()
def cutlist_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-q", "."], repo)
    (repo / "app.py").write_text("def f():\n    return 1\n")
    (repo / "poetry.lock").write_text("lock\n")
    (repo / ".caliper.yaml").write_text(_CALIPER_YAML)
    _git(["add", "-A"], repo)
    _git(["commit", "-qm", "base"], repo)
    base = _git(["rev-parse", "HEAD"], repo).strip()

    (repo / "app.py").write_text("def f():\n    return 2\n")  # logic change
    (repo / "poetry.lock").write_text("lock\nlock2\n")  # generated change
    (repo / "settings.yaml").write_text("k: v\n")  # config add
    _git(["add", "-A"], repo)
    _git(["commit", "-qm", "head"], repo)
    head = _git(["rev-parse", "HEAD"], repo).strip()

    # Produce a real cut list (parting consumer); write cutlist.json.
    outcome = PartingPlugin().cut(repo, base, head, PartingConfig())
    cutlist_path = tmp_path / "cutlist.json"
    cutlist_path.write_text(outcome.cutlist.model_dump_json())
    return repo, cutlist_path, outcome.cutlist


def _invoke(repo: Path, cutlist: Path, out: Path, *extra: str):
    return CliRunner().invoke(
        inspect,
        ["--cutlist", str(cutlist), "--repo", str(repo), "--out", str(out), *extra],
        catch_exceptions=False,
    )


def test_inspect_writes_per_part_and_integration_reports(cutlist_repo, tmp_path) -> None:
    repo, cutlist_path, cutlist = cutlist_repo
    out = tmp_path / "out"
    result = _invoke(repo, cutlist_path, out, "--no-llm")
    assert result.exit_code == 0, result.output

    report_dir = out / "inspect"
    # one report per part + one integration report
    for part in cutlist.parts:
        rep = json.loads((report_dir / f"{part.id}.json").read_text())
        assert rep["part_id"] == part.id
        assert rep["kind"] == "part"
    integ = json.loads((report_dir / "integration.json").read_text())
    assert integ["kind"] == "integration"


def test_no_llm_is_fully_deterministic(cutlist_repo, tmp_path) -> None:
    repo, cutlist_path, _ = cutlist_repo
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    assert _invoke(repo, cutlist_path, out_a, "--no-llm").exit_code == 0
    assert _invoke(repo, cutlist_path, out_b, "--no-llm").exit_code == 0

    def _reports(d: Path) -> dict[str, dict]:
        return {p.name: json.loads(p.read_text()) for p in sorted((d / "inspect").glob("*.json"))}

    assert _reports(out_a) == _reports(out_b)


def test_no_llm_skips_review_with_no_claims(cutlist_repo, tmp_path) -> None:
    repo, cutlist_path, _ = cutlist_repo
    out = tmp_path / "out"
    assert _invoke(repo, cutlist_path, out, "--no-llm").exit_code == 0
    for rep_path in (out / "inspect").glob("*.json"):
        rep = json.loads(rep_path.read_text())
        assert rep["skipped_llm"] is True
        assert rep["claims"] == []  # no LLM, no invented claims


def test_default_null_backend_fails_soft(cutlist_repo, tmp_path) -> None:
    """Without --no-llm, the default 'null' backend is unavailable: reports show
    skipped_llm and no invented claims (fail-soft Review)."""
    repo, cutlist_path, _ = cutlist_repo
    out = tmp_path / "out"
    assert _invoke(repo, cutlist_path, out).exit_code == 0
    integ = json.loads((out / "inspect" / "integration.json").read_text())
    assert integ["skipped_llm"] is True
    assert integ["claims"] == []


def test_explain_prints_report(cutlist_repo, tmp_path) -> None:
    repo, cutlist_path, _ = cutlist_repo
    out = tmp_path / "out"
    assert _invoke(repo, cutlist_path, out, "--no-llm").exit_code == 0
    a_report = next((out / "inspect").glob("*.json"))
    result = CliRunner().invoke(inspect, ["--explain", str(a_report)], catch_exceptions=False)
    assert result.exit_code == 0
    assert "inspection:" in result.output
