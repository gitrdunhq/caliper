# tested-by: self (e2e)
"""E2E: breakpoint/sampling infrastructure for binary-search debugging."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    E2E_ENABLED,
    breakpoint_dump,
    get_all_findings,
    run_review,
)

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")

ALL_SCANNERS = [
    "gitleaks",
    "semgrep",
    "clamav",
    "osv-scanner",
    "trivy",
    "syft",
    "scancode",
    "complexity",
    "cpd",
    "mypy",
    "typos",
    "ls-lint",
    "kube-linter",
    "cfn-nag",
    "cdk-nag",
    "supply-chain",
    "blast-radius",
]

FIRST_HALF = ALL_SCANNERS[: len(ALL_SCANNERS) // 2]
SECOND_HALF = ALL_SCANNERS[len(ALL_SCANNERS) // 2 :]


class TestBreakpointFilesCreated:
    def test_breakpoint_files_created(
        self, vuln_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CALIPER_E2E_BREAKPOINTS", "1")

        from tests.e2e import conftest as c

        orig = c.BREAKPOINTS_ENABLED
        c.BREAKPOINTS_ENABLED = True
        try:
            _, parsed = run_review(vuln_repo, scanners="gitleaks", output_format="json")
            breakpoint_dump(tmp_path, "manual_test_bp", {"test": True})
        finally:
            c.BREAKPOINTS_ENABLED = orig

        bp_dir = tmp_path / "breakpoints"
        assert bp_dir.exists(), "Breakpoints directory should be created"

        bp_files = list(bp_dir.glob("*.json"))
        assert len(bp_files) >= 1, f"Should have breakpoint files. Got: {bp_files}"

    def test_breakpoint_per_plugin_valid_json(
        self, vuln_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CALIPER_E2E_BREAKPOINTS", "1")

        from tests.e2e import conftest as c

        orig = c.BREAKPOINTS_ENABLED
        c.BREAKPOINTS_ENABLED = True
        try:
            _, parsed = run_review(vuln_repo, scanners="gitleaks,semgrep", output_format="json")
            breakpoint_dump(tmp_path, "bp_gitleaks_semgrep", parsed)
        finally:
            c.BREAKPOINTS_ENABLED = orig

        bp_dir = tmp_path / "breakpoints"
        for bp_file in bp_dir.glob("*.json"):
            content = bp_file.read_text()
            data = json.loads(content)
            assert isinstance(
                data, (dict, list)
            ), f"Breakpoint {bp_file.name} is not valid JSON structure"


class TestBisectPlugins:
    def test_bisect_plugins(self, vuln_repo: Path, tmp_path: Path) -> None:
        result_first, parsed_first = run_review(
            vuln_repo, scanners=",".join(FIRST_HALF), output_format="json"
        )
        breakpoint_dump(tmp_path, "bisect_first_half", parsed_first)

        result_second, parsed_second = run_review(
            vuln_repo, scanners=",".join(SECOND_HALF), output_format="json"
        )
        breakpoint_dump(tmp_path, "bisect_second_half", parsed_second)

        result_full, parsed_full = run_review(vuln_repo, run_all=True, output_format="json")
        breakpoint_dump(tmp_path, "bisect_full", parsed_full)

        assert result_first.exit_code == 0, "First half should succeed"
        assert result_second.exit_code == 0, "Second half should succeed"
        assert result_full.exit_code == 0, "Full run should succeed"

        first_count = len(get_all_findings(parsed_first))
        second_count = len(get_all_findings(parsed_second))
        full_count = len(get_all_findings(parsed_full))

        assert first_count + second_count > 0, "Half-runs should produce some findings"
        assert full_count > 0, "Full run should produce findings"
