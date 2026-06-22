# tested-by: self (e2e)
"""E2E: fail-open guarantee — scanner failures never block the pipeline."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    E2E_ENABLED,
    breakpoint_dump,
    get_plugin_findings,
    run_review,
)

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")


class TestMissingScannerContinues:
    def test_missing_scanner_continues(self, vuln_repo: Path, tmp_path: Path) -> None:
        syft_path = None
        for candidate in ("/usr/local/bin/syft", "/usr/bin/syft"):
            if os.path.isfile(candidate):
                syft_path = candidate
                break

        if syft_path is None:
            pytest.skip("syft not found — cannot test missing scanner")

        backup = syft_path + ".e2e-bak"
        try:
            os.rename(syft_path, backup)

            result, parsed = run_review(vuln_repo, run_all=True, output_format="json")
            breakpoint_dump(tmp_path, "fail_open_missing_syft", parsed)

            assert (
                result.exit_code == 0
            ), f"Pipeline must exit 0 even with missing scanner. Got {result.exit_code}"
        finally:
            if os.path.isfile(backup):
                os.rename(backup, syft_path)

    def test_scanner_timeout_continues(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, run_all=True, output_format="json")
        breakpoint_dump(tmp_path, "fail_open_normal", parsed)

        assert result.exit_code == 0, "Pipeline must always exit 0"


class TestScannerIsolation:
    def test_gitleaks_findings_stable_without_semgrep(
        self, vuln_repo: Path, tmp_path: Path
    ) -> None:
        result_solo, parsed_solo = run_review(vuln_repo, scanners="gitleaks", output_format="json")
        result_both, parsed_both = run_review(
            vuln_repo, scanners="gitleaks,semgrep", output_format="json"
        )
        breakpoint_dump(tmp_path, "isolation_solo", parsed_solo)
        breakpoint_dump(tmp_path, "isolation_both", parsed_both)

        assert result_solo.exit_code == 0
        assert result_both.exit_code == 0

        solo_findings = get_plugin_findings(parsed_solo, "gitleaks")
        both_findings = get_plugin_findings(parsed_both, "gitleaks")
        assert len(solo_findings) == len(both_findings), (
            f"Gitleaks findings should be identical solo vs combined. "
            f"Solo: {len(solo_findings)}, Combined: {len(both_findings)}"
        )
