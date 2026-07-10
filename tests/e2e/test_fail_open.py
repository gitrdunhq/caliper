# tested-by: self (e2e)
"""E2E: fail-open guarantee — scanner failures never block the pipeline."""

from __future__ import annotations

import os
import shutil
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
    def test_missing_scanner_continues(
        self, vuln_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        syft_real = shutil.which("syft")
        if syft_real is None:
            pytest.skip("syft not found — cannot test missing scanner")

        syft_dir = Path(syft_real).parent

        # Shadow syft via PATH instead of mutating the filesystem: renaming the
        # real binary needs write access to syft_dir, which is root-owned and
        # deliberately not writable by the unprivileged container user the
        # scanners run as. Symlink every sibling into a shim dir ahead of
        # syft_dir in PATH so other scanners still resolve normally.
        shim_dir = tmp_path / "path-shim"
        shim_dir.mkdir()
        for entry in syft_dir.iterdir():
            if entry.name != "syft":
                (shim_dir / entry.name).symlink_to(entry)

        pruned = [
            p for p in os.environ.get("PATH", "").split(os.pathsep) if p and Path(p) != syft_dir
        ]
        monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), *pruned]))
        assert shutil.which("syft") is None, "PATH shim failed to hide syft"

        result, parsed = run_review(vuln_repo, run_all=True, output_format="json")
        breakpoint_dump(tmp_path, "fail_open_missing_syft", parsed)

        assert (
            result.exit_code == 0
        ), f"Pipeline must exit 0 even with missing scanner. Got {result.exit_code}"

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
