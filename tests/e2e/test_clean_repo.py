# tested-by: self (e2e)
"""E2E: clean repo must produce zero actionable findings."""

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


class TestCleanRepoZeroFindings:
    def test_clean_repo_zero_findings(self, clean_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(clean_repo, run_all=True, output_format="json")
        breakpoint_dump(tmp_path, "clean_repo_full", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        all_findings = get_all_findings(parsed)
        error_findings = [
            f
            for f in all_findings
            if str(f.get("severity", "")).lower() in ("critical", "high", "error")
        ]
        assert len(error_findings) == 0, (
            f"Clean repo should have zero error findings. "
            f"Found {len(error_findings)}: {json.dumps(error_findings, indent=2)}"
        )

    def test_clean_repo_markdown_no_blocked(self, clean_repo: Path, tmp_path: Path) -> None:
        result, output = run_review(clean_repo, run_all=True, output_format="markdown")
        breakpoint_dump(tmp_path, "clean_repo_markdown", {"output": output})

        assert result.exit_code == 0
        assert "BLOCKED" not in output, "Clean repo should not be BLOCKED"
        assert "REJECTED" not in output, "Clean repo should not be REJECTED"
