# tested-by: self (e2e)
"""E2E smoke: CLI review path with a built-in scanner only."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.conftest import (
    E2E_ENABLED,
    breakpoint_dump,
    get_all_findings,
    run_review,
)

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")


class TestSmokeReview:
    def test_supply_chain_smoke_clean_repo(self, clean_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(
            clean_repo,
            scanners="supply-chain",
            output_format="json",
        )
        breakpoint_dump(tmp_path, "smoke_supply_chain_clean_repo", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        all_findings = get_all_findings(parsed)
        assert all_findings == []
