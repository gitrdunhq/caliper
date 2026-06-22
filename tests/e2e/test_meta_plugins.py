# tested-by: self (e2e)
"""E2E: meta plugins that analyze repo metadata or scan results.

supply-chain, blast-radius run in isolation.
OPA policy runs as a special depends_on=["*"] plugin via _opa.py — it is
intentionally excluded from auto-discovery and tested through the evaluate
pipeline (test_evaluate_pipeline.py), not here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.conftest import E2E_ENABLED, breakpoint_dump, run_review

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")


class TestSupplyChain:
    """Supply-chain plugin must detect lockfile/integrity signals."""

    def test_supply_chain_finds_issues(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="supply-chain", output_format="json")
        breakpoint_dump(tmp_path, "scanner_supply_chain", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"
        assert isinstance(parsed, dict), f"Expected JSON, got: {type(parsed)}"


class TestBlastRadius:
    """Blast-radius plugin must run without crashing on the fixture repo."""

    def test_blast_radius_completes(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="blast-radius", output_format="json")
        breakpoint_dump(tmp_path, "scanner_blast_radius", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"
        assert isinstance(parsed, dict), f"Expected JSON, got: {type(parsed)}"
