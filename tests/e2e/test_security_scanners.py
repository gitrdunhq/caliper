# tested-by: self (e2e)
"""E2E: security scanners find planted signals in vuln-repo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    E2E_ENABLED,
    breakpoint_dump,
    get_plugin_findings,
    run_review,
)

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")


class TestGitleaks:
    def test_gitleaks_finds_hardcoded_key(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="gitleaks", output_format="json")
        breakpoint_dump(tmp_path, "scanner_gitleaks", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "gitleaks")
        secret_findings = [
            f
            for f in findings
            if "private" in json.dumps(f).lower() or "rsa" in json.dumps(f).lower()
        ]
        assert (
            len(secret_findings) >= 1
        ), f"Gitleaks should find RSA private key. Findings: {json.dumps(findings, indent=2)}"


class TestSemgrep:
    @pytest.mark.xfail(reason="semgrep registry connectivity intermittent on self-hosted runners")
    def test_semgrep_finds_dangerous_pattern(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="semgrep", output_format="json")
        breakpoint_dump(tmp_path, "scanner_semgrep", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "semgrep")
        assert (
            len(findings) >= 1
        ), f"Semgrep should find at least 1 finding. Output: {result.output[:500]}"


class TestClamav:
    def test_clamav_completes(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="clamav", output_format="json")
        breakpoint_dump(tmp_path, "scanner_clamav", parsed)

        assert result.exit_code == 0, f"ClamAV crashed: {result.output}"
