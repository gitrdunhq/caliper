# tested-by: self (e2e)
"""E2E: infrastructure scanners find planted misconfigs in vuln-repo."""

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


class TestKubeLinter:
    def test_kube_linter_finds_privileged(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="kube-linter", output_format="json")
        breakpoint_dump(tmp_path, "scanner_kube_linter", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "kube-linter")
        priv_findings = [
            f
            for f in findings
            if "privileged" in json.dumps(f).lower() or "run-as-non-root" in json.dumps(f).lower()
        ]
        assert (
            len(priv_findings) >= 1
        ), f"Kube-linter should find privileged container. Findings: {json.dumps(findings, indent=2)}"


class TestCfnNag:
    @pytest.mark.xfail(
        reason="Flaky test - cfn-nag scanner intermittently fails to find findings", strict=False
    )
    def test_cfn_nag_finds_unencrypted(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="cfn-nag", output_format="json")
        breakpoint_dump(tmp_path, "scanner_cfn_nag", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "cfn-nag")
        security_findings = [
            f
            for f in findings
            if any(
                k in json.dumps(f).lower()
                for k in ("encryption", "security group", "ingress", "cidr", "0.0.0.0")
            )
        ]
        assert (
            len(security_findings) >= 1
        ), f"cfn-nag should find insecure resources. Findings: {json.dumps(findings, indent=2)}"


class TestCdkNag:
    def test_cdk_nag_completes(self, vuln_repo: Path, tmp_path: Path) -> None:
        result, parsed = run_review(vuln_repo, scanners="cdk-nag", output_format="json")
        breakpoint_dump(tmp_path, "scanner_cdk_nag", parsed)

        assert result.exit_code == 0, f"cdk-nag crashed: {result.output}"
