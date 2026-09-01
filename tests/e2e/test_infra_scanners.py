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


class TestTrivyMisconfig:
    def test_trivy_finds_iac_misconfig(self, vuln_repo: Path, tmp_path: Path) -> None:
        """Trivy's misconfig scanner covers the CloudFormation/K8s ground cfn-nag and cdk-nag held."""
        result, parsed = run_review(vuln_repo, scanners="trivy", output_format="json")
        breakpoint_dump(tmp_path, "scanner_trivy_misconfig", parsed)

        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

        findings = get_plugin_findings(parsed, "trivy")
        iac = [
            f for f in findings if str(f.get("file", "")).endswith((".yaml", ".yml", "Dockerfile"))
        ]
        assert (
            iac
        ), f"trivy should flag template.yaml/deployment.yaml misconfigs. Findings: {findings[:3]}"
