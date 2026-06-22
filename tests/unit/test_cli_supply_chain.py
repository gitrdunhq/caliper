"""CLI tests for the gated `supply-chain-diff` command.

DPS-12 domains:
  Integrity (SAFETY): the command runs only when the feature flag is set.
  Availability / fail-open (LIVENESS): a clean diff produces a clean report and
    a zero exit; advise mode exits non-zero only when the gate rejects.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

os.environ.setdefault("CALIPER_DB_DSN", "postgresql://t:t@localhost/t")
os.environ.setdefault("CALIPER_ALLOW_GLOBAL", "1")

from caliper.cli.main import cli  # noqa: E402
from caliper.core.models import DecisionVerdict, PolicyEvaluation  # noqa: E402
from caliper.core.plugin import PluginFinding  # noqa: E402

_DIFF = (
    "diff --git a/requirements.txt b/requirements.txt\n"
    "--- a/requirements.txt\n+++ b/requirements.txt\n"
    "@@ -1 +1 @@\n-flask==2.0.0\n+flask==2.0.1\n"
)


def _malicious_finding() -> PluginFinding:
    return PluginFinding(
        id="SC-INSTALL-HOOK",
        severity="critical",
        message="adds postinstall hook",
        category="supply_chain",
        package="flask",
        version="2.0.1",
        metadata={"threat_signal": "SC-INSTALL-HOOK", "version_diff": {"package": "flask"}},
    )


@pytest.fixture
def _patched(monkeypatch):
    """Patch the scan + gate so the CLI test never hits the network or OPA."""
    findings = [_malicious_finding()]
    monkeypatch.setattr(
        "caliper.data.supply_chain_scan.run_supply_chain_diff", lambda *a, **k: findings
    )

    def fake_gate(_findings, _settings):
        return PolicyEvaluation(
            decision=DecisionVerdict.reject, triggered_rules=["x"], policy_bundle_version="t"
        )

    monkeypatch.setattr("caliper.core.supply_chain_diff.evaluate_gate", fake_gate)
    return findings


def test_gated_off_skips(monkeypatch):  # Integrity
    monkeypatch.delenv("CALIPER_SUPPLY_CHAIN_DIFF_ENABLED", raising=False)
    res = CliRunner().invoke(cli, ["supply-chain-diff", "--diff", "-"], input=_DIFF)
    assert res.exit_code == 0
    assert "gated off" in (res.stderr or res.output)


def test_gated_on_markdown_reports_findings(monkeypatch, _patched):
    monkeypatch.setenv("CALIPER_SUPPLY_CHAIN_DIFF_ENABLED", "1")
    res = CliRunner().invoke(cli, ["supply-chain-diff", "--diff", "-"], input=_DIFF)
    assert res.exit_code == 0  # monitor mode never fails the build
    assert "SC-INSTALL-HOOK" in res.output
    assert "reject" in res.output


def test_advise_mode_exits_nonzero_on_reject(monkeypatch, _patched):  # Availability
    monkeypatch.setenv("CALIPER_SUPPLY_CHAIN_DIFF_ENABLED", "1")
    res = CliRunner().invoke(
        cli,
        ["supply-chain-diff", "--diff", "-", "--operating-mode", "advise"],
        input=_DIFF,
    )
    assert res.exit_code == 1


def test_json_format(monkeypatch, _patched):
    monkeypatch.setenv("CALIPER_SUPPLY_CHAIN_DIFF_ENABLED", "1")
    res = CliRunner().invoke(
        cli, ["supply-chain-diff", "--diff", "-", "--format", "json"], input=_DIFF
    )
    assert res.exit_code == 0
    assert '"supply-chain-diff"' in res.output


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
