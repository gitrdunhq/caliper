"""Pure install planning for `caliper install-scanners` and the review-time offer.
# tested-by: tests/unit/test_scanner_install.py
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from caliper.core.plugin import PluginResult
from caliper.core.scanner_install import (
    InstallPlan,
    default_bin_dir,
    missing_binaries_from_results,
    path_hint,
    plan_install,
    verify_sha256,
)
from caliper.core.scanner_pins import SCANNER_PINS


def _which_none(_name: str) -> str | None:
    return None


def _which_all(name: str) -> str | None:
    return f"/usr/local/bin/{name}"


class TestPlan:
    def test_plans_only_missing_pinned_binaries(self) -> None:
        plan = plan_install(
            ["syft", "trivy"], "darwin-arm64", which=lambda n: "/x/syft" if n == "syft" else None
        )
        assert isinstance(plan, InstallPlan)
        assert [i.name for i in plan.items] == ["trivy"]
        assert plan.already_present == ["syft"]
        assert plan.unsupported == []

    def test_all_selects_every_pin(self) -> None:
        plan = plan_install(None, "linux-amd64", which=_which_none)
        assert {i.name for i in plan.items} == set(SCANNER_PINS)

    def test_unknown_names_are_reported_not_raised(self) -> None:
        plan = plan_install(["syft", "pmd", "nope"], "linux-arm64", which=_which_none)
        assert [i.name for i in plan.items] == ["syft"]
        assert plan.unsupported == ["pmd", "nope"]

    def test_items_carry_platform_asset(self) -> None:
        plan = plan_install(["osv-scanner"], "darwin-amd64", which=_which_none)
        item = plan.items[0]
        assert item.asset is SCANNER_PINS["osv-scanner"].assets["darwin-amd64"]
        assert item.version == SCANNER_PINS["osv-scanner"].version

    def test_nothing_to_do_when_everything_present(self) -> None:
        plan = plan_install(None, "linux-amd64", which=_which_all)
        assert plan.items == [] and len(plan.already_present) == len(SCANNER_PINS)


class TestMissingFromResults:
    def test_extracts_binaries_for_not_installed_plugins(self) -> None:
        results = [
            PluginResult(plugin_name="trivy", error="[NOT_INSTALLED] trivy not installed"),
            PluginResult(plugin_name="gitleaks", findings=[]),
            PluginResult(plugin_name="semgrep", error="[NOT_INSTALLED] opengrep not installed"),
            PluginResult(plugin_name="cpd", error="[TIMEOUT] pmd timed out after 60s"),
        ]
        assert missing_binaries_from_results(results) == ["opengrep", "trivy"]

    def test_only_pinned_binaries_are_offered(self) -> None:
        results = [PluginResult(plugin_name="cpd", error="[NOT_INSTALLED] pmd not installed")]
        assert missing_binaries_from_results(results) == []


class TestHelpers:
    def test_verify_sha256(self) -> None:
        data = b"hello"
        assert verify_sha256(data, hashlib.sha256(data).hexdigest())
        assert not verify_sha256(data, "0" * 64)

    def test_default_bin_dir_env_override(self, tmp_path: Path) -> None:
        assert default_bin_dir({"CALIPER_BIN_DIR": str(tmp_path)}) == tmp_path
        assert default_bin_dir({"HOME": str(tmp_path)}) == tmp_path / ".local" / "bin"

    def test_path_hint_only_when_dir_not_on_path(self, tmp_path: Path) -> None:
        assert path_hint(tmp_path, f"/usr/bin:{tmp_path}") is None
        hint = path_hint(tmp_path, "/usr/bin")
        assert hint and str(tmp_path) in hint and "PATH" in hint


@pytest.mark.parametrize("plat", ["darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64"])
def test_every_platform_plans_every_pin(plat: str) -> None:
    plan = plan_install(None, plat, which=_which_none)
    assert len(plan.items) == len(SCANNER_PINS)
