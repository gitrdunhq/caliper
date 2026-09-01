"""Scanner pin table — one source of truth for versions, assets, and checksums.
# tested-by: tests/unit/test_scanner_pins.py

The Dockerfile bakes these binaries into the image; `caliper install-scanners`
installs the same pinned releases on a developer's machine. A drift guard keeps
the two from diverging.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from caliper.core.scanner_pins import (
    PLATFORMS,
    PLUGIN_BINARIES,
    SCANNER_PINS,
    SEMGREP_RULES_COMMIT,
    platform_key,
)

_REPO = Path(__file__).resolve().parents[2]
_DOCKERFILE = (_REPO / "Dockerfile").read_text()


class TestShape:
    def test_platform_keys(self) -> None:
        assert PLATFORMS == ("darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64")

    @pytest.mark.parametrize("name", sorted(SCANNER_PINS))
    def test_every_pin_covers_every_platform_with_a_real_checksum(self, name: str) -> None:
        pin = SCANNER_PINS[name]
        assert set(pin.assets) == set(PLATFORMS), f"{name} missing platforms"
        for plat, asset in pin.assets.items():
            assert asset.url.startswith("https://"), (name, plat)
            assert re.fullmatch(r"[0-9a-f]{64}", asset.sha256), (name, plat, asset.sha256)
            assert asset.kind in ("binary", "tar.gz", "zip")
            if asset.kind != "binary":
                assert asset.member, (name, plat)
            assert pin.version in asset.url or name == "opengrep", (name, plat)

    def test_binary_name_is_the_pin_key(self) -> None:
        for name, pin in SCANNER_PINS.items():
            assert pin.name == name

    def test_plugin_binaries_reference_known_pins_or_documented_externals(self) -> None:
        pinned = set(SCANNER_PINS)
        externals = {"pmd", "lizard", "pyrefly", "pyright", "mypy", "scancode", "swiftlint"}
        for plugin, binaries in PLUGIN_BINARIES.items():
            if binaries is None:
                continue
            for b in binaries:
                assert b in pinned or b in externals, (plugin, b)


class TestPlatformKey:
    @pytest.mark.parametrize(
        ("system", "machine", "expected"),
        [
            ("Darwin", "arm64", "darwin-arm64"),
            ("Darwin", "x86_64", "darwin-amd64"),
            ("Linux", "aarch64", "linux-arm64"),
            ("Linux", "x86_64", "linux-amd64"),
            ("Linux", "AMD64", "linux-amd64"),
        ],
    )
    def test_maps_uname_to_platform(self, system: str, machine: str, expected: str) -> None:
        assert platform_key(system, machine) == expected

    def test_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported platform"):
            platform_key("Windows", "AMD64")


class TestDockerfileDrift:
    """The image and the local installer must ship the same releases."""

    @staticmethod
    def _arg(name: str) -> str:
        m = re.search(rf"^ARG {name}=([^\s]+)", _DOCKERFILE, flags=re.M)
        assert m, f"ARG {name} not in Dockerfile"
        return m.group(1)

    @pytest.mark.parametrize(
        ("pin", "arg"),
        [
            ("syft", "SYFT_VERSION"),
            ("trivy", "TRIVY_VERSION"),
            ("osv-scanner", "OSV_VERSION"),
            ("opa", "OPA_VERSION"),
            ("gitleaks", "GITLEAKS_VERSION"),
            ("kube-linter", "KUBE_LINTER_VERSION"),
            ("ls-lint", "LS_LINT_VERSION"),
            ("jq", "JQ_VERSION"),
            ("opengrep", "OPENGREP_VERSION"),
        ],
    )
    def test_versions_match_dockerfile(self, pin: str, arg: str) -> None:
        assert SCANNER_PINS[pin].version == self._arg(arg)

    @pytest.mark.parametrize(
        ("pin", "arg_prefix"),
        [
            ("syft", "SYFT"),
            ("trivy", "TRIVY"),
            ("osv-scanner", "OSV"),
            ("opa", "OPA"),
            ("gitleaks", "GITLEAKS"),
            ("kube-linter", "KUBE_LINTER"),
            ("ls-lint", "LS_LINT"),
            ("jq", "JQ"),
            ("opengrep", "OPENGREP"),
        ],
    )
    def test_linux_checksums_match_dockerfile(self, pin: str, arg_prefix: str) -> None:
        assets = SCANNER_PINS[pin].assets
        assert assets["linux-arm64"].sha256 == self._arg(f"{arg_prefix}_SHA256_ARM64")
        assert assets["linux-amd64"].sha256 == self._arg(f"{arg_prefix}_SHA256_AMD64")

    def test_semgrep_rules_commit_matches_dockerfile(self) -> None:
        assert self._arg("SEMGREP_RULES_COMMIT") == SEMGREP_RULES_COMMIT
