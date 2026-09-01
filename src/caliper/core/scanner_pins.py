"""Pinned scanner releases — the single source of truth for the image and the CLI.
# tested-by: tests/unit/test_scanner_pins.py

The Dockerfile bakes these exact releases into the container; ``caliper
install-scanners`` installs the same ones on a developer machine. Every asset
is sha256-pinned per platform; a drift-guard test keeps the Linux checksums
and versions identical to the Dockerfile's ``ARG`` pins.

Not pinned here (documented externals): ``pmd`` needs a JRE, ``lizard`` and
``pyrefly`` are Python packages installed into caliper's own environment,
``swiftlint`` and ``scancode`` are opt-in and platform-limited.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PLATFORMS: tuple[str, ...] = ("darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64")

# Commit of semgrep/semgrep-rules baked into the image (see Dockerfile).
SEMGREP_RULES_COMMIT = "40b8c63f75dc7c22c8a77482d73bfb864b146f7e"


@dataclass(frozen=True)
class Asset:
    url: str
    sha256: str
    kind: Literal["binary", "tar.gz", "zip"]
    member: str | None = None  # path of the executable inside an archive


@dataclass(frozen=True)
class ScannerPin:
    name: str  # binary name on PATH
    version: str
    plugins: tuple[str, ...]  # caliper plugins that need it
    assets: dict[str, Asset]  # platform key -> asset


def platform_key(system: str, machine: str) -> str:
    """Map ``platform.system()``/``platform.machine()`` to a pin platform key."""
    os_name = {"darwin": "darwin", "linux": "linux"}.get(system.lower())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
        machine.lower()
    )
    if os_name is None or arch is None:
        raise ValueError(f"unsupported platform: {system}/{machine}")
    return f"{os_name}-{arch}"


def _gh(repo: str, tag: str, asset: str) -> str:
    return f"https://github.com/{repo}/releases/download/{tag}/{asset}"


def _syft() -> ScannerPin:
    v = "1.43.0"
    shas = {
        "darwin-arm64": (
            "darwin_arm64",
            "3640e2181c8be7a56377f3c96e520d5380c924dbafd115ee3c8d45fcbc89cac2",
        ),
        "darwin-amd64": (
            "darwin_amd64",
            "08fd18f55037f999f50b2c2256a9285f0146978a0b16cdc58662ecdc85d0e3c0",
        ),
        "linux-arm64": (
            "linux_arm64",
            "afe92510c467f952a009b994f2d998ff8f9dd266dc26eca55d14a0dd46fec7f2",
        ),
        "linux-amd64": (
            "linux_amd64",
            "7b98251d2d08926bb5d4639b56b1f0996a58ef6667c5830e3fe3cd3ad5f4214a",
        ),
    }
    return ScannerPin(
        "syft",
        v,
        ("syft",),
        {
            p: Asset(_gh("anchore/syft", f"v{v}", f"syft_{v}_{a}.tar.gz"), s, "tar.gz", "syft")
            for p, (a, s) in shas.items()
        },
    )


def _trivy() -> ScannerPin:
    v = "0.70.0"
    shas = {
        "darwin-arm64": (
            "macOS-ARM64",
            "68e543c51dcc96e1c344053a4fde9660cf602c25565d9f09dc17dd41e13b838a",
        ),
        "darwin-amd64": (
            "macOS-64bit",
            "52d531452b19e7593da29366007d02a810e1e0080d02f9cf6a1afb46c35aaa93",
        ),
        "linux-arm64": (
            "Linux-ARM64",
            "2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d",
        ),
        "linux-amd64": (
            "Linux-64bit",
            "8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9",
        ),
    }
    return ScannerPin(
        "trivy",
        v,
        ("trivy",),
        {
            p: Asset(
                _gh("aquasecurity/trivy", f"v{v}", f"trivy_{v}_{a}.tar.gz"), s, "tar.gz", "trivy"
            )
            for p, (a, s) in shas.items()
        },
    )


def _osv() -> ScannerPin:
    v = "2.3.5"
    shas = {
        "darwin-arm64": (
            "darwin_arm64",
            "b740efe0b08fb817865e818a498997d5f042f14b8eeafb6393176ce84dd09cf6",
        ),
        "darwin-amd64": (
            "darwin_amd64",
            "3b1c72d59dcbad99fa4eb2c72bf2e82017f83e0268340e4b00af76a1fea32c85",
        ),
        "linux-arm64": (
            "linux_arm64",
            "fa46ad2b3954db5d5335303d45de921613393285d9a93c140b63b40e35e9ce50",
        ),
        "linux-amd64": (
            "linux_amd64",
            "bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b",
        ),
    }
    return ScannerPin(
        "osv-scanner",
        v,
        ("osv-scanner",),
        {
            p: Asset(_gh("google/osv-scanner", f"v{v}", f"osv-scanner_{a}"), s, "binary")
            for p, (a, s) in shas.items()
        },
    )


def _opa() -> ScannerPin:
    v = "1.15.2"
    shas = {
        "darwin-arm64": (
            "opa_darwin_arm64_static",
            "bc8121f0d3cebf5efd84dc9f6d13080eaaf976ef4ca994b9de8a098b52d25db7",
        ),
        "darwin-amd64": (
            "opa_darwin_amd64",
            "34db678edd97adf6f0b4ed7cb20c2d1e81e7ab793e5ca6f08e734c0473c47b8e",
        ),
        "linux-arm64": (
            "opa_linux_arm64_static",
            "6651bf5a80cfec6ba6a2d3b6a550b8f748d9cade1c74d54b5f854782f9bea67a",
        ),
        "linux-amd64": (
            "opa_linux_amd64_static",
            "a9d9481e463e7af8cb1a2cd7c3deb764f0327b3281c54e632546c2f425fc0824",
        ),
    }
    return ScannerPin(
        "opa",
        v,
        ("opa",),
        {
            p: Asset(_gh("open-policy-agent/opa", f"v{v}", a), s, "binary")
            for p, (a, s) in shas.items()
        },
    )


def _gitleaks() -> ScannerPin:
    v = "8.30.1"
    shas = {
        "darwin-arm64": (
            "darwin_arm64",
            "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
        ),
        "darwin-amd64": (
            "darwin_x64",
            "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
        ),
        "linux-arm64": (
            "linux_arm64",
            "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
        ),
        "linux-amd64": (
            "linux_x64",
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        ),
    }
    return ScannerPin(
        "gitleaks",
        v,
        ("gitleaks",),
        {
            p: Asset(
                _gh("gitleaks/gitleaks", f"v{v}", f"gitleaks_{v}_{a}.tar.gz"),
                s,
                "tar.gz",
                "gitleaks",
            )
            for p, (a, s) in shas.items()
        },
    )


def _kube_linter() -> ScannerPin:
    v = "0.8.3"
    shas = {
        "darwin-arm64": (
            "kube-linter-darwin_arm64.tar.gz",
            "6e3443a8ff8625a9fc31a38682c783988d7559018f7ff707a4f8c77c18c92f14",
        ),
        "darwin-amd64": (
            "kube-linter-darwin.tar.gz",
            "c62e8af3c9df2557c7a3922119ea1b35597794737d1ccad493f63a0d66e7b8fc",
        ),
        "linux-arm64": (
            "kube-linter-linux_arm64.tar.gz",
            "802e1b09eabd08f6f0a060a6b8ab2bf7bc7e6bf4f673bb2692303704c84b3e22",
        ),
        "linux-amd64": (
            "kube-linter-linux.tar.gz",
            "1a6d8419b11971372971fdbc22682b684ebfb7cf1c39591662d1b6ca736c41df",
        ),
    }
    return ScannerPin(
        "kube-linter",
        v,
        ("kube-linter",),
        {
            p: Asset(_gh("stackrox/kube-linter", f"v{v}", a), s, "tar.gz", "kube-linter")
            for p, (a, s) in shas.items()
        },
    )


def _ls_lint() -> ScannerPin:
    v = "2.3.1"
    shas = {
        "darwin-arm64": (
            "darwin-arm64",
            "e4ed2ce2b7b61d6685769e34c6375ccecb14a3f00ee59438cf82d01d6236a3c4",
        ),
        "darwin-amd64": (
            "darwin-amd64",
            "fc17fc642e95fd8bf7030ed661e86758bee654f6e11f1e31a5f21887f47f73ae",
        ),
        "linux-arm64": (
            "linux-arm64",
            "2abdb71243c619f0bb29587be5c228bec84c107985f2c066139ef0ec35fd3a99",
        ),
        "linux-amd64": (
            "linux-amd64",
            "b5a0d2e4427ad039fbc574551f17679f38f142b25d15e0e538769f8cf15af397",
        ),
    }
    return ScannerPin(
        "ls-lint",
        v,
        ("ls-lint",),
        {
            p: Asset(_gh("loeffel-io/ls-lint", f"v{v}", f"ls-lint-{a}"), s, "binary")
            for p, (a, s) in shas.items()
        },
    )


def _jq() -> ScannerPin:
    v = "1.7.1"
    shas = {
        "darwin-arm64": (
            "macos-arm64",
            "0bbe619e663e0de2c550be2fe0d240d076799d6f8a652b70fa04aea8a8362e8a",
        ),
        "darwin-amd64": (
            "macos-amd64",
            "4155822bbf5ea90f5c79cf254665975eb4274d426d0709770c21774de5407443",
        ),
        "linux-arm64": (
            "linux-arm64",
            "4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5",
        ),
        "linux-amd64": (
            "linux-amd64",
            "5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5",
        ),
    }
    return ScannerPin(
        "jq",
        v,
        (),
        {
            p: Asset(_gh("jqlang/jq", f"jq-{v}", f"jq-{a}"), s, "binary")
            for p, (a, s) in shas.items()
        },
    )


def _opengrep() -> ScannerPin:
    v = "1.20.0"
    shas = {
        "darwin-arm64": (
            "opengrep_osx_arm64",
            "2937c14e09956dbdb7f76acfde1d161d473c2da0d0e46a21907c731b5633e479",
        ),
        "darwin-amd64": (
            "opengrep_osx_x86",
            "716ce3b1b20d383cf4923b9bb931e7f98e4603049de9f0a9ada2472ec5c6ffe5",
        ),
        "linux-arm64": (
            "opengrep_manylinux_aarch64",
            "3bade33c9aee60edf88899cac2b58086bf728caf0a93aced97dd77c272a740f1",
        ),
        "linux-amd64": (
            "opengrep_manylinux_x86",
            "09cbb4c938df696246018a678823adaa8d651a774f321fd19fb5ad44c0129860",
        ),
    }
    return ScannerPin(
        "opengrep",
        v,
        ("semgrep",),
        {p: Asset(_gh("opengrep/opengrep", f"v{v}", a), s, "binary") for p, (a, s) in shas.items()},
    )


SCANNER_PINS: dict[str, ScannerPin] = {
    p.name: p
    for p in (
        _syft(),
        _trivy(),
        _osv(),
        _opa(),
        _gitleaks(),
        _kube_linter(),
        _ls_lint(),
        _jq(),
        _opengrep(),
    )
}

# Plugin name -> binaries it needs (None = pure Python). ``caliper healthcheck``
# and the install offer both read this.
PLUGIN_BINARIES: dict[str, list[str] | None] = {
    "blast-radius": None,
    "complexity": ["lizard"],
    "cpd": ["pmd"],
    "gitleaks": ["gitleaks"],
    "kube-linter": ["kube-linter"],
    "ls-lint": ["ls-lint"],
    "mypy": ["pyrefly", "pyright", "mypy"],
    "opa": ["opa"],
    "osv-scanner": ["osv-scanner"],
    "scancode": ["scancode"],
    "semgrep": ["opengrep"],
    "supply-chain": None,
    "swiftlint": ["swiftlint"],
    "syft": ["syft"],
    "trivy": ["trivy"],
    "deterministic": None,
}
