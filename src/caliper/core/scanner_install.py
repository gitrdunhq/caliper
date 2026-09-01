"""Pure planning for ``caliper install-scanners`` (functional core).
# tested-by: tests/unit/test_scanner_install.py

No IO here: given the pin table, a platform key, and a ``which`` function, decide
what to install. The download/extract/write happens in
``data/scanner_installer.py``; the prompt lives in ``cli/install_cmd.py``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from caliper.core.scanner_pins import PLUGIN_BINARIES, SCANNER_PINS, Asset

_NOT_INSTALLED = re.compile(r"\[NOT_INSTALLED\]\s+(?P<tool>[A-Za-z0-9_./-]+)")


@dataclass(frozen=True)
class InstallItem:
    name: str
    version: str
    asset: Asset


@dataclass(frozen=True)
class InstallPlan:
    items: list[InstallItem] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)


def plan_install(
    names: Iterable[str] | None,
    platform: str,
    *,
    which: Callable[[str], str | None],
) -> InstallPlan:
    """Select the pinned binaries to install: requested (or all), minus present."""
    requested = list(names) if names is not None else sorted(SCANNER_PINS)
    items: list[InstallItem] = []
    present: list[str] = []
    unsupported: list[str] = []
    for name in requested:
        pin = SCANNER_PINS.get(name)
        if pin is None:
            unsupported.append(name)
            continue
        if which(name):
            present.append(name)
            continue
        items.append(InstallItem(name=name, version=pin.version, asset=pin.assets[platform]))
    return InstallPlan(items=items, already_present=present, unsupported=unsupported)


def missing_binaries_from_results(results: Iterable) -> list[str]:
    """Pinned binaries whose plugins reported ``[NOT_INSTALLED]`` (sorted, unique)."""
    found: set[str] = set()
    for r in results:
        err = getattr(r, "error", "") or ""
        m = _NOT_INSTALLED.search(err)
        if not m:
            continue
        tool = m.group("tool")
        if tool in SCANNER_PINS:
            found.add(tool)
            continue
        # Plugin errors name the plugin's first-choice tool; map via the plugin.
        for b in PLUGIN_BINARIES.get(getattr(r, "plugin_name", ""), None) or []:
            if b in SCANNER_PINS:
                found.add(b)
    return sorted(found)


def verify_sha256(data: bytes, expected_hex: str) -> bool:
    return hashlib.sha256(data).hexdigest() == expected_hex.lower()


def default_bin_dir(env: dict[str, str]) -> Path:
    """``$CALIPER_BIN_DIR`` wins, else ``~/.local/bin`` (the uv tool convention)."""
    if env.get("CALIPER_BIN_DIR"):
        return Path(env["CALIPER_BIN_DIR"])
    return Path(env.get("HOME", "~")).expanduser() / ".local" / "bin"


def path_hint(bin_dir: Path, path_env: str) -> str | None:
    """Advice when *bin_dir* is not on PATH; None when it already is."""
    entries = {Path(p) for p in path_env.split(":") if p}
    if bin_dir in entries:
        return None
    return f'{bin_dir} is not on your PATH. Add it, e.g.: export PATH="{bin_dir}:$PATH"'
