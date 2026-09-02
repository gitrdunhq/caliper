"""``caliper install-scanners`` and the review-time install offer.
# tested-by: tests/unit/test_install_cmd.py
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path

import click

from caliper.core.scanner_install import (
    InstallItem,
    default_bin_dir,
    path_hint,
    plan_install,
)
from caliper.core.scanner_pins import SCANNER_PINS, platform_key


# Seams (monkeypatched in tests).
def _installer():
    from caliper.data.scanner_installer import HttpScannerInstaller

    return HttpScannerInstaller()


def _which(name: str) -> str | None:
    return shutil.which(name)


def _platform() -> str:
    return platform_key(platform.system(), platform.machine())


def _isatty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _confirm(message: str) -> bool:
    return click.confirm(message, default=False)


def _run_plan(items: list[InstallItem], bin_dir: Path) -> int:
    """Install every item; returns the number installed. Raises on the first failure."""
    inst = _installer()
    for item in items:
        click.echo(f"  installing {item.name} {item.version} ...", nl=False)
        dest = inst.install(item, bin_dir)
        click.echo(f" {dest}")
    return len(items)


def _shadowing_path_entries() -> set[Path]:
    return {Path(p) for p in os.environ.get("PATH", "").split(":") if p}


@click.command("install-scanners")
@click.argument("names", nargs=-1)
@click.option(
    "--bin-dir",
    type=click.Path(),
    default=None,
    help="Install dir (default: $CALIPER_BIN_DIR or ~/.local/bin).",
)
@click.option("--dry-run", is_flag=True, help="Show what would be installed.")
@click.option("--yes", "-y", is_flag=True, help="Do not prompt.")
@click.option(
    "--skip-present",
    is_flag=True,
    help=(
        "Skip a scanner whose binary already exists elsewhere on PATH, ahead of "
        "--bin-dir, instead of installing over it into --bin-dir."
    ),
)
def install_scanners(
    names: tuple[str, ...],
    bin_dir: str | None,
    dry_run: bool,
    yes: bool,
    skip_present: bool,
) -> None:
    """Install the pinned scanner binaries for this machine.

    With no NAMES, installs every pinned scanner that is not already on PATH.
    Releases and sha256 checksums are the same ones baked into the container
    image (core/scanner_pins.py). Not covered: pmd (needs a JRE), scancode,
    swiftlint, and the Python tools lizard/pyrefly.

    A requested scanner can be shadowed: a same-named binary already lives in
    a directory that is *also* on PATH (unlike a binary found somewhere off
    PATH entirely). Installing into --bin-dir alone would silently do nothing
    useful there, since the shadowing copy — of unknown version — would still
    win on PATH. By default we install into --bin-dir anyway and warn that
    --bin-dir must precede that directory on PATH to take effect; pass
    --skip-present to leave it alone instead.
    """
    target = Path(bin_dir) if bin_dir else default_bin_dir(dict(os.environ))
    try:
        plat = _platform()
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    plan = plan_install(list(names) or None, plat, which=_which)

    if plan.unsupported:
        known = ", ".join(sorted(SCANNER_PINS))
        click.echo(
            f"error: not a pinned scanner: {', '.join(plan.unsupported)} (known: {known})",
            err=True,
        )
        sys.exit(2)

    items = list(plan.items)
    still_present: list[str] = []
    path_entries = _shadowing_path_entries()
    for name in plan.already_present:
        hit = _which(name)
        shadow_dir = Path(hit).parent if hit else None
        if hit is None or shadow_dir not in path_entries:
            still_present.append(name)
            continue
        click.echo(f"  {name}: present elsewhere: {hit} (version mismatch unknown)")
        if skip_present:
            click.echo(
                f"  skipped {name} — present elsewhere: {hit} "
                "(version mismatch unknown); pass without --skip-present to install anyway"
            )
            continue
        pin = SCANNER_PINS[name]
        items.append(InstallItem(name=name, version=pin.version, asset=pin.assets[plat]))
        click.echo(
            f"  note: {target} must precede {shadow_dir} on PATH for the {name} "
            "install in --bin-dir to take effect"
        )

    if still_present:
        click.echo(f"already on PATH: {', '.join(still_present)}")
    if not items:
        click.echo("nothing to install")
        return
    click.echo(f"platform {plat} -> {target}")
    for item in items:
        click.echo(f"  {item.name:<12} {item.version:<8} {item.asset.url}")
    if dry_run:
        return
    if not yes and not _confirm(f"Install {len(items)} scanner(s) into {target}?"):
        click.echo("aborted")
        sys.exit(1)
    try:
        n = _run_plan(items, target)
    except RuntimeError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"installed {n} scanner(s)")
    hint = path_hint(target, os.environ.get("PATH", ""))
    if hint:
        click.echo(hint)


def offer_install(missing: list[str]) -> bool:
    """After a review, offer to install pinned binaries that came back NOT_INSTALLED.

    Interactive (TTY on both ends): prompt, install into the default bin dir,
    return True when something was installed. Non-interactive: print the exact
    command to stderr and return False. Never raises.
    """
    if not missing:
        return False
    cmd = f"caliper install-scanners {' '.join(missing)}"
    if not _isatty():
        click.echo(f"hint: {len(missing)} scanner(s) not installed — run: {cmd}", err=True)
        return False
    if not _confirm(
        f"{len(missing)} scanner(s) not installed ({', '.join(missing)}). Install now?"
    ):
        click.echo(f"skipped — run later: {cmd}", err=True)
        return False
    try:
        plan = plan_install(missing, _platform(), which=_which)
        target = default_bin_dir(dict(os.environ))
        n = _run_plan(plan.items, target)
    except (RuntimeError, ValueError) as exc:
        click.echo(f"install failed: {exc}", err=True)
        return False
    hint = path_hint(target, os.environ.get("PATH", ""))
    if hint:
        click.echo(hint, err=True)
    click.echo(f"installed {n} scanner(s) — re-run the review to use them", err=True)
    return n > 0
