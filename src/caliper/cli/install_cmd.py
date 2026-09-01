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
    InstallPlan,
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


def _run_plan(plan: InstallPlan, bin_dir: Path) -> int:
    """Install every item; returns the number installed. Raises on the first failure."""
    inst = _installer()
    for item in plan.items:
        click.echo(f"  installing {item.name} {item.version} ...", nl=False)
        dest = inst.install(item, bin_dir)
        click.echo(f" {dest}")
    return len(plan.items)


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
def install_scanners(names: tuple[str, ...], bin_dir: str | None, dry_run: bool, yes: bool) -> None:
    """Install the pinned scanner binaries for this machine.

    With no NAMES, installs every pinned scanner that is not already on PATH.
    Releases and sha256 checksums are the same ones baked into the container
    image (core/scanner_pins.py). Not covered: pmd (needs a JRE), scancode,
    swiftlint, and the Python tools lizard/pyrefly.
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
    if plan.already_present:
        click.echo(f"already on PATH: {', '.join(plan.already_present)}")
    if not plan.items:
        click.echo("nothing to install")
        return
    click.echo(f"platform {plat} -> {target}")
    for item in plan.items:
        click.echo(f"  {item.name:<12} {item.version:<8} {item.asset.url}")
    if dry_run:
        return
    if not yes and not _confirm(f"Install {len(plan.items)} scanner(s) into {target}?"):
        click.echo("aborted")
        sys.exit(1)
    try:
        n = _run_plan(plan, target)
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
        n = _run_plan(plan, target)
    except (RuntimeError, ValueError) as exc:
        click.echo(f"install failed: {exc}", err=True)
        return False
    hint = path_hint(target, os.environ.get("PATH", ""))
    if hint:
        click.echo(hint, err=True)
    click.echo(f"installed {n} scanner(s) — re-run the review to use them", err=True)
    return n > 0
