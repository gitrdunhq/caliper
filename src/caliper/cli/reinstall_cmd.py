"""``caliper reinstall`` — rebuild + reinstall caliper from local source (dev).

# tested-by: tests/unit/test_reinstall_cmd.py

A developer convenience: rebuild the working tree and reinstall it as the
``caliper`` uv tool with a unique local build id, so the installed binary always
reflects HEAD. (uv caches built wheels by ``(name, version)``; an unchanged
static version can make ``--reinstall`` serve a stale wheel. A unique ``+dev``
segment busts that cache.) The version-bump-and-restore logic lives in
``scripts/install-local.sh`` — this command delegates to it so there is a single
source of truth.

Chicken-and-egg: this runs from the *installed* binary but rebuilds *from
source*, so it must run inside a checkout. It resolves the repo root via
``git rev-parse --show-toplevel`` (or ``--repo``), validates it is actually the
caliper project, and only then shells out. All IO goes through the
``ToolRunnerPort`` seam so it is testable with a fake runner — no real git, no
real install.
"""

from __future__ import annotations

from pathlib import Path

import click
import structlog

from caliper.core.subprocess_runner import SubprocessToolRunner
from caliper.core.tool_runner import ToolInvocation, ToolRunnerPort

logger = structlog.get_logger(__name__)

_QUICK_TIMEOUT = 30
_INSTALL_TIMEOUT = 600  # a clean build + install can take a couple of minutes
_INSTALL_SCRIPT = Path("scripts") / "install-local.sh"


class ReinstallError(Exception):
    """The repo could not be resolved/validated, or the reinstall step failed."""


def _run(
    runner: ToolRunnerPort,
    args: list[str],
    cwd: Path,
    *,
    timeout: int,
    what: str,
) -> str:
    """Run one tool invocation; fail-closed (raise) on any non-zero/timeout/missing."""
    result = runner.run(ToolInvocation(cmd=args, cwd=str(cwd), timeout=timeout))
    if result.not_installed:
        raise ReinstallError(f"{args[0]} is not installed — `caliper reinstall` needs git and bash")
    if result.timed_out:
        raise ReinstallError(f"timed out after {timeout}s while trying to {what}")
    if result.exit_code != 0:
        detail = (result.stderr or result.stdout).strip()[:400]
        raise ReinstallError(f"failed to {what} (exit {result.exit_code}): {detail}")
    return result.stdout


def validate_caliper_repo(repo_root: Path) -> Path:
    """Confirm *repo_root* is the caliper checkout; return the install script path.

    Pure (filesystem reads only): guards against running the reinstall from the
    wrong directory, which would otherwise rebuild some unrelated project.
    """
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.is_file():
        raise ReinstallError(f"{repo_root} is not a caliper checkout (no pyproject.toml)")
    text = pyproject.read_text(encoding="utf-8")
    if 'name = "caliper"' not in text:
        raise ReinstallError(f"{repo_root}/pyproject.toml is not the caliper project")
    script = repo_root / _INSTALL_SCRIPT
    if not script.is_file():
        raise ReinstallError(f"missing {_INSTALL_SCRIPT} in {repo_root}")
    return script


def _resolve_repo_root(runner: ToolRunnerPort, start: Path, override: str | None) -> Path:
    """Repo root from --repo if given, else the git toplevel of *start*."""
    if override:
        return Path(override).resolve()
    out = _run(
        runner,
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        start,
        timeout=_QUICK_TIMEOUT,
        what="find the repo root (run from inside the caliper checkout, or pass --repo)",
    )
    return Path(out.strip()).resolve()


def reinstall(
    repo: str | None,
    *,
    runner: ToolRunnerPort | None = None,
    cwd: Path | None = None,
) -> str:
    """Resolve + validate the checkout, then run the local install script."""
    runner = runner or SubprocessToolRunner()
    start = (cwd or Path.cwd()).resolve()
    repo_root = _resolve_repo_root(runner, start, repo)
    script = validate_caliper_repo(repo_root)
    logger.info("caliper_reinstall", repo_root=str(repo_root), script=str(script))
    return _run(
        runner,
        ["bash", str(script)],
        repo_root,
        timeout=_INSTALL_TIMEOUT,
        what="rebuild + reinstall caliper from local source",
    )


@click.command(name="reinstall")
@click.option(
    "--repo",
    "repo",
    type=click.Path(),
    default=None,
    help="Caliper checkout to rebuild from (default: the git repo of the current directory).",
)
def reinstall_cmd(repo: str | None) -> None:
    """Rebuild + reinstall caliper from local source with a fresh build id (dev)."""
    try:
        output = reinstall(repo)
    except ReinstallError as exc:
        raise click.ClickException(str(exc)) from exc
    # The script echoes the dev version it installed; surface its tail to the user.
    tail = "\n".join(line for line in output.strip().splitlines() if line.strip())[-2000:]
    if tail:
        click.echo(tail)
