# tested-by: tests/e2e/test_breakpoints.py
"""E2E test fixtures — container-only, real scanners, deterministic assertions.

Guard: all tests skip unless CALIPER_E2E=1 (set in the e2e container).
Breakpoints: when CALIPER_E2E_BREAKPOINTS=1, intermediate pipeline state is
dumped to tmp_path/breakpoints/ for binary-search debugging.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from caliper.cli.main import cli

FIXTURES_DIR = Path(__file__).parent / "fixtures"

E2E_ENABLED = os.getenv("CALIPER_E2E") == "1"
BREAKPOINTS_ENABLED = os.getenv("CALIPER_E2E_BREAKPOINTS") == "1"

pytestmark = pytest.mark.skipif(
    not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1 (container)"
)


@pytest.fixture()
def fixture_repo(tmp_path: Path, request: pytest.FixtureRequest) -> Path:
    """Copy a named fixture repo to tmp_path and init a git repo.

    Usage: @pytest.mark.parametrize("fixture_repo", ["vuln-repo"], indirect=True)
    Or use the default "vuln-repo" if no parameter is given.
    """
    name = getattr(request, "param", "vuln-repo")
    src = FIXTURES_DIR / name
    dst = tmp_path / name
    shutil.copytree(src, dst)
    subprocess.run(["git", "init", str(dst)], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(dst), "add", "-A"], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(dst), "commit", "-m", "fixture"],
        capture_output=True,
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "test",
            "GIT_COMMITTER_NAME": "test",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    )
    return dst


@pytest.fixture()
def vuln_repo(tmp_path: Path) -> Path:
    """Shorthand for the vuln-repo fixture without parametrize.

    Creates TWO commits: empty initial + all fixture files. This produces
    a diff that includes every file (including requirements.txt, LICENSE, etc.)
    which is needed for scanners that check manifest files.
    """
    src = FIXTURES_DIR / "vuln-repo"
    dst = tmp_path / "vuln-repo"
    git_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test",
        "GIT_COMMITTER_NAME": "test",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    shutil.copytree(src, dst)
    subprocess.run(["git", "init", str(dst)], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(dst), "commit", "--allow-empty", "-m", "init"],
        capture_output=True,
        check=True,
        env=git_env,
    )
    subprocess.run(["git", "-C", str(dst), "add", "-A"], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(dst), "commit", "-m", "add fixtures"],
        capture_output=True,
        check=True,
        env=git_env,
    )
    diff_result = subprocess.run(
        ["git", "-C", str(dst), "diff", "HEAD~1..HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    diff_file = dst / ".diff"
    diff_file.write_text(diff_result.stdout)
    return dst


@pytest.fixture()
def clean_repo(tmp_path: Path) -> Path:
    """The clean-repo fixture — should produce zero findings."""
    src = FIXTURES_DIR / "clean-repo"
    dst = tmp_path / "clean-repo"
    git_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test",
        "GIT_COMMITTER_NAME": "test",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    shutil.copytree(src, dst)
    subprocess.run(["git", "init", str(dst)], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(dst), "commit", "--allow-empty", "-m", "init"],
        capture_output=True,
        check=True,
        env=git_env,
    )
    subprocess.run(["git", "-C", str(dst), "add", "-A"], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(dst), "commit", "-m", "add fixtures"],
        capture_output=True,
        check=True,
        env=git_env,
    )
    diff_result = subprocess.run(
        ["git", "-C", str(dst), "diff", "HEAD~1..HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    diff_file = dst / ".diff"
    diff_file.write_text(diff_result.stdout)
    return dst


def run_review(
    repo_path: Path,
    *,
    scanners: str | None = None,
    run_all: bool = False,
    output_format: str = "json",
    extra_args: list[str] | None = None,
) -> tuple[object, dict | str]:
    """Run `caliper review` and return (CliRunner result, parsed output).

    For json/sarif formats, output is parsed as dict.
    For markdown, output is the raw string.
    """
    runner = CliRunner()
    args = ["review", "--repo-path", str(repo_path), "--format", output_format]
    diff_file = repo_path / ".diff"
    if diff_file.exists():
        args.extend(["--diff", str(diff_file)])
    if scanners:
        args.extend(["--scanners", scanners])
    if run_all:
        args.append("--all")
    if extra_args:
        args.extend(extra_args)

    result = runner.invoke(cli, args)

    if output_format in ("json", "sarif") and result.exit_code == 0 and result.output.strip():
        parsed = _extract_json(result.output)
    else:
        parsed = result.output

    return result, parsed


def _extract_json(text: str) -> dict | list | str:
    """Extract JSON from CLI output that may have structlog lines before it."""
    for i, ch in enumerate(text):
        if ch in ("{", "["):
            try:
                return json.loads(text[i:])
            except json.JSONDecodeError:
                continue
    return text


def get_plugin_findings(parsed: dict | list, plugin_name: str) -> list[dict]:
    """Extract findings for a named plugin from the JSON output.

    Handles both list-of-plugins and dict-of-plugins structures.
    """
    if isinstance(parsed, dict):
        plugins = parsed.get("plugins", [])
    elif isinstance(parsed, list):
        plugins = parsed
    else:
        return []

    if isinstance(plugins, list):
        for p in plugins:
            if isinstance(p, dict) and p.get("name") == plugin_name:
                return p.get("findings", [])
    elif isinstance(plugins, dict):
        plugin_data = plugins.get(plugin_name, {})
        return plugin_data.get("findings", [])
    return []


def get_all_findings(parsed: dict | list) -> list[dict]:
    """Extract all findings from all plugins in the JSON output."""
    findings = []
    if isinstance(parsed, dict):
        plugins = parsed.get("plugins", [])
    elif isinstance(parsed, list):
        plugins = parsed
    else:
        return findings

    if isinstance(plugins, list):
        for p in plugins:
            if isinstance(p, dict):
                findings.extend(p.get("findings", []))
    elif isinstance(plugins, dict):
        for plugin_data in plugins.values():
            if isinstance(plugin_data, dict):
                findings.extend(plugin_data.get("findings", []))
    return findings


def breakpoint_dump(tmp_path: Path, name: str, data: object) -> Path | None:
    """Dump intermediate state for binary-search debugging.

    Only writes when CALIPER_E2E_BREAKPOINTS=1.
    Returns the path written, or None if breakpoints disabled.
    """
    if not BREAKPOINTS_ENABLED:
        return None
    bp_dir = tmp_path / "breakpoints"
    bp_dir.mkdir(exist_ok=True)
    out = bp_dir / f"{name}.json"
    out.write_text(json.dumps(data, indent=2, default=str))
    return out
