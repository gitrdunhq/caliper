"""Tests for scripts/dogfood.sh.

Tests the three critical behaviors:
1. Exits 0 (CLEAR) when SARIF contains no error-level findings.
2. Exits 1 (BLOCKED) when SARIF contains one or more error-level findings.
3. Creates timestamped report + SARIF files and latest symlinks on CLEAR.

The script is exercised via subprocess with:
- A mock `uv` binary injected at the front of PATH.
- REPORT_DIR overridden to a tmp directory.
- REPO_ROOT overridden so git rev-parse is not needed.
"""

# tested-by: tests/unit/test_dogfood_script.py

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).parents[2] / "scripts" / "dogfood.sh"

_SARIF_CLEAR = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "caliper", "rules": []}},
                "results": [
                    {"ruleId": "DEP001", "level": "warning", "message": {"text": "medium finding"}},
                    {"ruleId": "DEP002", "level": "note", "message": {"text": "low finding"}},
                ],
            }
        ],
    }
)

_SARIF_BLOCKED = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "caliper", "rules": []}},
                "results": [
                    {"ruleId": "DEP001", "level": "error", "message": {"text": "critical finding"}},
                    {"ruleId": "DEP002", "level": "warning", "message": {"text": "medium finding"}},
                ],
            }
        ],
    }
)


def _mock_uv(tmp_path: Path, sarif_content: str) -> Path:
    """Write a mock `uv` binary to tmp_path that mimics `uv run caliper review`.

    When called with `--format sarif --output <file>`, writes sarif_content to that file.
    Otherwise writes a minimal markdown stub to `--output <file>` if provided.
    Returns the directory containing the mock binary.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    mock = bin_dir / "uv"
    mock.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import sys, json
            args = sys.argv[1:]
            # Parse --output value
            output_path = None
            for i, a in enumerate(args):
                if a == '--output' and i + 1 < len(args):
                    output_path = args[i + 1]
            is_sarif = '--format' in args and args[args.index('--format') + 1] == 'sarif'
            if output_path:
                with open(output_path, 'w') as fh:
                    if is_sarif:
                        fh.write({repr(sarif_content)})
                    else:
                        fh.write('## Caliper Review\\n\\nNo findings.\\n')
                if is_sarif:
                    print(f'SARIF written to {{output_path}}')
                else:
                    print(f'Review written to {{output_path}}')
            sys.exit(0)
            """))
    mock.chmod(0o755)
    return bin_dir


def _run_script(tmp_path: Path, sarif_content: str) -> subprocess.CompletedProcess:
    """Run dogfood.sh with a mock uv and isolated REPORT_DIR."""
    bin_dir = _mock_uv(tmp_path, sarif_content)
    report_dir = tmp_path / "dogfood"
    report_dir.mkdir()
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        "REPORT_DIR": str(report_dir),
        "REPO_ROOT": str(tmp_path),
    }
    return subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_script_exists():
    """The script file must be present and executable."""
    assert SCRIPT.exists(), f"dogfood.sh not found at {SCRIPT}"
    assert os.access(SCRIPT, os.X_OK), "dogfood.sh is not executable"


def test_exits_zero_when_no_error_findings(tmp_path):
    """Script exits 0 and prints CLEAR when SARIF has no error-level results."""
    result = _run_script(tmp_path, _SARIF_CLEAR)
    assert (
        result.returncode == 0
    ), f"Expected exit 0, got {result.returncode}\n{result.stdout}\n{result.stderr}"
    assert "CLEAR" in result.stdout


def test_exits_one_when_error_findings_exist(tmp_path):
    """Script exits 1 and prints BLOCKED when SARIF has error-level results."""
    result = _run_script(tmp_path, _SARIF_BLOCKED)
    assert (
        result.returncode == 1
    ), f"Expected exit 1, got {result.returncode}\n{result.stdout}\n{result.stderr}"
    assert "BLOCKED" in result.stdout


def test_blocked_message_includes_count(tmp_path):
    """BLOCKED output includes the number of error-level findings."""
    result = _run_script(tmp_path, _SARIF_BLOCKED)
    assert "1" in result.stdout, f"Expected count in output:\n{result.stdout}"


def test_creates_timestamped_report_file(tmp_path):
    """A timestamped markdown report is written to REPORT_DIR."""
    _run_script(tmp_path, _SARIF_CLEAR)
    report_dir = tmp_path / "dogfood"
    md_files = list(report_dir.glob("dogfood-report-*.md"))
    assert md_files, f"No timestamped .md report found in {report_dir}"


def test_creates_timestamped_sarif_file(tmp_path):
    """A timestamped SARIF file is written to REPORT_DIR."""
    _run_script(tmp_path, _SARIF_CLEAR)
    report_dir = tmp_path / "dogfood"
    sarif_files = list(report_dir.glob("dogfood-*.sarif"))
    assert sarif_files, f"No timestamped .sarif file found in {report_dir}"


def test_creates_latest_symlinks_on_clear(tmp_path):
    """Latest symlinks are created when the run is CLEAR."""
    _run_script(tmp_path, _SARIF_CLEAR)
    report_dir = tmp_path / "dogfood"
    assert (report_dir / "dogfood-report-latest.md").is_symlink()
    assert (report_dir / "dogfood-latest.sarif").is_symlink()


def test_no_latest_symlinks_on_blocked(tmp_path):
    """Latest symlinks are NOT created when the run is BLOCKED (exits before symlink step)."""
    _run_script(tmp_path, _SARIF_BLOCKED)
    report_dir = tmp_path / "dogfood"
    assert not (report_dir / "dogfood-report-latest.md").exists()
    assert not (report_dir / "dogfood-latest.sarif").exists()
