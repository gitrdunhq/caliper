# tested-by: self (e2e)
"""E2E: every org semgrep rule must parse (regression guard for the release gate).

A single malformed rule makes opengrep abort with a parse error, which the semgrep
plugin surfaces as a degraded-scanner error → an ``caliper-plugin-error`` SARIF result →
counted as a *crashed* plugin by the nightly release gate (``release-candidate.yml``),
blocking the release. This caught two such rules (the Terraform ``no-unencrypted-s3``
``resource "..." ...`` pattern and the Python ``def test_$NAME`` prefix-metavariable);
this test fails fast if any new rule reintroduces a parse error.

Runs only in the e2e container (CALIPER_E2E=1) and only when the opengrep binary is present.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.e2e.conftest import E2E_ENABLED

pytestmark = pytest.mark.skipif(not E2E_ENABLED, reason="E2E tests require CALIPER_E2E=1")

_RULES_DIR = Path(__file__).resolve().parents[2] / "policies" / "semgrep"


def test_all_org_semgrep_rules_parse(tmp_path: Path) -> None:
    """opengrep loads every policies/semgrep rule with zero parse errors."""
    opengrep = shutil.which("opengrep")
    if opengrep is None:
        pytest.skip("opengrep binary not installed")

    # A trivial target across a few languages — rule *loading* is what we assert,
    # so the file contents don't matter, only that opengrep parses the rule set.
    (tmp_path / "s.py").write_text("x = 1\n")
    (tmp_path / "m.tf").write_text('resource "aws_s3_bucket" "b" {}\n')

    proc = subprocess.run(
        [opengrep, "--config", str(_RULES_DIR), "--json", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    data = json.loads(proc.stdout)
    parse_errors = [
        e.get("message", "")
        for e in data.get("errors", [])
        if e.get("level") == "error"
        and ("Parse_error" in e.get("message", "") or "Invalid pattern" in e.get("message", ""))
    ]
    assert not parse_errors, "semgrep rule parse errors:\n" + "\n".join(parse_errors)
