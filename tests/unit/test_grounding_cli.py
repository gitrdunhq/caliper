# tested-by: tests/unit/test_grounding_cli.py
"""CLI tests for the gated `ground` command.

DPS-12 domains:
  Integrity (SAFETY): the command runs only when EEDOM_GROUNDING_ENABLED is set.
  Availability / fail-open (LIVENESS): with the flag set, a real source file
    produces a bundle and a zero exit.
"""

from __future__ import annotations

import json
import os

from click.testing import CliRunner

os.environ.setdefault("EEDOM_DB_DSN", "postgresql://t:t@localhost/t")
os.environ.setdefault("EEDOM_ALLOW_GLOBAL", "1")

from eedom.cli.main import cli  # noqa: E402


def test_gated_off_prints_message_and_exits_zero(monkeypatch) -> None:
    monkeypatch.delenv("EEDOM_GROUNDING_ENABLED", raising=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["ground", "--files", "src/eedom/core/policy.py"])
    assert result.exit_code == 0
    assert "gated off" in result.output


def test_enabled_emits_bundle_to_stdout(monkeypatch) -> None:
    monkeypatch.setenv("EEDOM_GROUNDING_ENABLED", "1")
    monkeypatch.setenv("EEDOM_GROUNDING_PROVIDER", "ctags")
    runner = CliRunner()
    result = runner.invoke(cli, ["ground", "--files", "src/eedom/core/config.py"])
    assert result.exit_code == 0
    bundle = json.loads(result.output)
    assert set(bundle) == {"provider", "root", "fact_sheet", "type_context"}


def test_enabled_writes_out_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("EEDOM_GROUNDING_ENABLED", "1")
    monkeypatch.setenv("EEDOM_GROUNDING_PROVIDER", "ctags")
    out = tmp_path / "bundle.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["ground", "--files", "src/eedom/core/config.py", "--out", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    bundle = json.loads(out.read_text())
    assert "fact_sheet" in bundle
    # Sibling markdown rendering for .json out paths.
    assert (tmp_path / "bundle.md").exists()


def test_files_required(monkeypatch) -> None:
    monkeypatch.setenv("EEDOM_GROUNDING_ENABLED", "1")
    runner = CliRunner()
    result = runner.invoke(cli, ["ground"])
    assert result.exit_code != 0
