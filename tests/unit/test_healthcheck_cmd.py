"""`caliper healthcheck` exit status: only default-on scanners can fail it.
# tested-by: tests/unit/test_healthcheck_cmd.py

The image's HEALTHCHECK runs this command. scancode is opt-in and swiftlint
ships amd64-only, so on an arm64 host both are absent by design; counting
them as MISSING marked every arm64 container permanently unhealthy.
"""

from __future__ import annotations

from click.testing import CliRunner

from caliper.cli import inspect_cmds
from caliper.cli.inspect_cmds import HEALTHCHECK_OPTIONAL, healthcheck

_PRESENT = {
    "syft",
    "trivy",
    "osv-scanner",
    "opa",
    "gitleaks",
    "kube-linter",
    "ls-lint",
    "jq",
    "opengrep",
    "pmd",
    "lizard",
    "pyrefly",
    "node",
}


def _which(present: set[str]):
    return lambda name: f"/usr/local/bin/{name}" if name in present else None


def test_optional_scanners_missing_is_healthy(monkeypatch) -> None:
    monkeypatch.setattr(inspect_cmds.shutil, "which", _which(_PRESENT))
    result = CliRunner().invoke(healthcheck)
    assert result.exit_code == 0, result.output
    assert "optional" in result.output
    assert "MISSING" not in result.output
    assert "scancode" in result.output and "swiftlint" in result.output


def test_default_scanner_missing_is_unhealthy(monkeypatch) -> None:
    monkeypatch.setattr(inspect_cmds.shutil, "which", _which(_PRESENT - {"trivy"}))
    result = CliRunner().invoke(healthcheck)
    assert result.exit_code == 1
    assert "MISSING  trivy" in result.output
    assert "caliper install-scanners" in result.output


def test_optional_set_is_exactly_opt_in_plus_platform_limited() -> None:
    assert frozenset({"scancode", "swiftlint"}) == HEALTHCHECK_OPTIONAL
