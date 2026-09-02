"""Golden-file test for the markdown report renderer (epic-next-10 R1 AC8).
# tested-by: tests/unit/test_renderer_golden.py

A fixed ``list[PluginResult]`` — three plugins that ran with mixed severities,
one that errored, one that was skipped — is rendered once through the only
public entry point, ``caliper.core.renderer.render_comment``, and compared
byte-for-byte against the committed ``tests/fixtures/renderer_golden.md``.

The fixture was hand-reviewed against SPEC R1: the security/quality scores are
consistent with the findings, every path is repo-relative, findings inside a
section run critical → info then by file, the skipped plugin is one summary
line, and below-floor semgrep findings sit in the collapsed notes block.

Regenerate deliberately (never blindly) when the report shape changes:

    uv run python -c "from tests.unit.test_renderer_golden import render_golden; print(render_golden(), end='')"
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core import renderer as renderer_module
from caliper.core.plugin import PluginResult
from caliper.core.renderer import render_comment

GOLDEN_PATH = Path(__file__).parent.parent / "fixtures" / "renderer_golden.md"

# The footer prints the installed caliper version; pin it so a release bump
# never churns the golden file.
_PINNED_VERSION = "0.0.0+golden"


def golden_results() -> list[PluginResult]:
    """The fixed fixture: deliberately out of order so the renderer must sort."""
    return [
        PluginResult(
            plugin_name="semgrep",
            category="code",
            findings=[
                {
                    "rule_id": "python.lang.best-practice.unused-import",
                    "severity": "info",
                    "file": "src/app/util.py",
                    "line": 3,
                    "message": "unused import `os`",
                },
                {
                    "rule_id": "python.security.weak-hash",
                    "severity": "medium",
                    "file": "src/app/auth.py",
                    "line": 15,
                    "message": "MD5 is cryptographically weak",
                },
                {
                    "rule_id": "python.security.sql-injection",
                    "severity": "high",
                    "file": "src/app/db.py",
                    "line": 42,
                    "message": "SQL query built with string formatting",
                    "fix_suggestion": "use a parameterized query",
                },
                {
                    "rule_id": "python.security.subprocess-shell",
                    "severity": "high",
                    "file": "src/app/cli.py",
                    "line": 88,
                    "message": "subprocess called with shell=True",
                },
            ],
            summary={"total": 4},
        ),
        PluginResult(
            plugin_name="trivy",
            category="dependency",
            error="not installed",
        ),
        PluginResult(
            plugin_name="typos",
            summary={"status": "skipped", "reason": "no .typos.toml"},
        ),
        PluginResult(
            plugin_name="detectors",
            category="code",
            findings=[
                {
                    "rule_id": "CAL-004",
                    "severity": "medium",
                    "file": "src/app/models.py",
                    "line": 9,
                    "message": "mutable default argument",
                    "fix_suggestion": "default to None and build the list inside the function",
                },
                {
                    "rule_id": "CAL-001",
                    "severity": "high",
                    "file": "src/app/db.py",
                    "line": 120,
                    "message": "bare except swallows every error",
                },
                {
                    "rule_id": "CAL-009",
                    "severity": "low",
                    "file": "src/app/util.py",
                    "line": 51,
                    "message": "f-string without placeholders",
                },
            ],
            summary={"total": 3},
        ),
        PluginResult(
            plugin_name="osv-scanner",
            category="dependency",
            findings=[
                {
                    "id": "GHSA-xxxx-low1",
                    "severity": "low",
                    "file": "requirements.txt",
                    "line": 12,
                    "package": "leftpad",
                    "version": "1.0.0",
                    "fixed_version": "",
                    "message": "leftpad 1.0.0: minor information disclosure",
                    "url": "https://osv.dev/GHSA-xxxx-low1",
                },
                {
                    "id": "GHSA-xxxx-crit1",
                    "severity": "critical",
                    "file": "requirements.txt",
                    "line": 4,
                    "package": "requests",
                    "version": "2.19.0",
                    "fixed_version": "2.32.0",
                    "message": "requests 2.19.0: remote code execution",
                    "url": "https://osv.dev/GHSA-xxxx-crit1",
                },
            ],
            summary={"total": 2},
        ),
    ]


def render_golden() -> str:
    original = renderer_module._VERSION
    renderer_module._VERSION = _PINNED_VERSION
    try:
        return render_comment(golden_results(), repo="org/repo", pr_num=1, title="golden")
    finally:
        renderer_module._VERSION = original


@pytest.fixture()
def pinned_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(renderer_module, "_VERSION", _PINNED_VERSION)


def test_golden_fixture_is_committed() -> None:
    assert GOLDEN_PATH.is_file(), f"missing golden fixture: {GOLDEN_PATH}"


def test_render_comment_matches_golden_byte_for_byte(pinned_version: None) -> None:
    rendered = render_comment(golden_results(), repo="org/repo", pr_num=1, title="golden")
    expected = GOLDEN_PATH.read_text(encoding="utf-8")
    assert rendered == expected, (
        "rendered report drifted from tests/fixtures/renderer_golden.md; "
        "review the diff and regenerate the fixture deliberately"
    )


def test_render_comment_is_deterministic(pinned_version: None) -> None:
    first = render_comment(golden_results(), repo="org/repo", pr_num=1, title="golden")
    second = render_comment(golden_results(), repo="org/repo", pr_num=1, title="golden")
    assert first == second
