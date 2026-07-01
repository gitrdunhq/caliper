"""SemgrepPlugin.run() fix_suggestion extraction (#276).
# tested-by: tests/unit/plugins/test_semgrep_plugin.py

Opengrep/semgrep results may carry a native autofix in
``extra.fix``, or a custom rule-YAML convention in
``extra.metadata.fix_suggestion``. Both must survive into the finding dict
(and, once normalized, into ``PluginFinding.fix_suggestion``) so
``core/concern_remediate.py`` can act on a real remediation instead of a
test-fixture-only value.
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import normalize_finding
from caliper.core.registries import RULE_RUNNERS
from caliper.plugins.semgrep import SemgrepPlugin


class _FakeRunner:
    def __init__(self, data: dict) -> None:
        self._data = data

    def run(self, *args, **kwargs) -> dict:
        return self._data


def _install_fake_runner(monkeypatch, data: dict) -> None:
    monkeypatch.setattr(RULE_RUNNERS, "create", lambda name: _FakeRunner(data))


def _result(extra: dict, path: Path) -> dict:
    return {
        "status": "ok",
        "results": [
            {
                "check_id": "rule.finding",
                "path": str(path),
                "start": {"line": 5},
                "end": {"line": 5},
                "extra": {"severity": "WARNING", "message": "a finding", **extra},
            }
        ],
    }


def test_run_extracts_native_fix_field(monkeypatch, tmp_path: Path) -> None:
    """A native semgrep/opengrep `extra.fix` becomes fix_suggestion."""
    target = tmp_path / "a.py"
    _install_fake_runner(monkeypatch, _result({"fix": "some fix"}, target))

    plugin = SemgrepPlugin()
    result = plugin.run([str(target)], tmp_path)

    assert result.findings[0]["fix_suggestion"] == "some fix"

    normalized = normalize_finding(result.findings[0])
    assert normalized.fix_suggestion == "some fix"


def test_run_extracts_metadata_fix_suggestion_when_no_native_fix(
    monkeypatch, tmp_path: Path
) -> None:
    """Custom rule-YAML `extra.metadata.fix_suggestion` is used when no native `fix`."""
    target = tmp_path / "a.py"
    _install_fake_runner(
        monkeypatch, _result({"metadata": {"fix_suggestion": "metadata fix"}}, target)
    )

    plugin = SemgrepPlugin()
    result = plugin.run([str(target)], tmp_path)

    assert result.findings[0]["fix_suggestion"] == "metadata fix"


def test_run_prefers_native_fix_over_metadata(monkeypatch, tmp_path: Path) -> None:
    """When both are present, the native `fix` field wins."""
    target = tmp_path / "a.py"
    _install_fake_runner(
        monkeypatch,
        _result({"fix": "native fix", "metadata": {"fix_suggestion": "metadata fix"}}, target),
    )

    plugin = SemgrepPlugin()
    result = plugin.run([str(target)], tmp_path)

    assert result.findings[0]["fix_suggestion"] == "native fix"


def test_run_defaults_fix_suggestion_to_empty_string(monkeypatch, tmp_path: Path) -> None:
    """No fix/metadata.fix_suggestion present -> fix_suggestion is empty, not missing."""
    target = tmp_path / "a.py"
    _install_fake_runner(monkeypatch, _result({}, target))

    plugin = SemgrepPlugin()
    result = plugin.run([str(target)], tmp_path)

    assert result.findings[0]["fix_suggestion"] == ""
