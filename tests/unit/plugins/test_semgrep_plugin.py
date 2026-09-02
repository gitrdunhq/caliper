"""SemgrepPlugin.run() fix_suggestion extraction (#276).
# tested-by: tests/unit/plugins/test_semgrep_plugin.py

Opengrep/semgrep results may carry a native autofix in
``extra.fix``, or a custom rule-YAML convention in
``extra.metadata.fix_suggestion``. Both must survive into the finding dict
(and, once normalized, into ``PluginFinding.fix_suggestion``) so
downstream consumers see a real remediation instead of a test-fixture-only
value.
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.config import CaliperSettings
from caliper.core.plugin import normalize_finding
from caliper.core.port_registries import RULE_RUNNERS
from caliper.plugins.semgrep import SemgrepPlugin


class _FakeRunner:
    def __init__(self, data: dict, captured: dict | None = None) -> None:
        self._data = data
        self._captured = captured

    def run(self, *args, **kwargs) -> dict:
        if self._captured is not None:
            self._captured.update(kwargs)
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


class TestSemgrepPluginTimeout:
    """SemgrepPlugin must honor CaliperSettings.scanner_timeout (#432a)."""

    def test_run_passes_scanner_timeout_from_settings(self, monkeypatch, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        captured: dict = {}
        monkeypatch.setattr(
            RULE_RUNNERS,
            "create",
            lambda name: _FakeRunner(_result({}, target), captured),
        )

        plugin = SemgrepPlugin(settings=CaliperSettings(scanner_timeout=5))
        plugin.run([str(target)], tmp_path)

        assert captured["timeout"] == 5

    def test_run_defaults_to_120_without_settings(self, monkeypatch, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        captured: dict = {}
        monkeypatch.setattr(
            RULE_RUNNERS,
            "create",
            lambda name: _FakeRunner(_result({}, target), captured),
        )

        plugin = SemgrepPlugin()
        plugin.run([str(target)], tmp_path)

        assert captured["timeout"] == 120


def test_run_passes_pinned_rule_dirs_from_settings(monkeypatch, tmp_path: Path) -> None:
    """The snapshot and org-rules dirs come from CaliperSettings, never a registry."""
    captured: dict = {}
    monkeypatch.setattr(RULE_RUNNERS, "create", lambda name: _FakeRunner({"results": []}, captured))
    settings = CaliperSettings(
        semgrep_rules_dir="/opt/caliper/semgrep-rules",
        semgrep_org_rules_dir="/opt/caliper/policies/semgrep",
    )
    SemgrepPlugin(settings).run([str(tmp_path / "a.py")], tmp_path)

    assert captured["rules_dir"] == "/opt/caliper/semgrep-rules"
    assert captured["org_rules_dir"] == "/opt/caliper/policies/semgrep"


def test_org_rules_dir_derived_from_opa_policy_path(monkeypatch, tmp_path: Path) -> None:
    """Unset org dir falls back to <policies dir>/semgrep next to the OPA policy."""
    captured: dict = {}
    monkeypatch.setattr(RULE_RUNNERS, "create", lambda name: _FakeRunner({"results": []}, captured))
    policies = tmp_path / "policies"
    (policies / "semgrep").mkdir(parents=True)
    settings = CaliperSettings(opa_policy_path=str(policies / "policy.rego"))
    SemgrepPlugin(settings).run([str(tmp_path / "a.py")], tmp_path)

    assert captured["org_rules_dir"] == str(policies / "semgrep")
    assert captured["rules_dir"] is None


def test_rule_ids_drop_configured_dir_prefixes(monkeypatch, tmp_path: Path) -> None:
    """opengrep prefixes local rule ids with their dotted path; strip the configured dirs' prefixes."""
    target = tmp_path / "a.py"
    data = {
        "status": "ok",
        "results": [
            {
                "check_id": "opt.caliper.semgrep-rules.python.lang.security.audit.subprocess-shell-true",
                "path": str(target),
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "WARNING", "message": "m"},
            },
            {
                "check_id": "opt.caliper.policies.semgrep.org.kubernetes.no-latest-tag",
                "path": str(target),
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {"severity": "WARNING", "message": "m"},
            },
            {
                "check_id": "policies.semgrep.first-test-no-assert",
                "path": str(target),
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {"severity": "INFO", "message": "m"},
            },
        ],
    }
    _install_fake_runner(monkeypatch, data)
    settings = CaliperSettings(
        semgrep_rules_dir="/opt/caliper/semgrep-rules",
        semgrep_org_rules_dir="/opt/caliper/policies/semgrep",
    )
    result = SemgrepPlugin(settings).run([str(target)], tmp_path)
    ids = [f["rule_id"] for f in result.findings]
    assert ids == [
        "python.lang.security.audit.subprocess-shell-true",
        "org.kubernetes.no-latest-tag",
        "policies.semgrep.first-test-no-assert",  # target-local rules keep their prefix
    ]


def test_run_passes_community_rules_dir_from_settings(monkeypatch, tmp_path: Path) -> None:
    """The baked eedom-community-rules snapshot is a third rule source, set by the image env."""
    captured: dict = {}
    monkeypatch.setattr(RULE_RUNNERS, "create", lambda name: _FakeRunner({"results": []}, captured))
    settings = CaliperSettings(
        semgrep_rules_dir="/opt/caliper/semgrep-rules",
        semgrep_org_rules_dir="/opt/caliper/policies/semgrep",
        semgrep_community_rules_dir="/opt/caliper/community-rules",
    )
    SemgrepPlugin(settings).run([str(tmp_path / "a.py")], tmp_path)

    assert captured["community_rules_dir"] == "/opt/caliper/community-rules"


def test_community_rules_dir_unset_by_default(monkeypatch, tmp_path: Path) -> None:
    """No snapshot configured -> None reaches the runner (fail-open, nothing extra loaded)."""
    captured: dict = {}
    monkeypatch.setattr(RULE_RUNNERS, "create", lambda name: _FakeRunner({"results": []}, captured))
    SemgrepPlugin(CaliperSettings()).run([str(tmp_path / "a.py")], tmp_path)

    assert captured["community_rules_dir"] is None


def test_community_rule_ids_drop_snapshot_prefix(monkeypatch, tmp_path: Path) -> None:
    """A community rule id comes back as its Kirby rule id, not the dotted snapshot path."""
    target = tmp_path / "a.ts"
    data = {
        "status": "ok",
        "results": [
            {
                "check_id": (
                    "opt.caliper.community-rules.rules.infrastructure.semgrep."
                    "cdk-custom-resource-oncreate-without-onupdate"
                ),
                "path": str(target),
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "ERROR", "message": "m"},
            },
        ],
    }
    _install_fake_runner(monkeypatch, data)
    settings = CaliperSettings(
        semgrep_rules_dir="/opt/caliper/semgrep-rules",
        semgrep_org_rules_dir="/opt/caliper/policies/semgrep",
        semgrep_community_rules_dir="/opt/caliper/community-rules",
    )
    result = SemgrepPlugin(settings).run([str(target)], tmp_path)
    assert [f["rule_id"] for f in result.findings] == [
        "rules.infrastructure.semgrep.cdk-custom-resource-oncreate-without-onupdate"
    ]
