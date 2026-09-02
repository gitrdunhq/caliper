"""Tests for repo-level config loading from .caliper.yaml.
# tested-by: tests/unit/test_repo_config.py
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from caliper.core.repo_config import PluginConfig, RepoConfig, load_repo_config

# ── Helpers ──


def _write_config(tmp_path: Path, content: dict) -> Path:
    cfg = tmp_path / ".caliper.yaml"
    cfg.write_text(yaml.dump(content))
    return tmp_path


# ── Tests: load_repo_config ──


class TestLoadRepoConfigDefaults:
    def test_missing_file_returns_defaults(self, tmp_path: Path) -> None:
        """No config file → returns RepoConfig with all defaults, no error."""
        config = load_repo_config(tmp_path)
        assert isinstance(config, RepoConfig)
        assert config.plugins.disabled is None
        assert config.plugins.enabled is None
        assert config.thresholds == {}

    def test_empty_config_file_returns_defaults(self, tmp_path: Path) -> None:
        """An empty YAML file produces default RepoConfig."""
        cfg = tmp_path / ".caliper.yaml"
        cfg.write_text("")
        config = load_repo_config(tmp_path)
        assert isinstance(config, RepoConfig)
        assert config.plugins.disabled is None
        assert config.plugins.enabled is None
        assert config.thresholds == {}


class TestLoadRepoConfigDisabled:
    def test_disabled_plugins_parsed(self, tmp_path: Path) -> None:
        """config with plugins.disabled: [typos] → typos in disabled list."""
        _write_config(tmp_path, {"plugins": {"disabled": ["typos"]}})
        config = load_repo_config(tmp_path)
        assert config.plugins.disabled == ["typos"]
        assert config.plugins.enabled is None

    def test_disabled_multiple_plugins(self, tmp_path: Path) -> None:
        """Multiple disabled plugins are all captured."""
        _write_config(tmp_path, {"plugins": {"disabled": ["typos", "trivy", "semgrep"]}})
        config = load_repo_config(tmp_path)
        assert config.plugins.disabled is not None
        assert set(config.plugins.disabled) == {"typos", "trivy", "semgrep"}


class TestLoadRepoConfigEnabled:
    def test_enabled_plugins_parsed(self, tmp_path: Path) -> None:
        """config with plugins.enabled: [semgrep, trivy] → only those in enabled."""
        _write_config(tmp_path, {"plugins": {"enabled": ["semgrep", "trivy"]}})
        config = load_repo_config(tmp_path)
        assert config.plugins.enabled == ["semgrep", "trivy"]
        assert config.plugins.disabled is None

    def test_enabled_single_plugin(self, tmp_path: Path) -> None:
        """Single enabled plugin is captured correctly."""
        _write_config(tmp_path, {"plugins": {"enabled": ["osv-scanner"]}})
        config = load_repo_config(tmp_path)
        assert config.plugins.enabled == ["osv-scanner"]


class TestLoadRepoConfigThresholds:
    def test_thresholds_parsed(self, tmp_path: Path) -> None:
        """Thresholds dict is parsed correctly."""
        _write_config(
            tmp_path,
            {"thresholds": {"semgrep": {"max_findings": 10}, "trivy": {"severity": "high"}}},
        )
        config = load_repo_config(tmp_path)
        assert config.thresholds["semgrep"] == {"max_findings": 10}
        assert config.thresholds["trivy"] == {"severity": "high"}

    def test_missing_thresholds_defaults_to_empty_dict(self, tmp_path: Path) -> None:
        """When thresholds key absent, defaults to {}."""
        _write_config(tmp_path, {"plugins": {"disabled": ["typos"]}})
        config = load_repo_config(tmp_path)
        assert config.thresholds == {}


class TestLoadRepoConfigErrors:
    def test_invalid_yaml_raises_value_error(self, tmp_path: Path) -> None:
        """Invalid YAML raises ValueError with a message — never silently passes."""
        cfg = tmp_path / ".caliper.yaml"
        cfg.write_text("plugins: {disabled: [unclosed\n  bad: yaml: here: [")
        with pytest.raises((ValueError, Exception)):
            load_repo_config(tmp_path)

    def test_wrong_type_for_disabled_raises(self, tmp_path: Path) -> None:
        """disabled must be a list — a scalar string raises a validation error."""
        cfg = tmp_path / ".caliper.yaml"
        cfg.write_text("plugins:\n  disabled: not-a-list\n")
        with pytest.raises(Exception):
            load_repo_config(tmp_path)


class TestLoadRepoConfigUnknownPlugins:
    def test_unknown_plugin_name_does_not_crash(self, tmp_path: Path) -> None:
        """Unknown plugin name in disabled list is stored without crashing.

        Validation against the actual plugin registry happens at run time, not at
        config-load time.  The config layer must never crash on unknown names.
        """
        _write_config(tmp_path, {"plugins": {"disabled": ["nonexistent-plugin-xyz"]}})
        config = load_repo_config(tmp_path)
        assert "nonexistent-plugin-xyz" in (config.plugins.disabled or [])


# ── Tests: PluginConfig model ──


class TestPluginConfigModel:
    def test_defaults(self) -> None:
        cfg = PluginConfig()
        assert cfg.enabled is None
        assert cfg.disabled is None

    def test_both_fields_set(self) -> None:
        cfg = PluginConfig(enabled=["a"], disabled=["b"])
        assert cfg.enabled == ["a"]
        assert cfg.disabled == ["b"]


# ── Tests: RepoConfig model ──


class TestRepoConfigModel:
    def test_defaults(self) -> None:
        rc = RepoConfig()
        assert isinstance(rc.plugins, PluginConfig)
        assert rc.thresholds == {}

    def test_custom_values(self) -> None:
        rc = RepoConfig(
            plugins=PluginConfig(disabled=["typos"]),
            thresholds={"semgrep": {"level": "error"}},
        )
        assert rc.plugins.disabled == ["typos"]
        assert rc.thresholds["semgrep"] == {"level": "error"}


class TestSemgrepConfig:
    def test_default_semgrep_config(self) -> None:
        """Default SemgrepConfig has empty lists."""
        rc = RepoConfig()
        assert rc.plugins.semgrep.extra_config_dirs == []
        assert rc.plugins.semgrep.exclude_rules == []

    def test_semgrep_config_from_yaml(self, tmp_path: Path) -> None:
        """Semgrep tuning keys are parsed from .caliper.yaml."""
        _write_config(
            tmp_path,
            {
                "plugins": {
                    "enabled": ["semgrep"],
                    "semgrep": {
                        "extra_config_dirs": ["/opt/rules/community"],
                        "exclude_rules": ["path-traversal", "magic-number"],
                    },
                }
            },
        )
        config = load_repo_config(tmp_path)
        assert config.plugins.semgrep.extra_config_dirs == ["/opt/rules/community"]
        assert "path-traversal" in config.plugins.semgrep.exclude_rules
        assert "magic-number" in config.plugins.semgrep.exclude_rules

    def test_semgrep_config_absent_defaults(self, tmp_path: Path) -> None:
        """Missing semgrep key produces empty defaults, not an error."""
        _write_config(tmp_path, {"plugins": {"enabled": ["semgrep"]}})
        config = load_repo_config(tmp_path)
        assert config.plugins.semgrep.extra_config_dirs == []
        assert config.plugins.semgrep.exclude_rules == []


class TestPartingOverrides:
    """parting.overrides — the reclassification table loaded from .caliper.yaml."""

    def test_overrides_parsed_from_yaml(self, tmp_path: Path) -> None:
        _write_config(
            tmp_path,
            {
                "parting": {
                    "overrides": [
                        {"glob": "src/ui/**", "bucket": "frontend", "note": "the SPA"},
                        {"glob": "src/repo/**", "bucket": "data"},
                    ]
                }
            },
        )
        config = load_repo_config(tmp_path)
        assert len(config.parting.overrides) == 2
        assert config.parting.overrides[0].glob == "src/ui/**"
        assert config.parting.overrides[0].bucket == "frontend"
        assert config.parting.overrides[0].note == "the SPA"

    def test_duplicate_override_glob_raises(self, tmp_path: Path) -> None:
        """Two rules with the same glob are an ambiguous conflict — fail at load."""
        _write_config(
            tmp_path,
            {
                "parting": {
                    "overrides": [
                        {"glob": "src/x/**", "bucket": "frontend"},
                        {"glob": "src/x/**", "bucket": "data"},
                    ]
                }
            },
        )
        with pytest.raises(ValueError, match="duplicate override glob"):
            load_repo_config(tmp_path)

    def test_structural_bucket_override_rejected(self, tmp_path: Path) -> None:
        """An override may not target a structural bucket (delete/move/binary)."""
        _write_config(
            tmp_path,
            {"parting": {"overrides": [{"glob": "src/x/**", "bucket": "delete"}]}},
        )
        with pytest.raises(ValueError):
            load_repo_config(tmp_path)

    def test_unknown_override_bucket_rejected(self, tmp_path: Path) -> None:
        """A bucket outside the ChangeType enum is a load error, not silently dropped."""
        _write_config(
            tmp_path,
            {"parting": {"overrides": [{"glob": "src/x/**", "bucket": "nonsense"}]}},
        )
        with pytest.raises(ValueError):
            load_repo_config(tmp_path)


class TestLoadIsCachedPerRun:
    """Every plugin loads .caliper.yaml; read it once, not once per plugin."""

    def test_second_load_does_not_reread_the_file(self, tmp_path: Path, monkeypatch) -> None:
        from caliper.core import repo_config as rc

        rc.clear_repo_config_cache()
        _write_config(tmp_path, {"plugins": {"disabled": ["ls-lint"]}})
        reads = {"n": 0}
        real = Path.read_text

        def counting(self, *a, **k):
            if self.name == ".caliper.yaml":
                reads["n"] += 1
            return real(self, *a, **k)

        monkeypatch.setattr(Path, "read_text", counting)
        a = rc.load_repo_config(tmp_path)
        b = rc.load_repo_config(tmp_path)
        assert a.plugins.disabled == ["ls-lint"] and b.plugins.disabled == ["ls-lint"]
        assert reads["n"] == 1

    def test_cache_invalidates_when_file_changes(self, tmp_path: Path) -> None:
        import os

        from caliper.core import repo_config as rc

        rc.clear_repo_config_cache()
        _write_config(tmp_path, {"plugins": {"disabled": ["ls-lint"]}})
        assert rc.load_repo_config(tmp_path).plugins.disabled == ["ls-lint"]
        _write_config(tmp_path, {"plugins": {"disabled": ["cpd"]}})
        # ensure a distinct mtime even on coarse filesystems
        os.utime(tmp_path / ".caliper.yaml", ns=(1, 2_000_000_000))
        assert rc.load_repo_config(tmp_path).plugins.disabled == ["cpd"]

    def test_missing_file_is_logged_once_per_path(self, tmp_path: Path, monkeypatch) -> None:
        from caliper.core import repo_config as rc

        rc.clear_repo_config_cache()
        events: list[str] = []

        class _Logger:
            def debug(self, event: str, **kw) -> None:
                events.append(event)

            warning = info = error = debug

        monkeypatch.setattr(rc, "logger", _Logger())
        rc.load_repo_config(tmp_path)
        rc.load_repo_config(tmp_path)
        rc.load_repo_config(tmp_path)
        assert events.count("repo_config.not_found") == 1


# ── Tests: task-006 — semgrep severity floor (thresholds.semgrep.min_severity) ──
#
# DPS-12 domain: Boundedness (INVARIANT) — a below-floor semgrep finding can never
# move the security score / verdict, no matter how many are present.


class TestSemgrepMinSeverityConfig:
    """AC1: repo_config parses thresholds.semgrep.min_severity, default 'medium'."""

    def test_defaults_to_medium_when_absent(self, tmp_path: Path) -> None:
        config = load_repo_config(tmp_path)
        assert config.semgrep_min_severity == "medium"

    def test_defaults_to_medium_when_thresholds_present_but_semgrep_absent(
        self, tmp_path: Path
    ) -> None:
        _write_config(tmp_path, {"thresholds": {"trivy": {"severity": "high"}}})
        config = load_repo_config(tmp_path)
        assert config.semgrep_min_severity == "medium"

    def test_overridable_via_caliper_yaml(self, tmp_path: Path) -> None:
        _write_config(tmp_path, {"thresholds": {"semgrep": {"min_severity": "low"}}})
        config = load_repo_config(tmp_path)
        assert config.semgrep_min_severity == "low"


class TestSemgrepFloorExcludesFromScore:
    """AC2: a below-floor semgrep Finding never moves verdict/score.

    Property: Boundedness — security_score stays pinned at 100.0 for a semgrep
    result containing only low/info findings once the default 'medium' floor
    applies, whereas today (no floor) those findings each subtract weight and
    the score drops below 100.
    """

    def _low_info_semgrep_result(self):
        from caliper.core.plugin import PluginResult

        return PluginResult(
            plugin_name="semgrep",
            category="code",
            findings=[
                {"id": "s1", "severity": "low", "message": "nit", "file": "a.py"},
                {"id": "s2", "severity": "info", "message": "fyi", "file": "b.py"},
            ],
            summary={},
        )

    def test_low_and_info_semgrep_findings_do_not_move_security_score(self) -> None:
        from caliper.core.review_summary import summarize_review

        summary = summarize_review([self._low_info_semgrep_result()], semgrep_min_severity="medium")
        assert summary.security_score == 100.0

    def test_low_and_info_semgrep_findings_do_not_move_verdict_or_blocking_count(
        self,
    ) -> None:
        from caliper.core.review_summary import ReviewVerdict, summarize_review

        summary = summarize_review([self._low_info_semgrep_result()], semgrep_min_severity="medium")
        assert summary.verdict == ReviewVerdict.clear
        assert summary.blocking_count == 0


class TestSemgrepFloorRenderedInNotesSection:
    """AC3: below-floor findings are still returned and rendered, but tucked
    into a collapsed 'notes' section rather than the main findings sections.
    """

    def test_below_floor_finding_appears_in_collapsed_notes_not_main_section(
        self, tmp_path: Path
    ) -> None:
        from caliper.core.plugin import PluginResult
        from caliper.core.renderer import render_comment

        low_result = PluginResult(
            plugin_name="semgrep",
            category="code",
            findings=[
                {
                    "id": "s1",
                    "severity": "low",
                    "message": "below-floor-marker-message",
                    "file": "a.py",
                }
            ],
            summary={},
        )
        output = render_comment(
            [low_result],
            repo="acme/widgets",
            repo_path=str(tmp_path),
            semgrep_min_severity="medium",
        )
        assert "<details>" in output and "notes" in output.lower()
        notes_start = output.lower().index("<details>")
        assert "below-floor-marker-message" in output
        marker_index = output.index("below-floor-marker-message")
        # The finding must live inside/after the collapsed notes block, never
        # ahead of it in a main findings section.
        assert marker_index >= notes_start


class TestSemgrepMinSeverityLowReenablesLowFindings:
    """AC4: thresholds.semgrep.min_severity: 'low' makes 'low' findings count
    toward verdict/scores again.
    """

    def test_low_floor_from_caliper_yaml_restores_low_finding_scoring(self, tmp_path: Path) -> None:
        from caliper.core.plugin import PluginResult
        from caliper.core.review_summary import summarize_review

        _write_config(tmp_path, {"thresholds": {"semgrep": {"min_severity": "low"}}})
        config = load_repo_config(tmp_path)
        assert config.semgrep_min_severity == "low"

        low_result = PluginResult(
            plugin_name="semgrep",
            category="code",
            findings=[{"id": "s1", "severity": "low", "message": "nit", "file": "a.py"}],
            summary={},
        )
        summary = summarize_review([low_result], semgrep_min_severity=config.semgrep_min_severity)
        # weight(low) == 1 -> score must actually drop from the 100.0 ceiling
        # once the floor is lowered to 'low'.
        assert summary.security_score == 99.0
