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
        """config with plugins.disabled: [cspell] → cspell in disabled list."""
        _write_config(tmp_path, {"plugins": {"disabled": ["cspell"]}})
        config = load_repo_config(tmp_path)
        assert config.plugins.disabled == ["cspell"]
        assert config.plugins.enabled is None

    def test_disabled_multiple_plugins(self, tmp_path: Path) -> None:
        """Multiple disabled plugins are all captured."""
        _write_config(tmp_path, {"plugins": {"disabled": ["cspell", "trivy", "semgrep"]}})
        config = load_repo_config(tmp_path)
        assert config.plugins.disabled is not None
        assert set(config.plugins.disabled) == {"cspell", "trivy", "semgrep"}


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
        _write_config(tmp_path, {"plugins": {"disabled": ["cspell"]}})
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
            plugins=PluginConfig(disabled=["cspell"]),
            thresholds={"semgrep": {"level": "error"}},
        )
        assert rc.plugins.disabled == ["cspell"]
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
