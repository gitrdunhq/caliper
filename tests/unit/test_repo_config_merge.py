"""Tests for load_merged_config — root + per-package config merging.
# tested-by: tests/unit/test_repo_config_merge.py
"""

from __future__ import annotations

from pathlib import Path

import yaml

from caliper.core.repo_config import (
    RepoConfig,
    SemgrepConfig,
    load_merged_config,
)

# ── Helpers ──


def _write_config(directory: Path, content: dict) -> None:
    cfg = directory / ".caliper.yaml"
    cfg.write_text(yaml.dump(content))


# ── TestLoadMergedConfig ──


class TestLoadMergedConfig:
    def test_no_package_root_returns_root_config(self, tmp_path: Path) -> None:
        """When package_root=None, returns the root config unchanged."""
        _write_config(tmp_path, {"plugins": {"disabled": ["trivy"]}})

        result = load_merged_config(tmp_path, package_root=None)

        assert result.plugins.disabled == ["trivy"]
        assert result.plugins.enabled is None

    def test_package_root_equals_repo_root_returns_root_config(self, tmp_path: Path) -> None:
        """When package_root == repo_path, no merge — returns root config as-is."""
        _write_config(tmp_path, {"plugins": {"disabled": ["typos"]}})

        result = load_merged_config(tmp_path, package_root=tmp_path)

        assert result.plugins.disabled == ["typos"]

    def test_no_package_config_file_falls_back_to_root(self, tmp_path: Path) -> None:
        """When the package directory has no .caliper.yaml, returns root config."""
        _write_config(tmp_path, {"plugins": {"disabled": ["semgrep"]}})
        pkg_dir = tmp_path / "packages" / "web"
        pkg_dir.mkdir(parents=True)
        # Intentionally no config file in pkg_dir

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.plugins.disabled == ["semgrep"]

    def test_package_disabled_overrides_root(self, tmp_path: Path) -> None:
        """Package-level disabled list takes precedence over root disabled list."""
        _write_config(tmp_path, {"plugins": {"disabled": ["trivy"]}})
        pkg_dir = tmp_path / "packages" / "api"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"plugins": {"disabled": ["osv-scanner"]}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.plugins.disabled == ["osv-scanner"]

    def test_package_enabled_overrides_root(self, tmp_path: Path) -> None:
        """Package-level enabled list takes precedence over root enabled list."""
        _write_config(tmp_path, {"plugins": {"enabled": ["semgrep", "trivy"]}})
        pkg_dir = tmp_path / "packages" / "frontend"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"plugins": {"enabled": ["semgrep"]}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.plugins.enabled == ["semgrep"]

    def test_package_thresholds_override_root_on_conflict(self, tmp_path: Path) -> None:
        """When both root and package define the same threshold key, package wins."""
        _write_config(
            tmp_path,
            {"thresholds": {"semgrep": {"max_findings": 10}, "trivy": {"severity": "high"}}},
        )
        pkg_dir = tmp_path / "packages" / "service"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"thresholds": {"semgrep": {"max_findings": 0}}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.thresholds["semgrep"] == {"max_findings": 0}
        # trivy threshold from root is preserved
        assert result.thresholds["trivy"] == {"severity": "high"}

    def test_root_thresholds_preserved_when_not_in_package(self, tmp_path: Path) -> None:
        """Root thresholds not mentioned in package config are kept in the merge."""
        _write_config(
            tmp_path,
            {"thresholds": {"trivy": {"severity": "critical"}, "typos": {"words": 5}}},
        )
        pkg_dir = tmp_path / "libs" / "core"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"thresholds": {"trivy": {"severity": "high"}}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.thresholds["trivy"] == {"severity": "high"}
        assert result.thresholds["typos"] == {"words": 5}

    def test_root_has_no_config_package_has_values(self, tmp_path: Path) -> None:
        """When root has no config file and package does, package config is used."""
        pkg_dir = tmp_path / "packages" / "app"
        pkg_dir.mkdir(parents=True)
        _write_config(
            pkg_dir,
            {
                "plugins": {"disabled": ["osv-scanner"]},
                "thresholds": {"trivy": {"severity": "medium"}},
            },
        )

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.plugins.disabled == ["osv-scanner"]
        assert result.thresholds["trivy"] == {"severity": "medium"}

    def test_root_disabled_used_when_package_has_no_disabled(self, tmp_path: Path) -> None:
        """When package config exists but has no disabled list, root disabled is kept."""
        _write_config(tmp_path, {"plugins": {"disabled": ["typos"]}})
        pkg_dir = tmp_path / "packages" / "lib"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"thresholds": {"semgrep": {"max_findings": 5}}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.plugins.disabled == ["typos"]

    def test_returns_repo_config_instance(self, tmp_path: Path) -> None:
        """load_merged_config always returns a RepoConfig instance."""
        result = load_merged_config(tmp_path, package_root=None)
        assert isinstance(result, RepoConfig)

    def test_both_none_returns_defaults(self, tmp_path: Path) -> None:
        """No root config file and no package_root → returns default RepoConfig."""
        result = load_merged_config(tmp_path)
        assert result.plugins.disabled is None
        assert result.plugins.enabled is None
        assert result.thresholds == {}


# ---------------------------------------------------------------------------
# Regression P05-1 (#262) — telemetry must survive a package-level merge
# ---------------------------------------------------------------------------


class TestLoadMergedConfigTelemetryRegression:
    """Regression suite for P05-1 / #262: telemetry was silently dropped."""

    def test_root_telemetry_preserved_when_package_omits_it(self, tmp_path: Path) -> None:
        """Root telemetry (enabled + endpoint) must survive when the package
        config has no telemetry section (the original bug: P05-1 / #262)."""
        custom_endpoint = "https://telemetry.regression-test.example.com/v1/events"
        _write_config(
            tmp_path,
            {
                "telemetry": {"enabled": True, "endpoint": custom_endpoint},
                "plugins": {"disabled": ["trivy"]},
            },
        )
        pkg_dir = tmp_path / "packages" / "svc"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"plugins": {"disabled": ["typos"]}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert (
            result.telemetry.enabled is True
        ), "P05-1 regression: telemetry.enabled dropped to False during package merge"
        assert (
            result.telemetry.endpoint == custom_endpoint
        ), f"P05-1 regression: telemetry.endpoint reverted to default; got {result.telemetry.endpoint!r}"

    def test_package_telemetry_takes_precedence_over_root(self, tmp_path: Path) -> None:
        """Package-level telemetry overrides root when explicitly set."""
        root_endpoint = "https://root.telemetry.example.com/v1"
        pkg_endpoint = "https://pkg.telemetry.example.com/v1"
        _write_config(
            tmp_path,
            {"telemetry": {"enabled": True, "endpoint": root_endpoint}},
        )
        pkg_dir = tmp_path / "services" / "auth"
        pkg_dir.mkdir(parents=True)
        _write_config(
            pkg_dir,
            {"telemetry": {"enabled": False, "endpoint": pkg_endpoint}},
        )

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.telemetry.enabled is False
        assert result.telemetry.endpoint == pkg_endpoint

    def test_root_telemetry_preserved_alongside_threshold_merge(self, tmp_path: Path) -> None:
        """Telemetry survives when the package config only overrides thresholds."""
        custom_endpoint = "https://override-check.example.com/v1/events"
        _write_config(
            tmp_path,
            {
                "telemetry": {"enabled": True, "endpoint": custom_endpoint},
                "thresholds": {"trivy": {"severity": "high"}},
            },
        )
        pkg_dir = tmp_path / "libs" / "shared"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"thresholds": {"semgrep": {"max_findings": 5}}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.telemetry.enabled is True
        assert result.telemetry.endpoint == custom_endpoint
        # Thresholds are still merged correctly
        assert result.thresholds["trivy"] == {"severity": "high"}
        assert result.thresholds["semgrep"] == {"max_findings": 5}


# ---------------------------------------------------------------------------
# Regression P05-6 — plugins.semgrep sub-config must survive a package merge
# ---------------------------------------------------------------------------


class TestLoadMergedConfigSemgrepRegression:
    """Regression suite for P05-6: plugins.semgrep was reset to defaults."""

    def test_root_semgrep_config_preserved_when_package_omits_it(self, tmp_path: Path) -> None:
        """Root plugins.semgrep (extra_config_dirs + exclude_rules) must survive
        when the package config has no plugins.semgrep section (P05-6)."""
        _write_config(
            tmp_path,
            {
                "plugins": {
                    "disabled": ["trivy"],
                    "semgrep": {
                        "extra_config_dirs": ["/shared/rules"],
                        "exclude_rules": ["python.flask.security.injection"],
                    },
                }
            },
        )
        pkg_dir = tmp_path / "services" / "web"
        pkg_dir.mkdir(parents=True)
        # Package config has NO semgrep section — root semgrep config must survive.
        _write_config(pkg_dir, {"plugins": {"disabled": ["typos"]}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.plugins.semgrep.extra_config_dirs == [
            "/shared/rules"
        ], "P05-6 regression: plugins.semgrep.extra_config_dirs reset to default during merge"
        assert result.plugins.semgrep.exclude_rules == [
            "python.flask.security.injection"
        ], "P05-6 regression: plugins.semgrep.exclude_rules reset to default during merge"

    def test_package_semgrep_config_overrides_root(self, tmp_path: Path) -> None:
        """Package-level plugins.semgrep takes precedence when explicitly set."""
        _write_config(
            tmp_path,
            {
                "plugins": {
                    "semgrep": {
                        "extra_config_dirs": ["/root/rules"],
                        "exclude_rules": ["root.rule"],
                    }
                }
            },
        )
        pkg_dir = tmp_path / "services" / "api"
        pkg_dir.mkdir(parents=True)
        _write_config(
            pkg_dir,
            {
                "plugins": {
                    "semgrep": {
                        "extra_config_dirs": ["/pkg/rules"],
                        "exclude_rules": ["pkg.rule"],
                    }
                }
            },
        )

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.plugins.semgrep == SemgrepConfig(
            extra_config_dirs=["/pkg/rules"],
            exclude_rules=["pkg.rule"],
        )

    def test_semgrep_and_telemetry_both_survive_merge(self, tmp_path: Path) -> None:
        """Both telemetry and semgrep sub-configs survive together in a single merge."""
        _write_config(
            tmp_path,
            {
                "telemetry": {
                    "enabled": True,
                    "endpoint": "https://t.example.com/v1",
                },
                "plugins": {
                    "semgrep": {
                        "extra_config_dirs": ["/shared/semgrep"],
                        "exclude_rules": ["test.rule.one"],
                    }
                },
            },
        )
        pkg_dir = tmp_path / "packages" / "core"
        pkg_dir.mkdir(parents=True)
        _write_config(pkg_dir, {"thresholds": {"semgrep": {"max_findings": 3}}})

        result = load_merged_config(tmp_path, package_root=pkg_dir)

        assert result.telemetry.enabled is True
        assert result.telemetry.endpoint == "https://t.example.com/v1"
        assert result.plugins.semgrep.extra_config_dirs == ["/shared/semgrep"]
        assert result.plugins.semgrep.exclude_rules == ["test.rule.one"]
