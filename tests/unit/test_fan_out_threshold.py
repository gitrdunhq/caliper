"""Tests for configurable fan-out threshold.
# tested-by: tests/unit/test_fan_out_threshold.py
"""

from __future__ import annotations

from caliper.core.repo_config import RepoConfig


class TestFanOutThresholdConfig:
    def test_default_thresholds_empty(self) -> None:
        config = RepoConfig()
        assert config.thresholds == {}

    def test_blast_radius_fan_out_limit_from_yaml(self) -> None:
        config = RepoConfig(thresholds={"blast-radius": {"fan_out_limit": 15}})
        limit = config.thresholds["blast-radius"]["fan_out_limit"]
        assert limit == 15


class TestFanOutQueryParameterization:
    def test_checks_yaml_uses_fan_out_limit_placeholder(self) -> None:
        from pathlib import Path

        checks_path = (
            Path(__file__).parent.parent.parent
            / "src"
            / "caliper"
            / "plugins"
            / "_runners"
            / "checks.yaml"
        )
        content = checks_path.read_text()
        assert "{fan_out_limit}" in content
