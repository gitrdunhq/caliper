"""`caliper init` — write the standard .caliper.yaml.
# tested-by: tests/unit/test_init_cmd.py

The default configuration is the product's standard; `init` makes it visible
so a repo's config is a diff from the default, not a guess (#291).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from caliper.cli.init_cmd import init, render_default_config
from caliper.core.repo_config import RepoConfig, load_repo_config


class TestRenderDefaultConfig:
    def test_is_valid_yaml_that_loads_to_the_defaults(self, tmp_path: Path) -> None:
        text = render_default_config()
        data = yaml.safe_load(text)
        assert isinstance(data, dict)
        (tmp_path / ".caliper.yaml").write_text(text)
        assert load_repo_config(tmp_path) == RepoConfig()

    def test_every_top_level_section_is_present_and_documented(self) -> None:
        text = render_default_config()
        for section in (
            "plugins",
            "thresholds",
            "parting",
            "detectors",
            "baseline",
            "architecture",
        ):
            assert f"\n{section}:" in text or text.startswith(f"{section}:"), section
        # comments explain each section; no bare, unexplained keys at top level
        assert text.count("#") >= 12

    def test_mentions_the_opt_in_plugin_and_the_house_rules_profile(self) -> None:
        text = render_default_config()
        assert "scancode" in text
        assert "house-rules" in text


class TestInitCommand:
    def test_writes_file_in_repo(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(init, ["--repo-path", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / ".caliper.yaml").exists()
        assert ".caliper.yaml" in result.output

    def test_refuses_to_overwrite_without_force(self, tmp_path: Path) -> None:
        (tmp_path / ".caliper.yaml").write_text("plugins:\n  disabled: [cpd]\n")
        result = CliRunner().invoke(init, ["--repo-path", str(tmp_path)])
        assert result.exit_code == 1
        assert (tmp_path / ".caliper.yaml").read_text() == "plugins:\n  disabled: [cpd]\n"
        assert "--force" in result.output

    def test_force_overwrites(self, tmp_path: Path) -> None:
        (tmp_path / ".caliper.yaml").write_text("plugins:\n  disabled: [cpd]\n")
        result = CliRunner().invoke(init, ["--repo-path", str(tmp_path), "--force"])
        assert result.exit_code == 0, result.output
        assert load_repo_config(tmp_path) == RepoConfig()

    def test_print_only(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(init, ["--repo-path", str(tmp_path), "--print"])
        assert result.exit_code == 0
        assert not (tmp_path / ".caliper.yaml").exists()
        assert "plugins:" in result.output


class TestInitDocumentsIgnoreAndSeverityKnobs:
    def test_config_template_includes_commented_ignore_rule_scope_example(self) -> None:
        text = render_default_config()
        # A commented example of the "<glob> !<rule-id-prefix>" .caliperignore
        # rule-scope syntax must be present so a reader discovers the feature
        # without leaving the generated config.
        assert ".caliperignore" in text
        assert "!<rule-id-prefix>" in text

    def test_config_template_includes_commented_semgrep_min_severity_example(self) -> None:
        text = render_default_config()
        # A commented thresholds.semgrep.min_severity example, defaulting to
        # "medium", must be discoverable directly in the generated template.
        assert "thresholds" in text
        assert "min_severity" in text
        assert "medium" in text
