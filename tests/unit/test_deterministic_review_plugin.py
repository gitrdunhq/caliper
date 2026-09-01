"""RED phase for the #457 correction.

DeterministicScanner's own docstring says it is "integrated into the 'review'
command rather than being a separate 'detect' command" (ADR-DET-006) — but
nothing wires it into ``ANALYZERS`` (the registry ``caliper review`` actually
runs). A prior attempt wired it into ``build_scanners()``/``evaluate()``
instead (the dependency-diff/OPA pipeline) — that pipeline never surfaces
findings in ``caliper review`` output, which is why dogfood showed zero
detector findings despite the earlier fix. This locks in the correct wiring.
"""

from __future__ import annotations

from caliper.core.plugin import PluginCategory, PluginResult


class TestDeterministicPluginRegistration:
    def test_registers_with_analyzers_after_load_adapters(self) -> None:
        from caliper.composition.bootstrap import load_adapters
        from caliper.plugins import ANALYZERS

        load_adapters()

        assert "deterministic" in ANALYZERS


class TestDeterministicPluginRun:
    def test_run_surfaces_a_real_detector_finding(self, tmp_path) -> None:
        from caliper.composition.deterministic_plugin import DeterministicPlugin

        src = tmp_path / "bad.py"
        src.write_text(
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception as exc:\n"
            "        print(f'{exc}')\n"
        )

        plugin = DeterministicPlugin()
        assert plugin.category == PluginCategory.code

        result = plugin.run([str(src)], tmp_path)

        assert isinstance(result, PluginResult)
        assert result.error == ""
        assert any(f["rule_id"] == "CAL-002" for f in result.findings), result.findings


class TestDeterministicPluginProfiles:
    """The plugin honours `detectors:` in .caliper.yaml; house rules are opt-in."""

    @staticmethod
    def _repo(tmp_path, yaml_text: str | None):
        # No `# tested-by:` annotation -> CAL-014 (house-rules) fires on any .py file.
        (tmp_path / "mod.py").write_text("def f():\n    return 1\n")
        if yaml_text is not None:
            (tmp_path / ".caliper.yaml").write_text(yaml_text)
        return tmp_path

    def test_default_profile_excludes_house_rules(self, tmp_path) -> None:
        from caliper.composition.deterministic_plugin import DeterministicPlugin

        repo = self._repo(tmp_path, None)
        result = DeterministicPlugin().run([str(repo / "mod.py")], repo)
        assert result.error == ""
        assert not any(f["rule_id"] == "CAL-014" for f in result.findings), result.findings
        assert result.summary["profiles"] == ["default"]

    def test_house_rules_profile_enables_cal_014(self, tmp_path) -> None:
        from caliper.composition.deterministic_plugin import DeterministicPlugin

        repo = self._repo(tmp_path, "detectors:\n  profiles: [default, house-rules]\n")
        result = DeterministicPlugin().run([str(repo / "mod.py")], repo)
        assert any(f["rule_id"] == "CAL-014" for f in result.findings), result.findings

    def test_enable_single_house_rule(self, tmp_path) -> None:
        from caliper.composition.deterministic_plugin import DeterministicPlugin

        repo = self._repo(tmp_path, "detectors:\n  enable: [CAL-014]\n")
        result = DeterministicPlugin().run([str(repo / "mod.py")], repo)
        assert any(f["rule_id"] == "CAL-014" for f in result.findings)

    def test_bad_profile_falls_back_to_default(self, tmp_path) -> None:
        """Fail-open: a typo in .caliper.yaml must not turn the detectors off or crash."""
        from caliper.composition.deterministic_plugin import DeterministicPlugin

        repo = self._repo(tmp_path, "detectors:\n  profiles: [defualt]\n")
        result = DeterministicPlugin().run([str(repo / "mod.py")], repo)
        assert result.error == ""
        assert result.summary["profiles"] == ["default"]
