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
