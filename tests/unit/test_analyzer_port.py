"""Conformance + capability-count tests for AnalyzerPort + the ANALYZERS registry.
# tested-by: tests/unit/test_analyzer_port.py

RED phase for issue #407 — imports `ANALYZERS` / `AnalyzerPort` which do not
exist yet. The count test guards `docs/CAPABILITIES.md` (16 auto-discovered
plugins) against a registry refactor silently dropping or adding one.

Note: "deterministic" (#457) is registered into this same `ANALYZERS`
registry, but not via `autodiscover()` — it self-registers only once
`caliper.composition.bootstrap.load_adapters()` has run (composition is the
only tier allowed to bridge `plugins` and `detectors`). Any test module that
calls `load_adapters()` at import time (e.g. `test_port_registries.py`,
`test_scribe_registry.py`) makes it visible here too in a full-suite run —
hence the count below is 17, not 16.
"""

from __future__ import annotations

from caliper.core.plugin import AnalyzerPort
from caliper.plugins import ANALYZERS, get_default_registry

# The 16 auto-discovered plugins + "deterministic" (composition-registered,
# see module docstring). "opa" is underscore-excluded, wired separately.
_EXPECTED_PLUGINS = {
    "blast-radius",
    "clamav",
    "complexity",
    "cpd",
    "typos",
    "deterministic",
    "gitleaks",
    "kube-linter",
    "ls-lint",
    "mypy",
    "osv-scanner",
    "scancode",
    "semgrep",
    "supply-chain",
    "swiftlint",
    "syft",
    "trivy",
}


class TestAnalyzerRegistry:
    def test_capability_count_is_17(self):
        from caliper.composition.bootstrap import load_adapters

        load_adapters()
        # Guards docs/CAPABILITIES.md — keep in lockstep with the inventory.
        assert len(ANALYZERS.keys()) == 17

    def test_registered_keys_match_expected_plugins(self):
        from caliper.composition.bootstrap import load_adapters

        load_adapters()
        assert set(ANALYZERS.keys()) == _EXPECTED_PLUGINS

    def test_every_factory_creates_an_analyzer_port(self):
        keys = ANALYZERS.keys()
        for key in keys:
            analyzer = ANALYZERS.create(key)
            assert isinstance(analyzer, AnalyzerPort), f"{key} is not an AnalyzerPort"

    def test_unknown_key_raises_key_error(self):
        import pytest

        with pytest.raises(KeyError):
            ANALYZERS.create("not-a-plugin")


class TestAnalyzerPortIsProtocol:
    def test_is_runtime_checkable(self):
        isinstance(object(), AnalyzerPort)

    def test_object_missing_run_is_not_an_analyzer(self):
        class Incomplete:
            name = "x"
            category = "code"

        assert not isinstance(Incomplete(), AnalyzerPort)


class TestGetDefaultRegistryUsesDecoratorDiscovery:
    def test_default_registry_has_17_plugins(self):
        from caliper.composition.bootstrap import load_adapters

        load_adapters()
        registry = get_default_registry()
        assert len(registry.list()) == 17

    def test_default_registry_names_match_registry_keys(self):
        registry = get_default_registry()
        names = {p.name for p in registry.list()}
        assert names == set(ANALYZERS.keys())

    def test_opa_is_not_auto_registered(self):
        registry = get_default_registry()
        names = {p.name for p in registry.list()}
        assert "opa" not in names
