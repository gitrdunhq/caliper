"""Conformance + capability-count tests for AnalyzerPort + the ANALYZERS registry.
# tested-by: tests/unit/test_analyzer_port.py

RED phase for issue #407 — imports `ANALYZERS` / `AnalyzerPort` which do not
exist yet. The count test guards `docs/CAPABILITIES.md` (19 plugins) against a
registry refactor silently dropping or adding one.
"""

from __future__ import annotations

from eedom.core.plugin import AnalyzerPort
from eedom.plugins import ANALYZERS, get_default_registry

# The 19 discoverable plugins (opa is underscore-excluded, wired separately).
_EXPECTED_PLUGINS = {
    "blast-radius",
    "cdk-nag",
    "cfn-nag",
    "clamav",
    "complexity",
    "cpd",
    "cspell",
    "gitleaks",
    "kube-linter",
    "ls-lint",
    "mypy",
    "osv-scanner",
    "scancode",
    "semgrep",
    "supply-chain",
    "swiftformat",
    "swiftlint",
    "syft",
    "trivy",
}


class TestAnalyzerRegistry:
    def test_capability_count_is_19(self):
        # Guards docs/CAPABILITIES.md — keep in lockstep with the inventory.
        assert len(ANALYZERS.keys()) == 19

    def test_registered_keys_match_expected_plugins(self):
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
    def test_default_registry_has_19_plugins(self):
        registry = get_default_registry()
        assert len(registry.list()) == 19

    def test_default_registry_names_match_registry_keys(self):
        registry = get_default_registry()
        names = {p.name for p in registry.list()}
        assert names == set(ANALYZERS.keys())

    def test_opa_is_not_auto_registered(self):
        registry = get_default_registry()
        names = {p.name for p in registry.list()}
        assert "opa" not in names
