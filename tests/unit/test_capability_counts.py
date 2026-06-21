"""Capability-count guard — keeps docs/CAPABILITIES.md honest (#412 Phase 8).
# tested-by: tests/unit/test_capability_counts.py

Counts the canonical capability artifacts deterministically from source and
asserts they match both the hard-coded canonical numbers and the headline in
docs/CAPABILITIES.md, so a registry/ruleset refactor cannot silently drop (or
the docs silently drift from) one.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from eedom.plugins import ANALYZERS

_REPO = Path(__file__).resolve().parents[2]

# Canonical capability counts — must match docs/CAPABILITIES.md.
_PLUGINS = 19
_SEMGREP = 61
_CODEGRAPH = 12
_OPA = 6


def _semgrep_rule_count() -> int:
    total = 0
    for path in sorted((_REPO / "policies" / "semgrep").glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        total += len(data.get("rules", []))
    return total


def _codegraph_check_count() -> int:
    data = yaml.safe_load(
        (_REPO / "src" / "eedom" / "plugins" / "_runners" / "checks.yaml").read_text()
    )
    return len(data.get("checks", []))


def _opa_rule_count() -> int:
    text = (_REPO / "policies" / "policy.rego").read_text()
    return len(re.findall(r"^(?:deny|warn) contains ", text, re.MULTILINE))


class TestCapabilityCounts:
    """Deterministic source counts match the canonical numbers."""

    def test_plugin_count(self):
        assert len(ANALYZERS.keys()) == _PLUGINS

    def test_semgrep_rule_count(self):
        assert _semgrep_rule_count() == _SEMGREP

    def test_codegraph_check_count(self):
        assert _codegraph_check_count() == _CODEGRAPH

    def test_opa_rule_count(self):
        assert _opa_rule_count() == _OPA


class TestCapabilitiesDocInSync:
    """The docs/CAPABILITIES.md headline matches the canonical numbers."""

    def test_headline_counts_present(self):
        text = (_REPO / "docs" / "CAPABILITIES.md").read_text()
        for needle in (
            f"{_PLUGINS} plugins",
            f"{_SEMGREP} custom semgrep rules",
            f"{_CODEGRAPH} code graph checks",
            f"{_OPA} OPA policy rules",
        ):
            assert needle in text, f"docs/CAPABILITIES.md missing/stale: {needle!r}"
