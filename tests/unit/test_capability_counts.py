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

from caliper.plugins import ANALYZERS

_REPO = Path(__file__).resolve().parents[2]

# Canonical capability counts — must match docs/CAPABILITIES.md.
_PLUGINS = 15
_SEMGREP = 72
_CODEGRAPH = 10
_OPA = 16
_DETECTORS = 21


def _semgrep_rule_count() -> int:
    total = 0
    for path in sorted((_REPO / "policies" / "semgrep").glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        total += len(data.get("rules", []))
    return total


def _codegraph_check_count() -> int:
    data = yaml.safe_load(
        (_REPO / "src" / "caliper" / "plugins" / "_runners" / "checks.yaml").read_text()
    )
    return len(data.get("checks", []))


def _opa_rule_count() -> int:
    text = (_REPO / "policies" / "policy.rego").read_text()
    return len(re.findall(r"^(?:deny|warn) contains ", text, re.MULTILINE))


def _detector_count() -> int:
    from caliper.detectors._registry import DETECTORS, discover_detectors

    discover_detectors()
    return len(DETECTORS.keys())


class TestCapabilityCounts:
    """Deterministic source counts match the canonical numbers."""

    def test_plugin_count(self):
        from caliper.composition.bootstrap import load_adapters

        load_adapters()
        assert len(ANALYZERS.keys()) == _PLUGINS

    def test_semgrep_rule_count(self):
        assert _semgrep_rule_count() == _SEMGREP

    def test_codegraph_check_count(self):
        assert _codegraph_check_count() == _CODEGRAPH

    def test_opa_rule_count(self):
        assert _opa_rule_count() == _OPA

    def test_detector_count(self):
        assert _detector_count() == _DETECTORS


class TestCapabilitiesDocInSync:
    """The docs/CAPABILITIES.md headline matches the canonical numbers."""

    def test_headline_counts_present(self):
        # Whitespace-normalized so the guard survives line-wrapping/reflow of the
        # identity paragraph (a phrase like "12 code graph checks" may span a newline).
        text = " ".join((_REPO / "docs" / "CAPABILITIES.md").read_text().split())
        for needle in (
            f"{_PLUGINS} scanner plugins",
            f"{_SEMGREP} custom semgrep rules",
            f"{_CODEGRAPH} code graph checks",
            f"{_OPA} OPA policy rules",
            f"{_DETECTORS} detectors",
        ):
            assert needle in text, f"docs/CAPABILITIES.md missing/stale: {needle!r}"


class TestReadmeDocInSync:
    """README.md's headline claims match the canonical numbers (M1-3/M1-4)."""

    def test_headline_counts_present(self):
        text = " ".join((_REPO / "README.md").read_text().split())
        for needle in (
            f"{_PLUGINS - 1} plugins",  # README counts auto-discovered only, not "deterministic"
            f"{_DETECTORS} detectors",
            f"{_OPA} OPA policy rules",
            f"{_SEMGREP} custom semgrep rules",
        ):
            assert needle in text, f"README.md missing/stale: {needle!r}"


class TestClaudeMdHasNoHardcodedCounts:
    """CLAUDE.md points at docs/CAPABILITIES.md instead of carrying its own counts
    (M1-4) — a hardcoded count here is exactly the drift this test file exists to
    prevent, just one file earlier."""

    def test_no_capability_counts_in_claude_md(self):
        claude_md = (_REPO / "CLAUDE.md").read_text()
        assert not re.search(
            r"\b\d+\+?\s+(scanner plugins?|deterministic detectors?|"
            r"custom semgrep rules?|code graph checks?|OPA policy rules?)\b",
            claude_md,
        )
