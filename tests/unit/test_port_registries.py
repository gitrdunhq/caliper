"""Conformance tests for the core-owned port registries (#411 Phase 7).
# tested-by: tests/unit/test_port_registries.py

Each external-dependency area exposes a registry + a registered fake/null + a
parametrized factory conformance check, mirroring the SCANNERS/ANALYZERS
template. ``load_adapters()`` triggers the cross-tier self-registration.
"""

from __future__ import annotations

import pytest

from eedom.composition.bootstrap import load_adapters
from eedom.core.policy_port import PolicyEnginePort
from eedom.core.ports import (
    CodeGraphCheckPort,
    DecisionStorePort,
    EvidenceStorePort,
    PackageMetadataPort,
    PullRequestPublisherPort,
    ReportRendererPort,
    RepoSnapshotPort,
    SemgrepRunnerPort,
)
from eedom.core.registries import (
    CODEGRAPH_CHECKS,
    DECISION_STORES,
    EVIDENCE_STORES,
    PACKAGE_INDEXES,
    POLICY_ENGINES,
    PUBLISHERS,
    RENDERERS,
    REPO_SNAPSHOTS,
    RULE_RUNNERS,
)

# Populate the registries via the composition tier's explicit import step.
load_adapters()


# (registry, expected keys, fake key, port protocol)
_AREAS = [
    (POLICY_ENGINES, {"opa", "fake"}, "fake", PolicyEnginePort),
    (RENDERERS, {"markdown", "sarif", "json", "fake"}, "fake", ReportRendererPort),
    (PACKAGE_INDEXES, {"pypi", "fake"}, "fake", PackageMetadataPort),
    (DECISION_STORES, {"postgres", "null"}, "null", DecisionStorePort),
    (EVIDENCE_STORES, {"file", "null"}, "null", EvidenceStorePort),
    (PUBLISHERS, {"github", "null"}, "null", PullRequestPublisherPort),
    (REPO_SNAPSHOTS, {"git", "fake"}, "fake", RepoSnapshotPort),
    (RULE_RUNNERS, {"semgrep", "fake"}, "fake", SemgrepRunnerPort),
    (CODEGRAPH_CHECKS, {"blast-radius", "fake"}, "fake", CodeGraphCheckPort),
]

_IDS = [r._kind for r, *_ in _AREAS]


class TestRegistryKeys:
    @pytest.mark.parametrize(("registry", "expected", "_fake", "_port"), _AREAS, ids=_IDS)
    def test_expected_adapters_registered(self, registry, expected, _fake, _port):
        assert expected <= set(registry.keys())

    @pytest.mark.parametrize(("registry", "_expected", "_fake", "_port"), _AREAS, ids=_IDS)
    def test_unknown_key_raises(self, registry, _expected, _fake, _port):
        with pytest.raises(KeyError):
            registry.create("does-not-exist")


class TestFakeConformance:
    """Every area's fake/null resolves to a port-satisfying instance, no I/O."""

    @pytest.mark.parametrize(("registry", "_expected", "fake", "port"), _AREAS, ids=_IDS)
    def test_fake_satisfies_port(self, registry, _expected, fake, port):
        instance = registry.create(fake)
        assert isinstance(instance, port)


class TestRealFactoriesConstruct:
    """The production factories construct their adapter with no I/O at create()."""

    def test_opa_engine(self):
        from eedom.core.subprocess_runner import SubprocessToolRunner

        engine = POLICY_ENGINES.create(
            "opa", policy_path="/tmp/policy.rego", tool_runner=SubprocessToolRunner()
        )
        assert isinstance(engine, PolicyEnginePort)

    @pytest.mark.parametrize("key", ["markdown", "sarif", "json"])
    def test_renderers(self, key):
        assert isinstance(RENDERERS.create(key), ReportRendererPort)

    def test_pypi_index(self):
        assert isinstance(PACKAGE_INDEXES.create("pypi", timeout=5), PackageMetadataPort)

    def test_postgres_decision_store(self):
        store = DECISION_STORES.create("postgres", dsn="postgresql://u:p@localhost/db")
        assert isinstance(store, DecisionStorePort)

    def test_file_evidence_store(self, tmp_path):
        assert isinstance(EVIDENCE_STORES.create("file", base_dir=tmp_path), EvidenceStorePort)

    def test_github_publisher(self):
        assert isinstance(PUBLISHERS.create("github", token="x"), PullRequestPublisherPort)

    def test_git_snapshot(self, tmp_path):
        assert isinstance(REPO_SNAPSHOTS.create("git", repo_path=tmp_path), RepoSnapshotPort)

    def test_semgrep_runner(self):
        assert isinstance(RULE_RUNNERS.create("semgrep"), SemgrepRunnerPort)

    def test_code_graph_check(self):
        assert isinstance(CODEGRAPH_CHECKS.create("blast-radius"), CodeGraphCheckPort)
