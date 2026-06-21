# tested-by: tests/unit/test_port_registries.py
"""Deterministic fakes for the core-owned port registries.

Registered under the ``"fake"`` key so ``bootstrap_test`` and conformance
tests can resolve a no-I/O stand-in via the registry. None of these reach the
network, a subprocess, or the filesystem.
"""

from __future__ import annotations

from eedom.core.policy_port import PolicyDecision, PolicyInput
from eedom.core.registries import PACKAGE_INDEXES, POLICY_ENGINES, RENDERERS


class FakePolicyEngine:
    """Always-approve PolicyEnginePort — never invokes OPA."""

    def evaluate(self, input: PolicyInput) -> PolicyDecision:
        return PolicyDecision(verdict="approve")


class FakePackageMetadata:
    """No-op PackageMetadataPort — never makes a network call."""

    def fetch_metadata(self, name: str, version: str | None = None) -> dict:
        return {"available": False}

    def close(self) -> None:
        return None


class FakeRenderer:
    """No-op ReportRendererPort — returns an empty string for any report."""

    def render(self, report) -> str:
        return ""


@POLICY_ENGINES.register("fake")
def build_fake_policy_engine() -> FakePolicyEngine:
    return FakePolicyEngine()


@PACKAGE_INDEXES.register("fake")
def build_fake_package_index() -> FakePackageMetadata:
    return FakePackageMetadata()


@RENDERERS.register("fake")
def build_fake_renderer() -> FakeRenderer:
    return FakeRenderer()
