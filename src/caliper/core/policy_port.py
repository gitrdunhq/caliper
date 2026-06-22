# tested-by: tests/unit/test_policy_port.py
"""PolicyEnginePort contract — typed boundary between pipeline and policy engine.

Defines the three public symbols used at the policy evaluation seam:
  - PolicyInput   — inputs gathered by the pipeline
  - PolicyDecision — verdict + reasons returned by any policy engine
  - PolicyEnginePort — runtime-checkable Protocol that policy engines must satisfy
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, TypedDict, runtime_checkable

from caliper.core.plugin import PluginFinding


class PackageMetadata(TypedDict, total=False):
    """Typed shape for package metadata crossing the PolicyEnginePort boundary."""

    name: str
    version: str
    ecosystem: str
    scope: str
    first_published_date: str
    transitive_dep_count: int
    environment_sensitivity: str


class PolicyConfigDict(TypedDict, total=False):
    """Typed shape for policy configuration options."""

    forbidden_licenses: list[str]
    max_transitive_deps: int
    min_package_age_days: int
    rules_enabled: dict[str, bool]


@dataclass
class PolicyInput:
    """Inputs passed to a policy engine for evaluation."""

    findings: list[PluginFinding]
    packages: list[PackageMetadata]
    config: PolicyConfigDict


class PolicyVerdict(StrEnum):
    """Enumeration of all valid policy evaluation outcomes."""

    approve = "approve"
    reject = "reject"
    approve_with_constraints = "approve_with_constraints"
    needs_review = "needs_review"


@dataclass
class PolicyDecision:
    """Result returned by a policy engine after evaluating a PolicyInput."""

    verdict: PolicyVerdict
    deny_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    triggered_rules: list[str] = field(default_factory=list)


@runtime_checkable
class PolicyEnginePort(Protocol):
    """Protocol that every policy engine implementation must satisfy."""

    def evaluate(self, input: PolicyInput) -> PolicyDecision: ...
