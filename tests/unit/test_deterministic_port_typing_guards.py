"""Deterministic source-inspection guards for loose port contract types (Issue #253).

Bug: Core port contracts use imprecise types that erase information at the
     hexagonal boundary and prevent static analysis from catching contract violations.

Evidence:
  - policy_port.py line 23: `packages: list[dict]`  — raw dict leaks implementation
  - policy_port.py line 24: `config: dict`          — raw dict leaks implementation
  - policy_port.py line 31: `verdict: str`           — plain str instead of Enum
  - ports.py lines 72-73:   `plugin_results: list[Any]`, `actionability: dict[str, Any]`

Fix: Replace list[dict] with list[TypedDict or Pydantic model], config: dict with
     a typed ConfigModel, verdict: str with a PolicyVerdict Enum, list[Any] with
     list[PluginResult], and dict[str, Any] with a typed ActionabilityMap.

Parent bug: #219 / Epic: #146.
Status: xfail — loose types still present.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #253 — tighten port contract types, then green",
    strict=False,
)


def test_253_policy_input_packages_not_list_dict() -> None:
    """PolicyInput.packages must not be annotated as list[dict].

    Raw list[dict] erases the shape of package metadata that crosses the
    PolicyEnginePort boundary.  Use a TypedDict or Pydantic model that names
    the expected keys (name, version, ecosystem, first_published_date, …).
    """
    from caliper.core.policy_port import PolicyInput

    src = inspect.getsource(PolicyInput)
    assert len(src) > 20, "inspect.getsource returned empty source — class not found"
    assert "list[dict]" not in src, (
        "BUG #253: PolicyInput.packages is annotated as list[dict]. "
        "This allows arbitrary dicts across the policy engine boundary. "
        "Replace with list[PackageMetadata] (TypedDict or Pydantic model) "
        "that declares the expected keys explicitly."
    )


def test_253_policy_input_config_not_bare_dict() -> None:
    """PolicyInput.config must not be a raw unparameterised dict.

    A bare dict annotation accepts any shape and offers no static safety.
    Replace with a typed ConfigModel or dict[str, SomeConcreteType].
    """
    from caliper.core.policy_port import PolicyInput

    src = inspect.getsource(PolicyInput)
    assert len(src) > 20, "inspect.getsource returned empty source — class not found"
    # Match bare `config: dict` (not dict[str, ...] which would be parameterised)
    assert "\n    config: dict\n" not in src and "config: dict\n" not in src, (
        "BUG #253: PolicyInput.config is a bare unparameterised dict. "
        "Replace with a typed config model or dict[str, AllowedValueType]."
    )


def test_253_policy_decision_verdict_not_plain_str() -> None:
    """PolicyDecision.verdict must not be a plain str field.

    Using str allows any string value as a verdict, bypassing exhaustiveness
    checks.  Replace with a PolicyVerdict Enum so that invalid verdicts are
    caught at assignment time.
    """
    from caliper.core.policy_port import PolicyDecision

    src = inspect.getsource(PolicyDecision)
    assert len(src) > 20, "inspect.getsource returned empty source — class not found"
    assert "verdict: str" not in src, (
        "BUG #253: PolicyDecision.verdict is annotated as plain str. "
        "Replace with a PolicyVerdict Enum (e.g. approve / deny / warn / needs_review) "
        "so that downstream code can do exhaustive matching."
    )


def test_253_review_report_plugin_results_not_list_any() -> None:
    """ReviewReport.plugin_results must not be list[Any].

    list[Any] disables all type checking on the results flowing out of the
    registry.  Replace with list[PluginResult] to make the contract explicit.
    """
    from caliper.core.ports import ReviewReport

    src = inspect.getsource(ReviewReport)
    assert len(src) > 20, "inspect.getsource returned empty source — class not found"
    assert "list[Any]" not in src, (
        "BUG #253: ReviewReport.plugin_results is annotated as list[Any]. "
        "Replace with list[PluginResult] to restore type safety across the "
        "port boundary between the registry and the renderer."
    )
