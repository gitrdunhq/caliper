"""Deterministic guards for OPA adapter input shape — Issue #236 / Parent #202.

Bug: OpaRegoAdapter._build_opa_input() emits "packages" instead of "pkg" and
passes config as-is without merging _DEFAULT_CONFIG. This means critical/high
vulnerability, forbidden-license, malicious-package, package-age, and
transitive-count rules evaluate undefined in Rego and fall through to approve —
silently bypassing policy enforcement.

These tests are xfail until the adapter is corrected to use "pkg" and merge
_DEFAULT_CONFIG defaults. See issues #202 and #236.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    reason=(
        "deterministic bug detector for #202 — "
        "OpaRegoAdapter._build_opa_input() uses 'packages' not 'pkg' and "
        "does not merge _DEFAULT_CONFIG; fix the adapter, then these go green"
    ),
    strict=False,
)

from caliper.core.opa_adapter import OpaRegoAdapter
from caliper.core.plugin import PluginFinding
from caliper.core.policy_port import PolicyInput


def _make_finding(severity: str = "critical") -> PluginFinding:
    return PluginFinding(id="CVE-2024-0001", severity=severity, message="test vuln")


def _make_input(config: dict | None = None) -> PolicyInput:
    return PolicyInput(
        findings=[_make_finding()],
        packages=[{"name": "requests", "version": "2.28.0"}],
        config=config if config is not None else {},
    )


def _build(config: dict | None = None) -> dict:
    adapter = OpaRegoAdapter(policy_path="/fake/policies", tool_runner=None)  # type: ignore[arg-type]
    return adapter._build_opa_input(_make_input(config=config))


class TestOpaInputKeyContract:
    """policy.rego reads input.pkg.* — the adapter must emit 'pkg', not 'packages'."""

    def test_opa_input_has_pkg_key_not_packages(self) -> None:
        """_build_opa_input() must emit 'pkg', not 'packages'.

        policy.rego package-age (input.pkg.first_published_date), malicious-package
        (input.pkg.*), and transitive-count rules all read input.pkg.*. Emitting
        'packages' means every one of those rules evaluates undefined → approve,
        silently bypassing policy.
        """
        opa_input = _build()
        assert "pkg" in opa_input, (
            f"OPA input is missing the 'pkg' key. Got: {list(opa_input.keys())}. "
            "policy.rego reads input.pkg.* — rename 'packages' → 'pkg' in "
            "OpaRegoAdapter._build_opa_input()."
        )

    def test_opa_input_does_not_have_packages_key(self) -> None:
        """'packages' must not be the package key in the OPA input."""
        opa_input = _build()
        assert "packages" not in opa_input, (
            "OPA input has 'packages' key which policy.rego does not read. "
            "Replace it with 'pkg' so package rules are evaluated correctly."
        )


class TestOpaInputConfigContract:
    """policy.rego reads input.config.rules_enabled.* — defaults must always be present."""

    def test_opa_input_config_has_rules_enabled_when_config_empty(self) -> None:
        """_build_opa_input() must merge _DEFAULT_CONFIG even when PolicyInput.config is {}.

        If the adapter passes config={} as-is, policy.rego reads
        input.config.rules_enabled.critical_vuln → undefined → deny rule silently
        skips → approve. Every rule that checks rules_enabled is a silent bypass.
        """
        opa_input = _build(config={})
        config = opa_input.get("config", {})
        assert "rules_enabled" in config, (
            f"OPA input config is missing 'rules_enabled'. Got: {list(config.keys())}. "
            "All five policy rules guard behind rules_enabled checks. An absent "
            "'rules_enabled' means every rule evaluates undefined → approve. "
            "Fix: merge _DEFAULT_CONFIG in OpaRegoAdapter._build_opa_input()."
        )

    def test_opa_input_config_rules_enabled_has_all_required_keys(self) -> None:
        """rules_enabled must contain all five policy rule keys, each defaulting to True."""
        required = {
            "critical_vuln",
            "forbidden_license",
            "package_age",
            "malicious_package",
            "transitive_count",
        }
        opa_input = _build(config={})
        rules_enabled = opa_input.get("config", {}).get("rules_enabled", {})
        missing = required - set(rules_enabled.keys())
        assert not missing, (
            f"rules_enabled is missing: {sorted(missing)}. "
            "Without these keys, the corresponding policy.rego deny rules evaluate "
            "undefined and fall through to approve. "
            "Fix: ensure OpaRegoAdapter._build_opa_input() sets all five defaults."
        )

    def test_opa_input_config_rules_enabled_defaults_to_true(self) -> None:
        """All rules_enabled flags must default to True when no config is supplied."""
        required = {
            "critical_vuln",
            "forbidden_license",
            "package_age",
            "malicious_package",
            "transitive_count",
        }
        opa_input = _build(config={})
        # Use sentinel None so an absent rules_enabled fails rather than vacuously passing
        rules_enabled = opa_input.get("config", {}).get("rules_enabled", None)
        assert rules_enabled is not None, (
            "rules_enabled is absent in OPA input config — all policy rules evaluate "
            "undefined and fall through to approve. See test_opa_input_config_has_rules_enabled_when_config_empty."
        )
        disabled = {k for k in required if rules_enabled.get(k) is not True}
        assert not disabled, (
            f"rules_enabled keys not defaulting to True: {sorted(disabled)}. "
            "All rules must be enabled by default so policy enforcement is opt-out, "
            "not opt-in. A disabled rule silently approves violations."
        )
