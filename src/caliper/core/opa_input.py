"""Canonical OPA policy-input builder — single source of truth.
# tested-by: tests/unit/test_opa_input.py
# tested-by: tests/unit/test_policy.py
# tested-by: tests/unit/test_opa_adapter.py

Builds the ``{findings, pkg, config}`` shape documented in
``policies/INPUT_SCHEMA.md`` and consumed by ``policies/policy.rego``.

Before this module existed, there were THREE places that built this shape
(and TWO copies of the default policy config), and they had drifted out of
sync:

- ``core/policy.py::build_opa_input`` — the complete builder, wired to the
  supply-chain-diff path and the legacy ``plugins/_opa.py`` path.
- ``core/opa_adapter.py::OpaRegoAdapter._build_opa_input`` — the one wired
  into the LIVE production pipeline (``core/pipeline.py::_policy_evaluation``
  -> ``PolicyEnginePort``), which emitted only ``{id, severity, message}``
  per finding. Every ``policy.rego`` rule that reads
  ``finding.category`` / ``.package_name`` / ``.license_id`` /
  ``.advisory_id`` / ``.source_tool`` therefore evaluated undefined in
  production and silently never fired.

This module is now the ONLY place that assembles the OPA input and the ONLY
copy of the default rule/config values. Both builder call sites (the core
``Finding`` domain model used by the supply-chain-diff/legacy path, and the
``PluginFinding`` value object the live ``PolicyEnginePort`` boundary carries)
are supported by dispatching on the finding's runtime type — those are the
only two finding representations that cross this boundary anywhere in the
codebase, so a single public ``build_opa_input`` stays the one entry point
without forcing a third shared finding type through both callers.

``PluginFinding`` has no dedicated ``advisory_id`` / ``license_id`` /
``source_tool`` fields (it is a generic scanner-finding value object shared
by every plugin, not just OPA-facing ones); those are threaded through its
``metadata`` dict and read back out via ``finding_get`` — the same escape
hatch ``core/plugin.py`` already defines for exactly this purpose.
"""

from __future__ import annotations

from caliper.core.models import Finding, FindingCategory
from caliper.core.plugin import PluginFinding, finding_get

# Severity ordering for OPA input (not used for dedup here, just for reference)
_SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")

_DEFAULT_RULES_ENABLED: dict[str, bool] = {
    "critical_vuln": True,
    "forbidden_license": True,
    "package_age": True,
    "malicious_package": True,
    "transitive_count": True,
    "supply_chain_diff": True,
    # Opt-in: downgrades critical_vuln/forbidden_license deny to warn for
    # dev-scope (input.pkg.scope == "dev") packages. Default False so no one
    # is opted in without explicitly enabling it. See policies/policy.rego
    # T-345 and _dev_scope_downgraded.
    "dev_scope_exemption": False,
    # Opt-in: denies vulnerabilities whose advisory_id is in the operator-
    # supplied `config.kev_ids` (CISA Known Exploited Vulnerabilities
    # catalog). Default False — kev_ids is threat intel the operator must
    # supply, caliper ships no default list. See policies/policy.rego T-344.
    "cisa_kev": False,
}

_DEFAULT_CONFIG: dict[str, object] = {
    "forbidden_licenses": [],
    "max_transitive_deps": 200,
    "min_package_age_days": 90,
    "rules_enabled": dict(_DEFAULT_RULES_ENABLED),
}


def _row_from_finding(f: Finding) -> dict:
    """Build one ``input.findings[_]`` row from a core ``Finding`` model."""
    entry: dict = {
        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "category": f.category.value if hasattr(f.category, "value") else str(f.category),
        "description": f.description,
        "package_name": f.package_name,
        "version": f.version,
        "advisory_id": f.advisory_id or "",
        "source_tool": f.source_tool,
    }
    if f.category == FindingCategory.license and f.license_id:
        entry["license_id"] = f.license_id
    return entry


def _row_from_plugin_finding(f: PluginFinding) -> dict:
    """Build one ``input.findings[_]`` row from the live ``PolicyInput``'s
    ``PluginFinding`` shape.

    ``category``/``package``/``version`` are first-class ``PluginFinding``
    fields; ``advisory_id``/``license_id``/``source_tool`` are not, so they
    are read from ``metadata`` via ``finding_get`` (falling back to ``.id``
    for ``advisory_id``, matching the historical convention of stamping the
    advisory id into ``PluginFinding.id``).
    """
    advisory_id = finding_get(f, "advisory_id", default="") or f.id or ""
    entry: dict = {
        "severity": f.severity,
        "category": f.category,
        "description": f.message,
        "package_name": f.package,
        "version": f.version,
        "advisory_id": advisory_id,
        "source_tool": finding_get(f, "source_tool", default=""),
    }
    license_id = finding_get(f, "license_id", default="")
    if f.category == FindingCategory.license.value and license_id:
        entry["license_id"] = license_id
    return entry


def _opa_finding_row(f: Finding | PluginFinding) -> dict:
    if isinstance(f, PluginFinding):
        return _row_from_plugin_finding(f)
    return _row_from_finding(f)


def _merge_config(config: dict | None) -> dict:
    """Merge caller-supplied config over ``_DEFAULT_CONFIG``.

    ``rules_enabled`` is merged key-by-key so a partial override (e.g.
    disabling one rule) never drops the defaults for the other rules — a
    shallow ``dict.update`` would otherwise silently disable every rule not
    named in the override.
    """
    merged_config = dict(_DEFAULT_CONFIG)
    if config:
        for key, value in config.items():
            if key == "rules_enabled" and isinstance(value, dict):
                merged_rules = dict(_DEFAULT_RULES_ENABLED)
                merged_rules.update(value)
                merged_config["rules_enabled"] = merged_rules
            else:
                merged_config[key] = value
    return merged_config


def build_opa_input(
    findings: list[Finding] | list[PluginFinding],
    package_metadata: dict,
    config: dict | None = None,
) -> dict:
    """Construct the OPA-expected input shape per ``policies/INPUT_SCHEMA.md``.

    Args:
        findings: Normalized scanner findings — either core ``Finding``
            models (supply-chain-diff / legacy path) or ``PluginFinding``
            value objects (the live ``PolicyEnginePort`` boundary).
        package_metadata: Package metadata dict with name, version, ecosystem, etc.
        config: Optional policy config overrides.

    Returns:
        Dict matching the OPA input schema with findings, pkg, and config keys.
    """
    return {
        "findings": [_opa_finding_row(f) for f in findings],
        "pkg": package_metadata,
        "config": _merge_config(config),
    }
