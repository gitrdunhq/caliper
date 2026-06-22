# tested-by: tests/unit/test_drift_guards.py
"""Drift guard tests for schema / inventory doc-gen (#188, #189).

All tests in this file are intentionally RED — eedom.core.doc_gen does not
exist yet.  They define the contract that the implementation must satisfy.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 1. generate_config_schema() returns a valid JSON-Schema dict
# ---------------------------------------------------------------------------


def test_generate_config_schema_returns_dict():
    """generate_config_schema() must exist and return a dict."""
    from eedom.core.doc_gen import generate_config_schema  # noqa: PLC0415

    schema = generate_config_schema()
    assert isinstance(schema, dict), "Expected a dict, got {type(schema).__name__}"


def test_generate_config_schema_matches_repo_config_json_schema():
    """Schema produced by generate_config_schema() must match RepoConfig.model_json_schema()."""
    from eedom.core.doc_gen import generate_config_schema  # noqa: PLC0415
    from eedom.core.repo_config import RepoConfig

    result = generate_config_schema()
    expected = RepoConfig.model_json_schema()

    assert result == expected, f"Schema drift detected.\nExpected: {expected}\nGot: {result}"


# ---------------------------------------------------------------------------
# 2. generate_config_schema() covers all RepoConfig top-level fields
# ---------------------------------------------------------------------------


def test_generate_config_schema_contains_all_repo_config_fields():
    """JSON schema must expose every top-level field declared on RepoConfig."""
    from eedom.core.doc_gen import generate_config_schema  # noqa: PLC0415
    from eedom.core.repo_config import RepoConfig

    schema = generate_config_schema()
    # Pydantic v2 JSON schema puts properties under "properties"
    schema_properties = set(schema.get("properties", {}).keys())

    model_fields = set(RepoConfig.model_fields.keys())

    missing = model_fields - schema_properties
    assert (
        not missing
    ), f"The following RepoConfig fields are absent from the generated schema: {missing}"


# ---------------------------------------------------------------------------
# 3. generate_plugin_inventory() returns a list of plugin names
# ---------------------------------------------------------------------------


def test_generate_plugin_inventory_returns_list_of_strings():
    """generate_plugin_inventory() must exist and return a non-empty list of str."""
    from eedom.core.doc_gen import generate_plugin_inventory  # noqa: PLC0415
    from eedom.plugins import get_default_registry

    inventory = generate_plugin_inventory(get_default_registry())
    assert isinstance(inventory, list), f"Expected list, got {type(inventory).__name__}"
    assert len(inventory) > 0, "Plugin inventory must not be empty"
    for name in inventory:
        assert isinstance(name, str), f"Each entry must be a str, got {type(name).__name__}"


def test_generate_plugin_inventory_matches_default_registry():
    """Inventory names must exactly match those discovered by get_default_registry()."""
    from eedom.core.doc_gen import generate_plugin_inventory  # noqa: PLC0415
    from eedom.plugins import get_default_registry

    registry = get_default_registry()
    inventory = set(generate_plugin_inventory(registry))
    registry_names = {p.name for p in registry.list()}

    assert inventory == registry_names, (
        f"Inventory drift detected.\n"
        f"Only in inventory : {inventory - registry_names}\n"
        f"Only in registry  : {registry_names - inventory}"
    )


# ---------------------------------------------------------------------------
# 4. Plugin count matches docs/CAPABILITIES.md canonical count (19)
# ---------------------------------------------------------------------------

_CAPABILITIES_PLUGIN_COUNT = 19


def test_plugin_inventory_count_matches_capabilities_md():
    """Inventory length must equal the canonical count declared in docs/CAPABILITIES.md."""
    from eedom.core.doc_gen import generate_plugin_inventory  # noqa: PLC0415
    from eedom.plugins import get_default_registry

    inventory = generate_plugin_inventory(get_default_registry())
    assert len(inventory) == _CAPABILITIES_PLUGIN_COUNT, (
        f"Expected {_CAPABILITIES_PLUGIN_COUNT} plugins per docs/CAPABILITIES.md, "
        f"got {len(inventory)}.  Update CAPABILITIES.md or add the missing plugin."
    )
