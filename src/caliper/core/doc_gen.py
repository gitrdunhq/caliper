# tested-by: tests/unit/test_drift_guards.py
"""Doc-gen helpers for drift guards (#188, #189).

Provides deterministic snapshots of the RepoConfig JSON schema and the
plugin inventory so CI can detect drift between code and documentation.
"""

from __future__ import annotations


def generate_config_schema() -> dict:
    """Return the JSON Schema for RepoConfig."""
    from caliper.core.repo_config import RepoConfig  # noqa: PLC0415

    return RepoConfig.model_json_schema()


def generate_plugin_inventory(registry) -> list[str]:
    """Return a sorted list of plugin names from the *injected* registry.

    Core no longer reaches into ``caliper.plugins``; the presentation/composition
    tier passes in a registry (e.g. ``get_default_registry()``).
    """
    return sorted(p.name for p in registry.list())
