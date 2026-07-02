"""Caliper scanner plugins — self-registering analyzer adapters.
# tested-by: tests/unit/test_analyzer_port.py
# tested-by: tests/unit/test_plugin_registry.py
# tested-by: tests/unit/test_plugin_sdk.py

`ANALYZERS` is the registry of analyzer-plugin factories. Each ``plugins/*.py``
ends with ``@ANALYZERS.register("<name>")`` on its factory; ``autodiscover``
imports them on package import so the decorators run. Underscore modules
(``_opa.py``, ``_runners/``) are intentionally excluded, mirroring the old
class-introspection loader, so the OPA policy plugin stays wired separately.

``PluginRegistry.run_all`` + ``_topological_sort`` remain the execution adapter
that consumes this registry: discovery changed, ordering did not.

Third-party plugins (docs/PLUGIN_SDK.md) join the same registry via the
``"caliper.plugins"`` ``importlib.metadata`` entry-point group — no fork
required. Discovery is fail-open per entry point: a third-party plugin that
fails to load or construct is logged and skipped, never crashing the scan or
blocking the in-package plugins that loaded fine.
"""

from __future__ import annotations

import importlib.metadata

import structlog

from caliper.adapter_registry import Registry, autodiscover
from caliper.core.plugin import AnalyzerPort
from caliper.core.plugin_registry import PluginRegistry

__all__ = ["ANALYZERS", "PluginRegistry", "get_default_registry"]

logger = structlog.get_logger(__name__)

# Defined before autodiscover so adapter modules can import it on import.
ANALYZERS: Registry[AnalyzerPort] = Registry("analyzer")

_ENTRY_POINT_GROUP = "caliper.plugins"


def _discover_entry_point_plugins() -> list[AnalyzerPort]:
    """Load third-party plugins published under the ``caliper.plugins`` entry-point group.

    Fail-open, both for the entry-point lookup itself (a broken metadata
    backend never blocks the in-package plugins) and per entry point (a
    third-party plugin that raises on load or construction is logged and
    skipped, not propagated).
    """
    try:
        entry_points = importlib.metadata.entry_points(group=_ENTRY_POINT_GROUP)
    except Exception:
        logger.warning("plugin_sdk.entry_points_lookup_failed", exc_info=True)
        return []

    plugins: list[AnalyzerPort] = []
    for entry_point in entry_points:
        try:
            factory = entry_point.load()
            plugin = factory()
        except Exception:
            logger.warning(
                "plugin_sdk.plugin_load_failed", entry_point=entry_point.name, exc_info=True
            )
            continue
        plugins.append(plugin)
    return plugins


def get_default_registry() -> PluginRegistry:
    """Build a PluginRegistry from every decorator-registered analyzer plus
    every third-party plugin published via the ``caliper.plugins`` entry-point
    group (docs/PLUGIN_SDK.md).
    """
    registry = PluginRegistry()
    keys = ANALYZERS.keys()
    for key in keys:
        registry.register(ANALYZERS.create(key))
    for plugin in _discover_entry_point_plugins():
        registry.register(plugin)
    return registry


# Import every plugin module so each self-registers against ANALYZERS.
autodiscover(__name__, __path__)
