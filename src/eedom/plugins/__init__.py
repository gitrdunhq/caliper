"""Eagle Eyed Dom scanner plugins — self-registering analyzer adapters.
# tested-by: tests/unit/test_analyzer_port.py
# tested-by: tests/unit/test_plugin_registry.py

`ANALYZERS` is the registry of analyzer-plugin factories. Each ``plugins/*.py``
ends with ``@ANALYZERS.register("<name>")`` on its factory; ``autodiscover``
imports them on package import so the decorators run. Underscore modules
(``_opa.py``, ``_runners/``) are intentionally excluded, mirroring the old
class-introspection loader, so the OPA policy plugin stays wired separately.

``PluginRegistry.run_all`` + ``_topological_sort`` remain the execution adapter
that consumes this registry: discovery changed, ordering did not.
"""

from __future__ import annotations

from eedom.core.plugin import AnalyzerPort
from eedom.core.registry import PluginRegistry, discover_plugins
from eedom.registry import Registry, autodiscover

__all__ = ["ANALYZERS", "PluginRegistry", "discover_plugins", "get_default_registry"]

# Defined before autodiscover so adapter modules can import it on import.
ANALYZERS: Registry[AnalyzerPort] = Registry("analyzer")


def get_default_registry() -> PluginRegistry:
    """Build a PluginRegistry from every decorator-registered analyzer."""
    registry = PluginRegistry()
    keys = ANALYZERS.keys()
    for key in keys:
        registry.register(ANALYZERS.create(key))
    return registry


# Import every plugin module so each self-registers against ANALYZERS.
autodiscover(__name__, __path__)
