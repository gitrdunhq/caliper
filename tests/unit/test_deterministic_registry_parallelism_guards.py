"""Deterministic source-inspection guard for sequential plugin execution (Issue #254).

Bug: PluginRegistry.run_all() executes all plugins sequentially in a for-loop.
     Independent plugins — those with no declared depends_on relationship — are
     executed one after another, so a slow plugin blocks all subsequent ones.

Evidence:
  - registry.py line 156: `for plugin in plugins:` inside run_all()
  - registry.py line 180: `for plugin in plugins:` inside _run_all_per_package()
  - No ThreadPoolExecutor, asyncio.gather, or concurrent.futures anywhere in
    PluginRegistry's execution path.

Fix: Bucket independent plugins (after topological sort) and execute each bucket
     concurrently via ThreadPoolExecutor or asyncio.gather.  Plugins with
     depends_on constraints still execute in topological order.

Parent bug: #220 / Epic: #146.
Status: xfail — sequential execution still present in registry.py.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #254 — parallelise independent plugins, then green",
    strict=False,
)

_CONCURRENCY_MARKERS = ("ThreadPoolExecutor", "gather", "concurrent.futures", "asyncio")


def _get_registry_source() -> str:
    from caliper.core.registry import PluginRegistry

    src = inspect.getsource(PluginRegistry)
    assert len(src) > 200, (
        "inspect.getsource returned a suspiciously short string — "
        "PluginRegistry class may have been renamed or moved"
    )
    return src


def test_254_registry_uses_concurrent_execution() -> None:
    """PluginRegistry must execute independent plugins concurrently.

    Sequential execution means each plugin blocks all plugins that follow it.
    A 30-second semgrep run forces osv-scanner, trivy, and all other independent
    plugins to wait — even though they could run in parallel.

    The source must contain at least one concurrency primitive.
    """
    src = _get_registry_source()
    found = [marker for marker in _CONCURRENCY_MARKERS if marker in src]
    assert found, (
        "BUG #254: PluginRegistry executes plugins sequentially. "
        f"None of the expected concurrency markers {_CONCURRENCY_MARKERS} "
        "appear in the PluginRegistry source. "
        "Add a ThreadPoolExecutor or asyncio.gather to parallelize "
        "independent plugin buckets after topological sort."
    )


def test_254_run_all_not_plain_sequential_loop() -> None:
    """run_all() must not use a bare sequential for-loop as its only execution model.

    After the topological sort, independent plugins (those in the same topological
    level) can run concurrently.  A plain `for plugin in plugins:` loop without
    any concurrency mechanism defeats the purpose of having concurrent scanners.
    """
    src = _get_registry_source()
    has_concurrency = any(marker in src for marker in _CONCURRENCY_MARKERS)
    assert has_concurrency, (
        "BUG #254: PluginRegistry.run_all() uses a plain sequential for-loop. "
        "Parallel execution of independent plugins is needed to reduce overall "
        "scan latency.  Introduce concurrent execution for plugins at the same "
        "topological depth."
    )
