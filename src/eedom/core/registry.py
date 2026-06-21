"""Plugin registry — discovery, filtering, execution.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from graphlib import CycleError, TopologicalSorter
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from eedom.core.plugin import (
    PluginCategory,
    PluginFinding,
    PluginResult,
    ScannerPlugin,
    normalize_finding,
)

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


def _normalize_findings(findings: list) -> list[PluginFinding]:
    return [f if isinstance(f, PluginFinding) else normalize_finding(f) for f in findings]


def _topological_sort(plugins: list[ScannerPlugin]) -> list[ScannerPlugin]:
    """Return *plugins* sorted so every dependency runs before its dependent.

    A ``depends_on=["*"]`` entry is expanded to "depends on every plugin in
    this run that does NOT itself use ``"*"``", effectively pinning wildcard
    plugins to the end of execution.  Other unknown dep names are silently
    skipped.  Raises ``ValueError`` on circular dependencies.
    """
    if not plugins:
        return []

    by_name = {p.name: p for p in plugins}
    non_wildcard_names = {p.name for p in plugins if "*" not in p.depends_on}

    # Build a graph: each plugin -> set of plugins it must run *after*
    graph: dict[str, set[str]] = {}
    for p in plugins:
        if "*" in p.depends_on:
            # Wildcard: run after every non-wildcard plugin in this batch
            graph[p.name] = non_wildcard_names - {p.name}
        else:
            # Only count deps that are actually registered; drop unknown names
            known_deps = {d for d in p.depends_on if d in by_name}
            graph[p.name] = known_deps

    try:
        sorter = TopologicalSorter(graph)
        return [by_name[name] for name in sorter.static_order()]
    except CycleError as exc:
        raise ValueError(f"Circular plugin dependency detected: {exc}") from exc


def _is_under(file_path: str, root: Path) -> bool:
    """Return True when *file_path* is a descendant of *root*."""
    try:
        return Path(file_path).is_relative_to(root)
    except ValueError:
        return False


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ScannerPlugin | None:
        return self._plugins.get(name)

    def list(
        self,
        category: PluginCategory | None = None,
        names: list[str] | None = None,
    ) -> list[ScannerPlugin]:
        plugins = list(self._plugins.values())
        if category is not None:
            plugins = [p for p in plugins if p.category == category]
        if names is not None:
            name_set = set(names)
            plugins = [p for p in plugins if p.name in name_set]
        return plugins

    # Categories that always scan the full repo even in diff mode.
    _REPO_WIDE_CATEGORIES: frozenset[PluginCategory] = frozenset(
        {PluginCategory.dependency, PluginCategory.infra, PluginCategory.supply_chain}
    )

    def run_all(
        self,
        files: list[str],
        repo_path: Path,
        names: list[str] | None = None,
        categories: list[PluginCategory] | None = None,
        disabled_names: set[str] | list[str] | None = None,
        enabled_names: set[str] | list[str] | None = None,
        package_units: list | None = None,
        repo_files: list[str] | None = None,
    ) -> list[PluginResult]:
        """Run all matching plugins.

        Filtering priority:
        1. *names* / *categories* — existing positional filters applied first.
        2. *disabled_names* — plugins in this set are skipped.
        3. *enabled_names* — plugins in this set override disabled_names.
           A plugin that is both disabled and enabled will run.
           enabled_names alone (without any disabled_names) has no filtering effect.

        When *repo_files* is provided (diff mode), dependency/infra/supply_chain
        plugins receive *repo_files* while code/quality plugins receive *files*.

        When *package_units* is provided (a list of
        ``eedom.core.manifest_discovery.PackageUnit``), each plugin is executed
        once per package.  Files are scoped to the package root and results are
        tagged with ``PluginResult.package_root``.  When *package_units* is
        ``None`` the existing single-pass behaviour is used unchanged.

        All plugins are treated uniformly — no findings= injection.  A plugin
        with ``depends_on=["*"]`` is sorted after all other plugins by the
        topological sorter (ordering semantics only).
        """
        disabled_set: set[str] = set(disabled_names) if disabled_names else set()
        enabled_set: set[str] = set(enabled_names) if enabled_names else set()

        plugins: list[ScannerPlugin] = []
        for plugin in self._plugins.values():
            if names and plugin.name not in names:
                continue
            if categories and plugin.category not in categories:
                continue
            if plugin.name in disabled_set and plugin.name not in enabled_set:
                continue
            plugins.append(plugin)

        # Topologically sort all plugins; depends_on=["*"] plugins land last.
        # Raises ValueError on circular dependencies.
        plugins = _topological_sort(plugins)

        if package_units is not None:
            return self._run_all_per_package(files, repo_path, plugins, package_units)

        # No plugins matched the filters — avoid ThreadPoolExecutor(max_workers=0).
        if not plugins:
            return []

        # Run independent plugins in parallel; preserve original ordering.
        def _task(indexed_plugin: tuple[int, ScannerPlugin]) -> tuple[int, PluginResult]:
            idx, plugin = indexed_plugin
            plugin_files = (
                repo_files
                if repo_files is not None and plugin.category in self._REPO_WIDE_CATEGORIES
                else files
            )
            return idx, self._run_one(plugin, plugin_files, repo_path)

        results_dict: dict[int, PluginResult] = {}
        with ThreadPoolExecutor(max_workers=min(len(plugins), 8)) as pool:
            for idx, result in pool.map(_task, enumerate(plugins)):
                results_dict[idx] = result

        return [results_dict[i] for i in range(len(plugins))]

    def _run_all_per_package(
        self,
        files: list[str],
        repo_path: Path,
        plugins: list[ScannerPlugin],
        package_units: list,
    ) -> list[PluginResult]:
        """Execute plugins once per PackageUnit, scoping files to each package root."""
        results: list[PluginResult] = []
        for unit in package_units:
            unit_root = unit.root
            pkg_root_str = str(unit_root)
            unit_files = [f for f in files if _is_under(f, unit_root)]

            for plugin in plugins:
                r = self._run_one(plugin, unit_files, repo_path)
                results.append(replace(r, package_root=pkg_root_str))

        return results

    def _run_one(
        self,
        plugin: ScannerPlugin,
        files: list[str],
        repo_path: Path,
    ) -> PluginResult:
        cat = plugin.category.value
        if not plugin.can_run(files, repo_path):
            reason, remediation = plugin.skip_reason()
            return PluginResult(
                plugin_name=plugin.name,
                summary={"status": "skipped"},
                category=cat,
                skip_reason=reason,
                skip_remediation=remediation,
            )
        try:
            result = plugin.run(files, repo_path)
            return replace(
                result, category=cat, findings=_normalize_findings(result.findings)
            )
        except Exception as exc:
            logger.warning(
                "plugin.run_failed",
                plugin=plugin.name,
                error=str(exc),
            )
            return PluginResult(plugin_name=plugin.name, error=str(exc), category=cat)

