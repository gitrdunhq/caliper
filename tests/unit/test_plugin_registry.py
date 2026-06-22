"""Tests for plugin contract and registry.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.plugin import (
    PluginCategory,
    PluginResult,
    ScannerPlugin,
)
from caliper.core.registry import PluginRegistry

# ── Concrete test plugin ──


class _GoodPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "test-good"

    @property
    def description(self) -> str:
        return "A test plugin"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(f.endswith(".py") for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            findings=[{"file": f, "issue": "test"} for f in files],
            summary={"count": len(files)},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        return f"Found {len(result.findings)} issues"


class _BadPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "test-bad"

    @property
    def description(self) -> str:
        return "Always raises"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        raise RuntimeError("scanner exploded")

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        return ""


class _InfraPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "test-infra"

    @property
    def description(self) -> str:
        return "Infra scanner"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.infra

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(plugin_name=self.name)

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        return ""


# ── Contract tests ──


class TestPluginContract:
    def test_incomplete_plugin_raises(self):
        class Incomplete(ScannerPlugin):
            pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_concrete_plugin_instantiates(self):
        plugin = _GoodPlugin()
        assert plugin.name == "test-good"
        assert plugin.category == PluginCategory.code

    def test_plugin_result_defaults(self):
        result = PluginResult(plugin_name="x")
        assert result.findings == []
        assert result.summary == {}
        assert result.error == ""

    def test_plugin_run_returns_result(self):
        plugin = _GoodPlugin()
        result = plugin.run(["a.py", "b.py"], Path("."))
        assert len(result.findings) == 2
        assert result.plugin_name == "test-good"

    def test_plugin_can_run_filters(self):
        plugin = _GoodPlugin()
        assert plugin.can_run(["app.py"], Path(".")) is True
        assert plugin.can_run(["app.tf"], Path(".")) is False

    def test_plugin_render(self):
        plugin = _GoodPlugin()
        result = plugin.run(["a.py"], Path("."))
        md = plugin.render(result)
        assert "1 issues" in md


# ── Registry tests ──


class TestPluginRegistry:
    def test_register_and_get(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        assert reg.get("test-good") is not None
        assert reg.get("nonexistent") is None

    def test_list_all(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        assert len(reg.list()) == 2

    def test_filter_by_category(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        code_only = reg.list(category=PluginCategory.code)
        assert len(code_only) == 1
        assert code_only[0].name == "test-good"

    def test_filter_by_names(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        reg.register(_BadPlugin())
        selected = reg.list(names=["test-good", "test-infra"])
        assert len(selected) == 2

    def test_run_all_returns_results(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        results = reg.run_all(["a.py"], Path("."))
        assert len(results) == 2
        assert all(isinstance(r, PluginResult) for r in results)

    def test_run_all_with_no_matching_plugins_returns_empty(self):
        # Regression: ThreadPoolExecutor(max_workers=0) raises ValueError when
        # the filters match no plugins. run_all must short-circuit to [].
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        assert reg.run_all(["a.py"], Path("."), names=["does-not-exist"]) == []
        assert PluginRegistry().run_all(["a.py"], Path(".")) == []

    def test_run_all_with_name_filter(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        results = reg.run_all(["a.py"], Path("."), names=["test-good"])
        assert len(results) == 1
        assert results[0].plugin_name == "test-good"

    def test_plugin_exception_captured(self):
        reg = PluginRegistry()
        reg.register(_BadPlugin())
        results = reg.run_all(["a.py"], Path("."))
        assert len(results) == 1
        assert results[0].error != ""
        assert "exploded" in results[0].error

    def test_run_all_skips_cant_run(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        results = reg.run_all(["app.tf"], Path("."))
        assert len(results) == 1
        assert results[0].findings == []
        assert "skipped" in results[0].summary.get("status", "")

    def test_duplicate_register_replaces(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_GoodPlugin())
        assert len(reg.list()) == 1

    def test_run_all_preserves_order(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        reg.register(_BadPlugin())
        results = reg.run_all(["a.py"], Path("."))
        assert [r.plugin_name for r in results] == [
            "test-good",
            "test-infra",
            "test-bad",
        ]


class TestRunAllDisableEnable:
    """Tests for disabled_names / enabled_names params on run_all."""

    def test_disabled_names_skips_plugin(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())  # test-good
        reg.register(_InfraPlugin())  # test-infra
        results = reg.run_all(["a.py"], Path("."), disabled_names={"test-good"})
        names = [r.plugin_name for r in results]
        assert "test-good" not in names
        assert "test-infra" in names

    def test_disabled_names_multiple(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        reg.register(_BadPlugin())
        results = reg.run_all(["a.py"], Path("."), disabled_names={"test-good", "test-infra"})
        names = [r.plugin_name for r in results]
        assert "test-good" not in names
        assert "test-infra" not in names
        assert "test-bad" in names

    def test_enabled_names_overrides_disabled(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        results = reg.run_all(
            ["a.py"],
            Path("."),
            disabled_names={"test-good"},
            enabled_names={"test-good"},
        )
        names = [r.plugin_name for r in results]
        assert "test-good" in names
        assert "test-infra" in names

    def test_enable_takes_priority_over_disable(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        reg.register(_BadPlugin())
        results = reg.run_all(
            ["a.py"],
            Path("."),
            disabled_names={"test-good", "test-infra"},
            enabled_names={"test-good"},
        )
        names = [r.plugin_name for r in results]
        assert "test-good" in names
        assert "test-infra" not in names

    def test_disable_composes_with_names_filter(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        reg.register(_BadPlugin())
        results = reg.run_all(
            ["a.py"],
            Path("."),
            names=["test-good", "test-infra"],
            disabled_names={"test-infra"},
        )
        names = [r.plugin_name for r in results]
        assert "test-good" in names
        assert "test-infra" not in names
        assert "test-bad" not in names

    def test_disable_composes_with_category_filter(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())  # code
        reg.register(_InfraPlugin())  # infra
        reg.register(_BadPlugin())  # quality
        results = reg.run_all(
            ["a.py"],
            Path("."),
            categories=[PluginCategory.code, PluginCategory.infra],
            disabled_names={"test-infra"},
        )
        names = [r.plugin_name for r in results]
        assert "test-good" in names
        assert "test-infra" not in names
        assert "test-bad" not in names

    def test_disabled_empty_set_no_effect(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        results = reg.run_all(["a.py"], Path("."), disabled_names=set())
        assert len(results) == 2

    def test_enabled_without_disabled_no_effect(self):
        """enabled_names alone (no disabled_names) does not add or remove plugins."""
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        results = reg.run_all(["a.py"], Path("."), enabled_names={"test-good"})
        assert len(results) == 2

    def test_none_disabled_and_enabled_is_baseline(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        reg.register(_InfraPlugin())
        results = reg.run_all(["a.py"], Path("."), disabled_names=None, enabled_names=None)
        assert len(results) == 2


# ── PackageUnit helpers ──


class _FileScopedPlugin(ScannerPlugin):
    """Records the file list from each call — used to assert file scoping."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    @property
    def name(self) -> str:
        return "test-scoped"

    @property
    def description(self) -> str:
        return "Records file calls"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        self.calls.append(list(files))
        return PluginResult(
            plugin_name=self.name,
            findings=[{"file": f} for f in files],
        )


class _FixedFindingPlugin(ScannerPlugin):
    """Returns one finding per file with ecosystem=python — used as OPA input."""

    @property
    def name(self) -> str:
        return "test-findings"

    @property
    def description(self) -> str:
        return "Fixed findings"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            findings=[{"file": f, "ecosystem": "python"} for f in files],
        )


class _MockOpaPlugin(ScannerPlugin):
    """Pretends to be the OPA plugin — records files received per-call."""

    def __init__(self) -> None:
        self.received_findings: list[list[dict]] = []
        self.received_files: list[list[str]] = []

    @property
    def name(self) -> str:
        return "opa"

    @property
    def description(self) -> str:
        return "Mock OPA"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    @property
    def depends_on(self) -> list[str]:
        return ["*"]

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(
        self,
        files: list[str],
        repo_path: Path,
        findings: list[dict] | None = None,
        **kwargs,
    ) -> PluginResult:
        self.received_findings.append(list(findings or []))
        self.received_files.append(list(files))
        return PluginResult(plugin_name=self.name)


# ── PluginResult.package_root field ──


class TestPluginResultPackageRoot:
    def test_package_root_defaults_to_none(self):
        r = PluginResult(plugin_name="x")
        assert r.package_root is None  # type: ignore[attr-defined]

    def test_package_root_can_be_set(self):
        r = PluginResult(plugin_name="x", package_root="apps/web")  # type: ignore[call-arg]
        assert r.package_root == "apps/web"  # type: ignore[attr-defined]


# ── run_all() with package_units ──


class TestPackageUnitsRunAll:
    def test_none_package_units_is_backward_compatible(self):
        """run_all(package_units=None) must produce the same results as the current default."""
        reg = PluginRegistry()
        plugin = _FileScopedPlugin()
        reg.register(plugin)

        files = ["a.py", "b.py"]
        results = reg.run_all(files, Path("."), package_units=None)

        assert len(results) == 1
        assert results[0].plugin_name == "test-scoped"
        # package_root is None when no units provided
        assert results[0].package_root is None  # type: ignore[attr-defined]

    def test_two_package_units_calls_each_plugin_twice(self):
        """With 2 PackageUnits the plugin is invoked once per package."""
        from caliper.core.manifest_discovery import PackageUnit

        reg = PluginRegistry()
        plugin = _FileScopedPlugin()
        reg.register(plugin)

        pkg_a = PackageUnit(
            root=Path("apps/a"), manifest=Path("apps/a/package.json"), ecosystem="npm"
        )
        pkg_b = PackageUnit(
            root=Path("apps/b"), manifest=Path("apps/b/package.json"), ecosystem="npm"
        )
        files = ["apps/a/index.ts", "apps/b/index.ts"]

        results = reg.run_all(files, Path("."), package_units=[pkg_a, pkg_b])

        # 2 results — one per package (plugin runs twice)
        assert len(results) == 2
        assert len(plugin.calls) == 2

    def test_package_root_tagged_on_results(self):
        """Results returned when using package_units carry the correct package_root."""
        from caliper.core.manifest_discovery import PackageUnit

        reg = PluginRegistry()
        reg.register(_FileScopedPlugin())

        pkg_a = PackageUnit(
            root=Path("apps/a"), manifest=Path("apps/a/package.json"), ecosystem="npm"
        )
        pkg_b = PackageUnit(
            root=Path("apps/b"), manifest=Path("apps/b/package.json"), ecosystem="npm"
        )
        files = ["apps/a/index.ts", "apps/b/index.ts"]

        results = reg.run_all(files, Path("."), package_units=[pkg_a, pkg_b])

        roots = {r.package_root for r in results}  # type: ignore[attr-defined]
        assert "apps/a" in roots
        assert "apps/b" in roots

    def test_files_scoped_to_package_root(self):
        """Each plugin invocation only sees files under its package root."""
        from caliper.core.manifest_discovery import PackageUnit

        reg = PluginRegistry()
        plugin = _FileScopedPlugin()
        reg.register(plugin)

        pkg_a = PackageUnit(
            root=Path("apps/a"), manifest=Path("apps/a/package.json"), ecosystem="npm"
        )
        files = ["apps/a/index.ts", "apps/b/index.ts", "apps/a/utils.ts"]

        reg.run_all(files, Path("."), package_units=[pkg_a])

        assert len(plugin.calls) == 1
        scoped = plugin.calls[0]
        assert all("apps/a" in f for f in scoped), f"Expected only apps/a files, got {scoped}"
        assert "apps/b/index.ts" not in scoped

    def test_opa_receives_per_package_findings_not_global_merged(self):
        """OPA (wildcard) is called once per package and sees only that package's files.

        After #158: no findings= injection.  Scoping is now verified via the
        files argument passed to each run() invocation.
        """
        from caliper.core.manifest_discovery import PackageUnit

        reg = PluginRegistry()
        opa = _MockOpaPlugin()
        findings_plugin = _FixedFindingPlugin()
        reg.register(findings_plugin)
        reg.register(opa)

        pkg_a = PackageUnit(
            root=Path("apps/a"), manifest=Path("apps/a/package.json"), ecosystem="npm"
        )
        pkg_b = PackageUnit(
            root=Path("apps/b"), manifest=Path("apps/b/package.json"), ecosystem="npm"
        )
        files = ["apps/a/index.ts", "apps/b/index.ts"]

        reg.run_all(files, Path("."), package_units=[pkg_a, pkg_b])

        # OPA called twice — once per package
        assert len(opa.received_files) == 2

        # Each call sees only its package's files (no cross-package mixing)
        all_files_seen = {f for call in opa.received_files for f in call}
        assert "apps/a/index.ts" in all_files_seen
        assert "apps/b/index.ts" in all_files_seen

        for call_files in opa.received_files:
            assert not (
                any("apps/a" in f for f in call_files) and any("apps/b" in f for f in call_files)
            ), f"OPA call mixed files from different packages: {call_files}"

    def test_single_package_unit_behaves_same_as_no_units(self):
        """A single PackageUnit at root produces 1 result, same as no units."""
        from caliper.core.manifest_discovery import PackageUnit

        reg = PluginRegistry()
        plugin = _FileScopedPlugin()
        reg.register(plugin)

        root_unit = PackageUnit(root=Path("."), manifest=Path("package.json"), ecosystem="npm")
        files = ["index.ts", "utils.ts"]

        results = reg.run_all(files, Path("."), package_units=[root_unit])

        assert len(results) == 1
        assert results[0].package_root == "."  # type: ignore[attr-defined]


# ── Plugin dependency graph (depends_on + topological sort) ──


class TestPluginDependencyGraph:
    """depends_on property and topological execution order via graphlib."""

    @staticmethod
    def _make_plugin(
        plugin_name: str,
        depends_on: list[str] | None = None,
        execution_order: list[str] | None = None,
    ) -> ScannerPlugin:
        """Factory: returns a plugin that appends its name to execution_order on run."""
        _deps: list[str] = depends_on if depends_on is not None else []
        _order = execution_order

        class _DynPlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return plugin_name

            @property
            def description(self) -> str:
                return f"Dynamic plugin {plugin_name}"

            @property
            def category(self) -> PluginCategory:
                return PluginCategory.code

            @property
            def depends_on(self) -> list[str]:  # type: ignore[override]
                return list(_deps)

            def can_run(self, files: list[str], repo_path: Path) -> bool:
                return True

            def run(self, files: list[str], repo_path: Path) -> PluginResult:
                if _order is not None:
                    _order.append(plugin_name)
                return PluginResult(plugin_name=plugin_name)

        return _DynPlugin()

    def test_a_depends_on_b_b_runs_first(self):
        """Plugin A depends on B -> B executes before A."""
        order: list[str] = []
        reg = PluginRegistry()
        reg.register(self._make_plugin("plugin-b", execution_order=order))
        reg.register(self._make_plugin("plugin-a", depends_on=["plugin-b"], execution_order=order))
        reg.run_all(["a.py"], Path("."))
        assert order.index("plugin-b") < order.index("plugin-a")

    def test_wildcard_depends_on_runs_last(self):
        """A plugin with depends_on=['*'] executes after all non-wildcard plugins."""
        order: list[str] = []

        class _WildPlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return "wild-policy"

            @property
            def description(self) -> str:
                return "Wildcard policy plugin"

            @property
            def category(self) -> PluginCategory:
                return PluginCategory.code

            @property
            def depends_on(self) -> list[str]:  # type: ignore[override]
                return ["*"]

            def can_run(self, files: list[str], repo_path: Path) -> bool:
                return True

            def run(
                self,
                files: list[str],
                repo_path: Path,
                findings: list[dict] | None = None,
                **kwargs,
            ) -> PluginResult:
                order.append("wild-policy")
                return PluginResult(plugin_name="wild-policy")

        reg = PluginRegistry()
        reg.register(self._make_plugin("alpha", execution_order=order))
        reg.register(self._make_plugin("beta", execution_order=order))
        reg.register(_WildPlugin())
        reg.run_all(["a.py"], Path("."))
        assert "alpha" in order
        assert "beta" in order
        assert "wild-policy" in order
        assert order[-1] == "wild-policy"

    def test_no_depends_on_preserves_registration_order(self):
        """Plugins without depends_on run in the order they were registered."""
        order: list[str] = []
        reg = PluginRegistry()
        reg.register(self._make_plugin("first", execution_order=order))
        reg.register(self._make_plugin("second", execution_order=order))
        reg.register(self._make_plugin("third", execution_order=order))
        reg.run_all(["a.py"], Path("."))
        assert order == ["first", "second", "third"]

    def test_circular_dependency_raises_value_error(self):
        """Circular A->B->A dependency raises ValueError."""
        reg = PluginRegistry()
        reg.register(self._make_plugin("plugin-a", depends_on=["plugin-b"]))
        reg.register(self._make_plugin("plugin-b", depends_on=["plugin-a"]))
        with pytest.raises(ValueError, match="[Cc]ircular"):
            reg.run_all(["a.py"], Path("."))

    def test_diamond_dependency_d_runs_first(self):
        """Diamond: A depends on B,C; B,C both depend on D — D runs before all."""
        order: list[str] = []
        reg = PluginRegistry()
        # Register in a non-obvious order to confirm sort is driving execution
        reg.register(self._make_plugin("A", depends_on=["B", "C"], execution_order=order))
        reg.register(self._make_plugin("B", depends_on=["D"], execution_order=order))
        reg.register(self._make_plugin("C", depends_on=["D"], execution_order=order))
        reg.register(self._make_plugin("D", execution_order=order))
        reg.run_all(["a.py"], Path("."))
        assert order[0] == "D"
        assert order[-1] == "A"
        assert order.index("B") < order.index("A")
        assert order.index("C") < order.index("A")

    def test_opa_plugin_uses_depends_on_not_hardcoded_name(self):
        """A plugin with depends_on=['*'] — regardless of name — runs last.

        After #158: depends_on=["*"] is ordering-only; no findings= are
        injected.  The wildcard plugin runs after all non-wildcard plugins.
        """
        order: list[str] = []
        was_called = {"value": False}

        class _NonOpaWildcard(ScannerPlugin):
            @property
            def name(self) -> str:
                return "not-opa-policy"

            @property
            def description(self) -> str:
                return "Non-OPA wildcard"

            @property
            def category(self) -> PluginCategory:
                return PluginCategory.dependency

            @property
            def depends_on(self) -> list[str]:  # type: ignore[override]
                return ["*"]

            def can_run(self, files: list[str], repo_path: Path) -> bool:
                return True

            def run(
                self,
                files: list[str],
                repo_path: Path,
            ) -> PluginResult:
                was_called["value"] = True
                order.append("not-opa-policy")
                return PluginResult(plugin_name="not-opa-policy")

        class _FindingsPlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return "scan-source"

            @property
            def description(self) -> str:
                return "Produces findings"

            @property
            def category(self) -> PluginCategory:
                return PluginCategory.dependency

            def can_run(self, files: list[str], repo_path: Path) -> bool:
                return True

            def run(self, files: list[str], repo_path: Path) -> PluginResult:
                order.append("scan-source")
                return PluginResult(
                    plugin_name="scan-source",
                    findings=[{"issue": "cve-test"}],
                )

        reg = PluginRegistry()
        reg.register(_FindingsPlugin())
        reg.register(_NonOpaWildcard())
        reg.run_all(["a.py"], Path("."))

        assert was_called["value"], "Wildcard plugin was never called"
        assert "scan-source" in order
        assert order[-1] == "not-opa-policy", f"Wildcard plugin did not run last: {order}"

    def test_real_opa_plugin_declares_depends_on_wildcard(self):
        """OpaPlugin.depends_on == ['*'] — driven by property, not hard-coded name check."""
        from caliper.plugins._opa import OpaPlugin

        assert OpaPlugin().depends_on == ["*"]


# ── run_all() with repo_files (diff-scoped routing) ──


class _TrackingPlugin(ScannerPlugin):
    """Records which files it received on each run() call."""

    def __init__(self, plugin_name: str, plugin_category: PluginCategory) -> None:
        self._name = plugin_name
        self._category = plugin_category
        self.received_files: list[list[str]] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"Tracking plugin {self._name}"

    @property
    def category(self) -> PluginCategory:
        return self._category

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        self.received_files.append(list(files))
        return PluginResult(plugin_name=self._name)


class TestRepoFilesRouting:
    """run_all(repo_files=...) routes files by plugin category."""

    def test_repo_files_none_all_plugins_get_same_files(self):
        reg = PluginRegistry()
        code_p = _TrackingPlugin("code-scanner", PluginCategory.code)
        dep_p = _TrackingPlugin("dep-scanner", PluginCategory.dependency)
        reg.register(code_p)
        reg.register(dep_p)

        reg.run_all(["a.py", "b.py"], Path("."), repo_files=None)

        assert code_p.received_files[0] == ["a.py", "b.py"]
        assert dep_p.received_files[0] == ["a.py", "b.py"]

    def test_repo_files_code_plugin_gets_diff_files(self):
        reg = PluginRegistry()
        code_p = _TrackingPlugin("code-scanner", PluginCategory.code)
        reg.register(code_p)

        diff_files = ["changed.py"]
        repo_files = ["changed.py", "untouched.py", "other.py"]
        reg.run_all(diff_files, Path("."), repo_files=repo_files)

        assert code_p.received_files[0] == ["changed.py"]

    def test_repo_files_quality_plugin_gets_diff_files(self):
        reg = PluginRegistry()
        qual_p = _TrackingPlugin("quality-scanner", PluginCategory.quality)
        reg.register(qual_p)

        diff_files = ["changed.py"]
        repo_files = ["changed.py", "untouched.py"]
        reg.run_all(diff_files, Path("."), repo_files=repo_files)

        assert qual_p.received_files[0] == ["changed.py"]

    def test_repo_files_dependency_plugin_gets_repo_files(self):
        reg = PluginRegistry()
        dep_p = _TrackingPlugin("dep-scanner", PluginCategory.dependency)
        reg.register(dep_p)

        diff_files = ["changed.py"]
        repo_files = ["changed.py", "untouched.py", "other.py"]
        reg.run_all(diff_files, Path("."), repo_files=repo_files)

        assert dep_p.received_files[0] == ["changed.py", "untouched.py", "other.py"]

    def test_repo_files_infra_plugin_gets_repo_files(self):
        reg = PluginRegistry()
        infra_p = _TrackingPlugin("infra-scanner", PluginCategory.infra)
        reg.register(infra_p)

        diff_files = ["changed.tf"]
        repo_files = ["changed.tf", "main.tf", "vars.tf"]
        reg.run_all(diff_files, Path("."), repo_files=repo_files)

        assert infra_p.received_files[0] == ["changed.tf", "main.tf", "vars.tf"]

    def test_repo_files_supply_chain_plugin_gets_repo_files(self):
        reg = PluginRegistry()
        sc_p = _TrackingPlugin("sc-scanner", PluginCategory.supply_chain)
        reg.register(sc_p)

        diff_files = ["changed.py"]
        repo_files = ["changed.py", "requirements.txt"]
        reg.run_all(diff_files, Path("."), repo_files=repo_files)

        assert sc_p.received_files[0] == ["changed.py", "requirements.txt"]

    def test_repo_files_mixed_plugins_route_correctly(self):
        """Code gets diff files, dependency gets repo files, in same run."""
        reg = PluginRegistry()
        code_p = _TrackingPlugin("code-scanner", PluginCategory.code)
        dep_p = _TrackingPlugin("dep-scanner", PluginCategory.dependency)
        reg.register(code_p)
        reg.register(dep_p)

        diff_files = ["changed.py"]
        repo_files = ["changed.py", "untouched.py", "other.py"]
        reg.run_all(diff_files, Path("."), repo_files=repo_files)

        assert code_p.received_files[0] == ["changed.py"]
        assert dep_p.received_files[0] == ["changed.py", "untouched.py", "other.py"]
